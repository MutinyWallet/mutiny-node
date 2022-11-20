//! Utilities that take care of tasks that (1) need to happen periodically to keep Rust-Lightning
//! running properly, and (2) either can or should be run in the background. See docs for
//! [`BackgroundProcessor`] for more details on the nitty-gritty.

// Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(broken_intra_doc_links)]
#![deny(private_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//#[macro_use]
//extern crate lightning;
//extern crate lightning_rapid_gossip_sync;
use crate::utils;
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::{ChainMonitor, Persist};
use lightning::chain::keysinterface::{KeysInterface, Sign};
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::msgs::{ChannelMessageHandler, OnionMessageHandler, RoutingMessageHandler};
use lightning::ln::peer_handler::{CustomMessageHandler, PeerManager, SocketDescriptor};
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::scoring::WriteableScore;
use lightning::util::events::{Event, EventHandler, EventsProvider};
use lightning::util::logger::Logger;
use lightning::util::persist::Persister;
use lightning_rapid_gossip_sync::RapidGossipSync;
use log::{error, trace};
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use wasm_bindgen_futures::spawn_local;

/// `BackgroundProcessor` takes care of tasks that (1) need to happen periodically to keep
/// Rust-Lightning running properly, and (2) either can or should be run in the background. Its
/// responsibilities are:
/// * Processing [`Event`]s with a user-provided [`EventHandler`].
/// * Monitoring whether the [`ChannelManager`] needs to be re-persisted to disk, and if so,
///   writing it to disk/backups by invoking the callback given to it at startup.
///   [`ChannelManager`] persistence should be done in the background.
/// * Calling [`ChannelManager::timer_tick_occurred`] and [`PeerManager::timer_tick_occurred`]
///   at the appropriate intervals.
/// * Calling [`NetworkGraph::remove_stale_channels_and_tracking`] (if a [`GossipSync`] with a
///   [`NetworkGraph`] is provided to [`BackgroundProcessor::start`]).
///
/// It will also call [`PeerManager::process_events`] periodically though this shouldn't be relied
/// upon as doing so may result in high latency.
///
/// # Note
///
/// If [`ChannelManager`] persistence fails and the persisted manager becomes out-of-date, then
/// there is a risk of channels force-closing on startup when the manager realizes it's outdated.
/// However, as long as [`ChannelMonitor`] backups are sound, no funds besides those used for
/// unilateral chain closure fees are at risk.
///
/// [`ChannelMonitor`]: lightning::chain::channelmonitor::ChannelMonitor
/// [`Event`]: lightning::util::events::Event
#[must_use = "BackgroundProcessor will immediately stop on drop. It should be stored until shutdown."]
pub struct BackgroundProcessor {
    stop_thread: Arc<AtomicBool>,
    thread_handle: Option<JoinHandle<Result<(), std::io::Error>>>,
}

const FRESHNESS_TIMER: u64 = 60;

const PING_TIMER: u64 = 30;

/// Prune the network graph of stale entries hourly.
const NETWORK_PRUNE_TIMER: u64 = 60 * 60;

const SCORER_PERSIST_TIMER: u64 = 30;

const FIRST_NETWORK_PRUNE_TIMER: u64 = 60;

/// Either [`P2PGossipSync`] or [`RapidGossipSync`].
pub enum GossipSync<
    P: Deref<Target = P2PGossipSync<G, A, L>>,
    R: Deref<Target = RapidGossipSync<G, L>>,
    G: Deref<Target = NetworkGraph<L>>,
    A: Deref,
    L: Deref,
> where
    A::Target: chain::Access,
    L::Target: Logger,
{
    /// Gossip sync via the lightning peer-to-peer network as defined by BOLT 7.
    P2P(P),
    /// Rapid gossip sync from a trusted server.
    Rapid(R),
    /// No gossip sync.
    None,
}

impl<
        P: Deref<Target = P2PGossipSync<G, A, L>>,
        R: Deref<Target = RapidGossipSync<G, L>>,
        G: Deref<Target = NetworkGraph<L>>,
        A: Deref,
        L: Deref,
    > GossipSync<P, R, G, A, L>
where
    A::Target: chain::Access,
    L::Target: Logger,
{
    fn network_graph(&self) -> Option<&G> {
        match self {
            GossipSync::P2P(gossip_sync) => Some(gossip_sync.network_graph()),
            GossipSync::Rapid(gossip_sync) => Some(gossip_sync.network_graph()),
            GossipSync::None => None,
        }
    }

    fn prunable_network_graph(&self) -> Option<&G> {
        match self {
            GossipSync::P2P(gossip_sync) => Some(gossip_sync.network_graph()),
            GossipSync::Rapid(gossip_sync) => {
                if gossip_sync.is_initial_sync_complete() {
                    Some(gossip_sync.network_graph())
                } else {
                    None
                }
            }
            GossipSync::None => None,
        }
    }
}

/// (C-not exported) as the bindings concretize everything and have constructors for us
impl<
        P: Deref<Target = P2PGossipSync<G, A, L>>,
        G: Deref<Target = NetworkGraph<L>>,
        A: Deref,
        L: Deref,
    > GossipSync<P, &RapidGossipSync<G, L>, G, A, L>
where
    A::Target: chain::Access,
    L::Target: Logger,
{
    /// Initializes a new [`GossipSync::P2P`] variant.
    pub fn p2p(gossip_sync: P) -> Self {
        GossipSync::P2P(gossip_sync)
    }
}

/// (C-not exported) as the bindings concretize everything and have constructors for us
impl<
        'a,
        R: Deref<Target = RapidGossipSync<G, L>>,
        G: Deref<Target = NetworkGraph<L>>,
        L: Deref,
    >
    GossipSync<
        &P2PGossipSync<G, &'a (dyn chain::Access + Send + Sync), L>,
        R,
        G,
        &'a (dyn chain::Access + Send + Sync),
        L,
    >
where
    L::Target: Logger,
{
    /// Initializes a new [`GossipSync::Rapid`] variant.
    pub fn rapid(gossip_sync: R) -> Self {
        GossipSync::Rapid(gossip_sync)
    }
}

/// (C-not exported) as the bindings concretize everything and have constructors for us
impl<'a, L: Deref>
    GossipSync<
        &P2PGossipSync<&'a NetworkGraph<L>, &'a (dyn chain::Access + Send + Sync), L>,
        &RapidGossipSync<&'a NetworkGraph<L>, L>,
        &'a NetworkGraph<L>,
        &'a (dyn chain::Access + Send + Sync),
        L,
    >
where
    L::Target: Logger,
{
    /// Initializes a new [`GossipSync::None`] variant.
    pub fn none() -> Self {
        GossipSync::None
    }
}

/// Decorates an [`EventHandler`] with common functionality provided by standard [`EventHandler`]s.
struct DecoratingEventHandler<
    'a,
    E: EventHandler,
    PGS: Deref<Target = P2PGossipSync<G, A, L>>,
    RGS: Deref<Target = RapidGossipSync<G, L>>,
    G: Deref<Target = NetworkGraph<L>>,
    A: Deref,
    L: Deref,
> where
    A::Target: chain::Access,
    L::Target: Logger,
{
    event_handler: E,
    gossip_sync: &'a GossipSync<PGS, RGS, G, A, L>,
}

impl<
        'a,
        E: EventHandler,
        PGS: Deref<Target = P2PGossipSync<G, A, L>>,
        RGS: Deref<Target = RapidGossipSync<G, L>>,
        G: Deref<Target = NetworkGraph<L>>,
        A: Deref,
        L: Deref,
    > EventHandler for DecoratingEventHandler<'a, E, PGS, RGS, G, A, L>
where
    A::Target: chain::Access,
    L::Target: Logger,
{
    fn handle_event(&self, event: &Event) {
        if let Some(network_graph) = self.gossip_sync.network_graph() {
            network_graph.handle_event(event);
        }
        self.event_handler.handle_event(event);
    }
}

macro_rules! define_run_body {
	($persister: ident, $event_handler: ident, $chain_monitor: ident, $channel_manager: ident,
	 $gossip_sync: ident, $peer_manager: ident, $logger: ident, $scorer: ident,
	 $loop_exit_check: expr, $await: expr)
	=> { {
		let event_handler = DecoratingEventHandler {
			event_handler: $event_handler,
			gossip_sync: &$gossip_sync,
		};

		trace!("Calling ChannelManager's timer_tick_occurred on startup");
		$channel_manager.timer_tick_occurred();

		let mut last_freshness_call = instant::now();
		let mut last_ping_call = instant::now();
		let mut last_prune_call = instant::now();
		let mut last_scorer_persist_call = instant::now();
		let mut have_pruned = false;

		loop {
                        utils::sleep(100).await;

			$channel_manager.process_pending_events(&event_handler);
			$chain_monitor.process_pending_events(&event_handler);

			// Note that the PeerManager::process_events may block on ChannelManager's locks,
			// hence it comes last here. When the ChannelManager finishes whatever it's doing,
			// we want to ensure we get into `persist_manager` as quickly as we can, especially
			// without running the normal event processing above and handing events to users.
			//
			// Specifically, on an *extremely* slow machine, we may see ChannelManager start
			// processing a message effectively at any point during this loop. In order to
			// minimize the time between such processing completing and persisting the updated
			// ChannelManager, we want to minimize methods blocking on a ChannelManager
			// generally, and as a fallback place such blocking only immediately before
			// persistence.
			$peer_manager.process_events();

			// We wait up to 100ms, but track how long it takes to detect being put to sleep,
			// see `await_start`'s use below.
			let await_start = instant::now();
			let updates_available = $await;
			let await_time = instant::now();

			if updates_available {
				trace!("Persisting ChannelManager...");
				let _ = $persister.persist_manager(&*$channel_manager);
				trace!("Done persisting ChannelManager.");
			}
			// Exit the loop if the background processor was requested to stop.
			if $loop_exit_check {
				trace!("Terminating background processor.");
				break;
			}
			if instant::now() - last_freshness_call > (1000 * FRESHNESS_TIMER) as f64 {
				trace!("Calling ChannelManager's timer_tick_occurred");
				$channel_manager.timer_tick_occurred();
				last_freshness_call = instant::now();
			}
			if await_time - await_start  > 1000 as f64  {
				// On various platforms, we may be starved of CPU cycles for several reasons.
				// E.g. on iOS, if we've been in the background, we will be entirely paused.
				// Similarly, if we're on a desktop platform and the device has been asleep, we
				// may not get any cycles.
				// We detect this by checking if our max-100ms-sleep, above, ran longer than a
				// full second, at which point we assume sockets may have been killed (they
				// appear to be at least on some platforms, even if it has only been a second).
				// Note that we have to take care to not get here just because user event
				// processing was slow at the top of the loop. For example, the sample client
				// may call Bitcoin Core RPCs during event handling, which very often takes
				// more than a handful of seconds to complete, and shouldn't disconnect all our
				// peers.
				trace!("100ms sleep took more than a second, disconnecting peers.");
				$peer_manager.disconnect_all_peers();
				last_ping_call = instant::now();
			} else if instant::now() - last_ping_call > (1000 * PING_TIMER) as f64 {
				trace!("Calling PeerManager's timer_tick_occurred");
				$peer_manager.timer_tick_occurred();
				last_ping_call = instant::now();
			}

			// Note that we want to run a graph prune once not long after startup before
			// falling back to our usual hourly prunes. This avoids short-lived clients never
			// pruning their network graph. We run once 60 seconds after startup before
			// continuing our normal cadence.
			if instant::now() - last_prune_call > if have_pruned { (1000 * NETWORK_PRUNE_TIMER) as f64 } else { (1000 * FIRST_NETWORK_PRUNE_TIMER) as f64 } {
				// The network graph must not be pruned while rapid sync completion is pending
				trace!("Assessing prunability of network graph");
				if let Some(network_graph) = $gossip_sync.prunable_network_graph() {
					network_graph.remove_stale_channels_and_tracking();

					if let Err(e) = $persister.persist_graph(network_graph) {
						error!("Error: Failed to persist network graph, check your disk and permissions {}", e)
					}

					last_prune_call = instant::now();
					have_pruned = true;
				} else {
					trace!("Not pruning network graph, either due to pending rapid gossip sync or absence of a prunable graph.");
				}
			}

			if instant::now() - last_scorer_persist_call > (1000 * SCORER_PERSIST_TIMER) as f64 {
				if let Some(ref scorer) = $scorer {
					trace!("Persisting scorer");
					if let Err(e) = $persister.persist_scorer(&scorer) {
						error!("Error: Failed to persist scorer, check your disk and permissions {}", e)
					}
				}
				last_scorer_persist_call = instant::now();
			}
		}

		// After we exit, ensure we persist the ChannelManager one final time - this avoids
		// some races where users quit while channel updates were in-flight, with
		// ChannelMonitor update(s) persisted without a corresponding ChannelManager update.
		let _ = $persister.persist_manager(&*$channel_manager);

		// Persist Scorer on exit
		if let Some(ref scorer) = $scorer {
			let _ = $persister.persist_scorer(&scorer);
		}

		// Persist NetworkGraph on exit
		if let Some(network_graph) = $gossip_sync.network_graph() {
			let _ = $persister.persist_graph(network_graph);
		}
	} }
}

impl BackgroundProcessor {
    /// Start a background thread that takes care of responsibilities enumerated in the [top-level
    /// documentation].
    ///
    /// The thread runs indefinitely unless the object is dropped, [`stop`] is called, or
    /// [`Persister::persist_manager`] returns an error. In case of an error, the error is retrieved by calling
    /// either [`join`] or [`stop`].
    ///
    /// # Data Persistence
    ///
    /// [`Persister::persist_manager`] is responsible for writing out the [`ChannelManager`] to disk, and/or
    /// uploading to one or more backup services. See [`ChannelManager::write`] for writing out a
    /// [`ChannelManager`]. See the `lightning-persister` crate for LDK's
    /// provided implementation.
    ///
    /// [`Persister::persist_graph`] is responsible for writing out the [`NetworkGraph`] to disk, if
    /// [`GossipSync`] is supplied. See [`NetworkGraph::write`] for writing out a [`NetworkGraph`].
    /// See the `lightning-persister` crate for LDK's provided implementation.
    ///
    /// Typically, users should either implement [`Persister::persist_manager`] to never return an
    /// error or call [`join`] and handle any error that may arise. For the latter case,
    /// `BackgroundProcessor` must be restarted by calling `start` again after handling the error.
    ///
    /// # Event Handling
    ///
    /// `event_handler` is responsible for handling events that users should be notified of (e.g.,
    /// payment failed). [`BackgroundProcessor`] may decorate the given [`EventHandler`] with common
    /// functionality implemented by other handlers.
    /// * [`P2PGossipSync`] if given will update the [`NetworkGraph`] based on payment failures.
    ///
    /// # Rapid Gossip Sync
    ///
    /// If rapid gossip sync is meant to run at startup, pass [`RapidGossipSync`] via `gossip_sync`
    /// to indicate that the [`BackgroundProcessor`] should not prune the [`NetworkGraph`] instance
    /// until the [`RapidGossipSync`] instance completes its first sync.
    ///
    /// [top-level documentation]: BackgroundProcessor
    /// [`join`]: Self::join
    /// [`stop`]: Self::stop
    /// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
    /// [`ChannelManager::write`]: lightning::ln::channelmanager::ChannelManager#impl-Writeable
    /// [`Persister::persist_manager`]: lightning::util::persist::Persister::persist_manager
    /// [`Persister::persist_graph`]: lightning::util::persist::Persister::persist_graph
    /// [`NetworkGraph`]: lightning::routing::gossip::NetworkGraph
    /// [`NetworkGraph::write`]: lightning::routing::gossip::NetworkGraph#impl-Writeable
    pub fn start<
        'a,
        Signer: 'static + Sign,
        CA: 'static + Deref + Send + Sync,
        CF: 'static + Deref + Send + Sync,
        CW: 'static + Deref + Send + Sync,
        T: 'static + Deref + Send + Sync,
        K: 'static + Deref + Send + Sync,
        F: 'static + Deref + Send + Sync,
        G: 'static + Deref<Target = NetworkGraph<L>> + Send + Sync,
        L: 'static + Deref + Send + Sync,
        P: 'static + Deref + Send + Sync,
        Descriptor: 'static + SocketDescriptor + Send + Sync,
        CMH: 'static + Deref + Send + Sync,
        OMH: 'static + Deref + Send + Sync,
        RMH: 'static + Deref + Send + Sync,
        EH: 'static + EventHandler + Send,
        PS: 'static + Deref + Send,
        M: 'static + Deref<Target = ChainMonitor<Signer, CF, T, F, L, P>> + Send + Sync,
        CM: 'static + Deref<Target = ChannelManager<Signer, CW, T, K, F, L>> + Send + Sync,
        PGS: 'static + Deref<Target = P2PGossipSync<G, CA, L>> + Send + Sync,
        RGS: 'static + Deref<Target = RapidGossipSync<G, L>> + Send,
        UMH: 'static + Deref + Send + Sync,
        PM: 'static + Deref<Target = PeerManager<Descriptor, CMH, RMH, OMH, L, UMH>> + Send + Sync,
        S: 'static + Deref<Target = SC> + Send + Sync,
        SC: WriteableScore<'a>,
    >(
        persister: PS,
        event_handler: EH,
        chain_monitor: M,
        channel_manager: CM,
        gossip_sync: GossipSync<PGS, RGS, G, CA, L>,
        peer_manager: PM,
        _logger: L,
        scorer: Option<S>,
    ) -> Self
    where
        CA::Target: 'static + chain::Access,
        CF::Target: 'static + chain::Filter,
        CW::Target: 'static + chain::Watch<Signer>,
        T::Target: 'static + BroadcasterInterface,
        K::Target: 'static + KeysInterface<Signer = Signer>,
        F::Target: 'static + FeeEstimator,
        L::Target: 'static + Logger,
        P::Target: 'static + Persist<Signer>,
        CMH::Target: 'static + ChannelMessageHandler,
        OMH::Target: 'static + OnionMessageHandler,
        RMH::Target: 'static + RoutingMessageHandler,
        UMH::Target: 'static + CustomMessageHandler,
        PS::Target: 'static + Persister<'a, Signer, CW, T, K, F, L, SC>,
    {
        let stop_thread = Arc::new(AtomicBool::new(false));
        let stop_thread_clone = stop_thread.clone();
        let _ = spawn_local(async move {
            let _ = define_run_body!(
                persister,
                event_handler,
                chain_monitor,
                channel_manager,
                gossip_sync,
                peer_manager,
                logger,
                scorer,
                stop_thread.load(Ordering::Acquire),
                should_update_channel_manager()
            );
        });
        Self {
            stop_thread: stop_thread_clone,
            thread_handle: None,
        }
    }

    /// Join `BackgroundProcessor`'s thread, returning any error that occurred while persisting
    /// [`ChannelManager`].
    ///
    /// # Panics
    ///
    /// This function panics if the background thread has panicked such as while persisting or
    /// handling events.
    ///
    /// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
    pub fn join(mut self) -> Result<(), std::io::Error> {
        assert!(self.thread_handle.is_some());
        self.join_thread()
    }

    /// Stop `BackgroundProcessor`'s thread, returning any error that occurred while persisting
    /// [`ChannelManager`].
    ///
    /// # Panics
    ///
    /// This function panics if the background thread has panicked such as while persisting or
    /// handling events.
    ///
    /// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
    pub fn stop(mut self) -> Result<(), std::io::Error> {
        assert!(self.thread_handle.is_some());
        self.stop_and_join_thread()
    }

    fn stop_and_join_thread(&mut self) -> Result<(), std::io::Error> {
        self.stop_thread.store(true, Ordering::Release);
        self.join_thread()
    }

    fn join_thread(&mut self) -> Result<(), std::io::Error> {
        match self.thread_handle.take() {
            Some(handle) => handle.join().unwrap(),
            None => Ok(()),
        }
    }
}

impl Drop for BackgroundProcessor {
    fn drop(&mut self) {
        self.stop_and_join_thread().unwrap();
    }
}

fn should_update_channel_manager() -> bool {
    // TODO
    true
}
