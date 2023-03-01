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
use futures_util::{future::FutureExt, select_biased};
use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::{ChainMonitor, Persist};
use lightning::chain::keysinterface::{EntropySource, NodeSigner, SignerProvider};
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::msgs::{ChannelMessageHandler, OnionMessageHandler, RoutingMessageHandler};
use lightning::ln::peer_handler::{CustomMessageHandler, PeerManager, SocketDescriptor};
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::router::Router;
use lightning::routing::scoring::WriteableScore;
use lightning::routing::utxo::UtxoLookup;
use lightning::util::events::{Event, EventHandler};
use lightning::util::logger::Logger;
use lightning::util::persist::Persister;
use lightning_rapid_gossip_sync::RapidGossipSync;
use log::{debug, error, trace};
use std::ops::Deref;
use std::time::Duration;

const FRESHNESS_TIMER: u64 = 60;

const PING_TIMER: u64 = 30;

/// Prune the network graph of stale entries hourly.
const NETWORK_PRUNE_TIMER: u64 = 60 * 60;

const SCORER_PERSIST_TIMER: u64 = 30;

const FIRST_NETWORK_PRUNE_TIMER: u64 = 60;

/// Either [`P2PGossipSync`] or [`RapidGossipSync`].
// FIXME: Use for routing soon
#[allow(dead_code)]
pub enum GossipSync<
    P: Deref<Target = P2PGossipSync<G, U, L>>,
    R: Deref<Target = RapidGossipSync<G, L>>,
    G: Deref<Target = NetworkGraph<L>>,
    U: Deref,
    L: Deref,
> where
    U::Target: UtxoLookup,
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
        P: Deref<Target = P2PGossipSync<G, U, L>>,
        R: Deref<Target = RapidGossipSync<G, L>>,
        G: Deref<Target = NetworkGraph<L>>,
        U: Deref,
        L: Deref,
    > GossipSync<P, R, G, U, L>
where
    U::Target: UtxoLookup,
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
        P: Deref<Target = P2PGossipSync<G, U, L>>,
        G: Deref<Target = NetworkGraph<L>>,
        U: Deref,
        L: Deref,
    > GossipSync<P, &RapidGossipSync<G, L>, G, U, L>
where
    U::Target: UtxoLookup,
    L::Target: Logger,
{
    /// Initializes a new [`GossipSync::P2P`] variant.
    // FIXME: Use for routing soon
    #[allow(dead_code)]
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
        &P2PGossipSync<G, &'a (dyn UtxoLookup + Send + Sync), L>,
        R,
        G,
        &'a (dyn UtxoLookup + Send + Sync),
        L,
    >
where
    L::Target: Logger,
{
    /// Initializes a new [`GossipSync::Rapid`] variant.
    // FIXME: Use for routing soon
    #[allow(dead_code)]
    pub fn rapid(gossip_sync: R) -> Self {
        GossipSync::Rapid(gossip_sync)
    }
}

/// (C-not exported) as the bindings concretize everything and have constructors for us
impl<'a, L: Deref>
    GossipSync<
        &P2PGossipSync<&'a NetworkGraph<L>, &'a (dyn UtxoLookup + Send + Sync), L>,
        &RapidGossipSync<&'a NetworkGraph<L>, L>,
        &'a NetworkGraph<L>,
        &'a (dyn UtxoLookup + Send + Sync),
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
/*
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
    fn handle_event(&self, event: Event) {
        if let Some(network_graph) = self.gossip_sync.network_graph() {
            handle_network_graph_update(network_graph, &event);
        }
        self.event_handler.handle_event(event);
    }
}
*/

#[allow(clippy::collapsible_match)]
fn handle_network_graph_update<L: Deref>(network_graph: &NetworkGraph<L>, event: &Event)
where
    L::Target: Logger,
{
    if let Event::PaymentPathFailed {
        ref network_update, ..
    } = event
    {
        if let Some(network_update) = network_update {
            network_graph.handle_network_update(network_update);
        }
    }
}

macro_rules! define_run_body {
	($persister: ident, $chain_monitor: ident, $process_chain_monitor_events: expr,
	 $channel_manager: ident, $process_channel_manager_events: expr,
	 $gossip_sync: ident, $peer_manager: ident, $logger: ident, $scorer: ident,
	 $loop_exit_check: expr, $await: expr)
	=> { {
		trace!("Calling ChannelManager's timer_tick_occurred on startup");
		$channel_manager.timer_tick_occurred();

		let mut last_freshness_call = instant::now();
		let mut last_ping_call = instant::now();
		let mut last_prune_call = instant::now();
		let mut last_scorer_persist_call = instant::now();
		let mut have_pruned = false;

		loop {
			$process_channel_manager_events;
			$process_chain_monitor_events;

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
			if await_time - await_start  > (1000 * 2) as f64 {
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
				debug!("100ms sleep took more than 2 seconds, disconnecting peers.");
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

        Ok(())
	} }
}

/// Processes background events in a future.
///
/// `sleeper` should return a future which completes in the given amount of time and returns a
/// boolean indicating whether the background processing should exit. Once `sleeper` returns a
/// future which outputs true, the loop will exit and this function's future will complete.
///
/// See [`BackgroundProcessor::start`] for information on which actions this handles.
#[allow(clippy::too_many_arguments)]
pub async fn process_events_async<
    'a,
    UL: 'static + Deref + Send + Sync,
    CF: 'static + Deref + Send + Sync,
    CW: 'static + Deref + Send + Sync,
    T: 'static + Deref + Send + Sync,
    ES: 'static + Deref + Send + Sync,
    NS: 'static + Deref + Send + Sync,
    SP: 'static + Deref + Send + Sync,
    F: 'static + Deref + Send + Sync,
    R: 'static + Deref + Send + Sync,
    G: 'static + Deref<Target = NetworkGraph<L>> + Send + Sync,
    L: 'static + Deref + Send + Sync,
    P: 'static + Deref + Send + Sync,
    Descriptor: 'static + SocketDescriptor + Send + Sync,
    CMH: 'static + Deref + Send + Sync,
    RMH: 'static + Deref + Send + Sync,
    OMH: 'static + Deref + Send + Sync,
    EventHandlerFuture: core::future::Future<Output = ()>,
    EventHandler: Fn(Event) -> EventHandlerFuture,
    PS: 'static + Deref + Send,
    M: 'static
        + Deref<Target = ChainMonitor<<SP::Target as SignerProvider>::Signer, CF, T, F, L, P>>
        + Send
        + Sync,
    CM: 'static + Deref<Target = ChannelManager<CW, T, ES, NS, SP, F, R, L>> + Send + Sync,
    PGS: 'static + Deref<Target = P2PGossipSync<G, UL, L>> + Send + Sync,
    RGS: 'static + Deref<Target = RapidGossipSync<G, L>> + Send,
    UMH: 'static + Deref + Send + Sync,
    PM: 'static + Deref<Target = PeerManager<Descriptor, CMH, RMH, OMH, L, UMH, NS>> + Send + Sync,
    S: 'static + Deref<Target = SC> + Send + Sync,
    SC: for<'b> WriteableScore<'b>,
    SleepFuture: core::future::Future<Output = bool> + core::marker::Unpin,
    Sleeper: Fn(Duration) -> SleepFuture,
>(
    persister: PS,
    event_handler: EventHandler,
    chain_monitor: M,
    channel_manager: CM,
    gossip_sync: GossipSync<PGS, RGS, G, UL, L>,
    peer_manager: PM,
    logger: L,
    scorer: Option<S>,
    sleeper: Sleeper,
) -> Result<(), lightning::io::Error>
where
    UL::Target: 'static + UtxoLookup,
    CF::Target: 'static + chain::Filter,
    CW::Target: 'static + chain::Watch<<SP::Target as SignerProvider>::Signer>,
    T::Target: 'static + BroadcasterInterface,
    ES::Target: 'static + EntropySource,
    NS::Target: 'static + NodeSigner,
    SP::Target: 'static + SignerProvider,
    F::Target: 'static + FeeEstimator,
    R::Target: 'static + Router,
    L::Target: 'static + Logger,
    P::Target: 'static + Persist<<SP::Target as SignerProvider>::Signer>,
    CMH::Target: 'static + ChannelMessageHandler,
    OMH::Target: 'static + OnionMessageHandler,
    RMH::Target: 'static + RoutingMessageHandler,
    UMH::Target: 'static + CustomMessageHandler,
    PS::Target: 'static + Persister<'a, CW, T, ES, NS, SP, F, R, L, SC>,
{
    let mut should_break = true;
    let async_event_handler = |event| {
        let network_graph = gossip_sync.network_graph();
        let event_handler = &event_handler;
        async move {
            if let Some(network_graph) = network_graph {
                handle_network_graph_update(network_graph, &event)
            }
            event_handler(event).await;
        }
    };
    define_run_body!(
        persister,
        chain_monitor,
        chain_monitor
            .process_pending_events_async(async_event_handler)
            .await,
        channel_manager,
        channel_manager
            .process_pending_events_async(async_event_handler)
            .await,
        gossip_sync,
        peer_manager,
        _logger,
        scorer,
        should_break,
        {
            select_biased! {
                _ = channel_manager.get_persistable_update_future().fuse() => true,
                exit = sleeper(Duration::from_millis(100)).fuse() => {
                    should_break = exit;
                    false
                }
            }
        }
    )
}
