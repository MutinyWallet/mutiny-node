//! Utilities that take care of tasks that (1) need to happen periodically to keep Rust-Lightning
//! running properly, and (2) either can or should be run in the background. See docs for
//! [`BackgroundProcessor`] for more details on the nitty-gritty.

// Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(broken_intra_doc_links)]
#![deny(private_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(dead_code)]

#[cfg(any(test, feature = "std"))]
extern crate core;

use log::{error, trace, warn};

#[cfg(not(feature = "std"))]
extern crate alloc;

// #[macro_use] extern crate lightning;
extern crate lightning_rapid_gossip_sync;

use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::{ChainMonitor, Persist};
use lightning::chain::keysinterface::{EntropySource, NodeSigner, SignerProvider};
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::msgs::{ChannelMessageHandler, OnionMessageHandler, RoutingMessageHandler};
use lightning::ln::peer_handler::{CustomMessageHandler, PeerManager, SocketDescriptor};
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::router::Router;
use lightning::routing::scoring::{Score, WriteableScore};
use lightning::routing::utxo::UtxoLookup;
use lightning::util::events::{Event, PathFailure};
#[cfg(feature = "std")]
use lightning::util::events::{EventHandler, EventsProvider};
use lightning::util::logger::Logger;
use lightning::util::persist::Persister;
use lightning_rapid_gossip_sync::RapidGossipSync;

use core::ops::Deref;
use core::time::Duration;

#[cfg(feature = "std")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "std")]
use std::sync::Arc;
#[cfg(feature = "std")]
use std::thread::{self, JoinHandle};
#[cfg(feature = "std")]
use std::time::Instant;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use futures_util::{future::FutureExt, select_biased, task};

#[cfg(not(test))]
const FRESHNESS_TIMER: u64 = 60;
#[cfg(test)]
const FRESHNESS_TIMER: u64 = 1;

#[cfg(all(not(test), not(debug_assertions)))]
const PING_TIMER: u64 = 10;
/// Signature operations take a lot longer without compiler optimisations.
/// Increasing the ping timer allows for this but slower devices will be disconnected if the
/// timeout is reached.
#[cfg(all(not(test), debug_assertions))]
const PING_TIMER: u64 = 30;
#[cfg(test)]
const PING_TIMER: u64 = 1;

/// Prune the network graph of stale entries hourly.
const NETWORK_PRUNE_TIMER: u64 = 60 * 60;

#[cfg(not(test))]
const SCORER_PERSIST_TIMER: u64 = 30;
#[cfg(test)]
const SCORER_PERSIST_TIMER: u64 = 1;

#[cfg(not(test))]
const FIRST_NETWORK_PRUNE_TIMER: u64 = 60;
#[cfg(test)]
const FIRST_NETWORK_PRUNE_TIMER: u64 = 1;

/// Either [`P2PGossipSync`] or [`RapidGossipSync`].
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

fn handle_network_graph_update<L: Deref>(network_graph: &NetworkGraph<L>, event: &Event)
where
    L::Target: Logger,
{
    if let Event::PaymentPathFailed {
        failure: PathFailure::OnPath {
            network_update: Some(ref upd),
        },
        ..
    } = event
    {
        network_graph.handle_network_update(upd);
    }
}

fn update_scorer<'a, S: 'static + Deref<Target = SC>, SC: 'a + WriteableScore<'a>>(
    scorer: &'a S,
    event: &Event,
) {
    let mut score = scorer.lock();
    match event {
        Event::PaymentPathFailed {
            ref path,
            short_channel_id: Some(scid),
            ..
        } => {
            let path = path.iter().collect::<Vec<_>>();
            score.payment_path_failed(&path, *scid);
        }
        Event::PaymentPathFailed {
            ref path,
            payment_failed_permanently: true,
            ..
        } => {
            // Reached if the destination explicitly failed it back. We treat this as a successful probe
            // because the payment made it all the way to the destination with sufficient liquidity.
            let path = path.iter().collect::<Vec<_>>();
            score.probe_successful(&path);
        }
        Event::PaymentPathSuccessful { path, .. } => {
            let path = path.iter().collect::<Vec<_>>();
            score.payment_path_successful(&path);
        }
        Event::ProbeSuccessful { path, .. } => {
            let path = path.iter().collect::<Vec<_>>();
            score.probe_successful(&path);
        }
        Event::ProbeFailed {
            path,
            short_channel_id: Some(scid),
            ..
        } => {
            let path = path.iter().collect::<Vec<_>>();
            score.probe_failed(&path, *scid);
        }
        _ => {}
    }
}

macro_rules! define_run_body {
	($persister: ident, $chain_monitor: ident, $process_chain_monitor_events: expr,
	 $channel_manager: ident, $process_channel_manager_events: expr,
	 $gossip_sync: ident, $peer_manager: ident, $logger: ident, $scorer: ident,
	 $loop_exit_check: expr, $await: expr, $get_timer: expr, $timer_elapsed: expr)
	=> { {
		trace!("Calling ChannelManager's timer_tick_occurred on startup");
		$channel_manager.timer_tick_occurred();

		let mut last_freshness_call = $get_timer(FRESHNESS_TIMER);
		let mut last_ping_call = $get_timer(PING_TIMER);
		let mut last_prune_call = $get_timer(FIRST_NETWORK_PRUNE_TIMER);
		let mut last_scorer_persist_call = $get_timer(SCORER_PERSIST_TIMER);
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
			let mut await_start = $get_timer(1);
			let updates_available = $await;
			let await_slow = $timer_elapsed(&mut await_start, 1);

			if updates_available {
				trace!("Persisting ChannelManager...");
				$persister.persist_manager(&*$channel_manager)?;
				trace!("Done persisting ChannelManager.");
			}
			// Exit the loop if the background processor was requested to stop.
			if $loop_exit_check {
				trace!("Terminating background processor.");
				break;
			}
			if $timer_elapsed(&mut last_freshness_call, FRESHNESS_TIMER) {
				trace!("Calling ChannelManager's timer_tick_occurred");
				$channel_manager.timer_tick_occurred();
				last_freshness_call = $get_timer(FRESHNESS_TIMER);
			}
			if await_slow {
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
				last_ping_call = $get_timer(PING_TIMER);
			} else if $timer_elapsed(&mut last_ping_call, PING_TIMER) {
				trace!("Calling PeerManager's timer_tick_occurred");
				$peer_manager.timer_tick_occurred();
				last_ping_call = $get_timer(PING_TIMER);
			}

			// Note that we want to run a graph prune once not long after startup before
			// falling back to our usual hourly prunes. This avoids short-lived clients never
			// pruning their network graph. We run once 60 seconds after startup before
			// continuing our normal cadence.
			if $timer_elapsed(&mut last_prune_call, if have_pruned { NETWORK_PRUNE_TIMER } else { FIRST_NETWORK_PRUNE_TIMER }) {
				// The network graph must not be pruned while rapid sync completion is pending
				if let Some(network_graph) = $gossip_sync.prunable_network_graph() {
					#[cfg(feature = "std")] {
						trace!("Pruning and persisting network graph.");
						network_graph.remove_stale_channels_and_tracking();
					}
					#[cfg(not(feature = "std"))] {
						warn!("Not pruning network graph, consider enabling `std` or doing so manually with remove_stale_channels_and_tracking_with_time.");
						trace!("Persisting network graph.");
					}

					if let Err(e) = $persister.persist_graph(network_graph) {
						error!("Error: Failed to persist network graph, check your disk and permissions {}", e)
					}

					have_pruned = true;
				}
				last_prune_call = $get_timer(NETWORK_PRUNE_TIMER);
			}

			if $timer_elapsed(&mut last_scorer_persist_call, SCORER_PERSIST_TIMER) {
				if let Some(ref scorer) = $scorer {
					trace!("Persisting scorer");
					if let Err(e) = $persister.persist_scorer(&scorer) {
						error!("Error: Failed to persist scorer, check your disk and permissions {}", e)
					}
				}
				last_scorer_persist_call = $get_timer(SCORER_PERSIST_TIMER);
			}
		}

		// After we exit, ensure we persist the ChannelManager one final time - this avoids
		// some races where users quit while channel updates were in-flight, with
		// ChannelMonitor update(s) persisted without a corresponding ChannelManager update.
		$persister.persist_manager(&*$channel_manager)?;

		// Persist Scorer on exit
		if let Some(ref scorer) = $scorer {
			$persister.persist_scorer(&scorer)?;
		}

		// Persist NetworkGraph on exit
		if let Some(network_graph) = $gossip_sync.network_graph() {
			$persister.persist_graph(network_graph)?;
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
///
/// Requires the `futures` feature. Note that while this method is available without the `std`
/// feature, doing so will skip calling [`NetworkGraph::remove_stale_channels_and_tracking`],
/// you should call [`NetworkGraph::remove_stale_channels_and_tracking_with_time`] regularly
/// manually instead.
pub async fn process_events_async<
    'a,
    UL: 'static + Deref,
    CF: 'static + Deref,
    CW: 'static + Deref,
    T: 'static + Deref,
    ES: 'static + Deref,
    NS: 'static + Deref,
    SP: 'static + Deref,
    F: 'static + Deref,
    R: 'static + Deref,
    G: 'static + Deref<Target = NetworkGraph<L>>,
    L: 'static + Deref,
    P: 'static + Deref,
    Descriptor: 'static + SocketDescriptor,
    CMH: 'static + Deref,
    RMH: 'static + Deref,
    OMH: 'static + Deref,
    EventHandlerFuture: core::future::Future<Output = ()>,
    EventHandler: Fn(Event) -> EventHandlerFuture,
    PS: 'static + Deref,
    M: 'static + Deref<Target = ChainMonitor<<SP::Target as SignerProvider>::Signer, CF, T, F, L, P>>,
    CM: 'static + Deref<Target = ChannelManager<CW, T, ES, NS, SP, F, R, L>>,
    PGS: 'static + Deref<Target = P2PGossipSync<G, UL, L>>,
    RGS: 'static + Deref<Target = RapidGossipSync<G, L>>,
    UMH: 'static + Deref + Send + Sync,
    PM: 'static + Deref<Target = PeerManager<Descriptor, CMH, RMH, OMH, L, UMH, NS>>,
    S: 'static + Deref<Target = SC>,
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
    _logger: L,
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
        let scorer = &scorer;
        async move {
            if let Some(network_graph) = network_graph {
                handle_network_graph_update(network_graph, &event)
            }
            if let Some(ref scorer) = scorer {
                update_scorer(scorer, &event);
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
        logger,
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
        },
        |t| sleeper(Duration::from_secs(t)),
        |fut: &mut SleepFuture, _| {
            let mut waker = task::noop_waker();
            let mut ctx = task::Context::from_waker(&mut waker);
            core::pin::Pin::new(fut).poll(&mut ctx).is_ready()
        }
    )
}
