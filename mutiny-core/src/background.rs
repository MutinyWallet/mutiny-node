//! Utilities that take care of tasks that (1) need to happen periodically to keep Rust-Lightning
//! running properly, and (2) either can or should be run in the background. See docs for
//! [`BackgroundProcessor`] for more details on the nitty-gritty.

// Prefix these with `rustdoc::` when we update our MSRV to be >= 1.52 to remove warnings.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![allow(dead_code)]
#![allow(clippy::all)]

#[cfg(any(test, feature = "std"))]
extern crate core;

use lightning::{log_error, log_trace};

#[cfg(not(feature = "std"))]
extern crate alloc;

use lightning::chain;
use lightning::chain::chaininterface::{BroadcasterInterface, FeeEstimator};
use lightning::chain::chainmonitor::{ChainMonitor, Persist};
use lightning::events::{Event, PathFailure};
use lightning::ln::channelmanager::ChannelManager;
use lightning::ln::peer_handler::APeerManager;
use lightning::routing::gossip::{NetworkGraph, P2PGossipSync};
use lightning::routing::router::Router;
use lightning::routing::scoring::{ScoreUpdate, WriteableScore};
use lightning::routing::utxo::UtxoLookup;
use lightning::sign::{EntropySource, NodeSigner, SignerProvider};
use lightning::util::logger::Logger;
use lightning::util::persist::Persister;
use lightning_rapid_gossip_sync::RapidGossipSync;

use core::ops::Deref;
use core::time::Duration;

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
const SCORER_PERSIST_TIMER: u64 = 60 * 60;
#[cfg(test)]
const SCORER_PERSIST_TIMER: u64 = 1;

#[cfg(not(test))]
const FIRST_NETWORK_PRUNE_TIMER: u64 = 60;
#[cfg(test)]
const FIRST_NETWORK_PRUNE_TIMER: u64 = 1;

#[cfg(not(test))]
const REBROADCAST_TIMER: u64 = 30;
#[cfg(test)]
const REBROADCAST_TIMER: u64 = 1;

/// core::cmp::min is not currently const, so we define a trivial (and equivalent) replacement
const fn min_u64(a: u64, b: u64) -> u64 {
    if a < b {
        a
    } else {
        b
    }
}
const FASTEST_TIMER: u64 = min_u64(
    min_u64(FRESHNESS_TIMER, PING_TIMER),
    min_u64(
        SCORER_PERSIST_TIMER,
        min_u64(FIRST_NETWORK_PRUNE_TIMER, REBROADCAST_TIMER),
    ),
);

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

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
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

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
impl<
        'a,
        R: Deref<Target = RapidGossipSync<G, L>>,
        G: Deref<Target = NetworkGraph<L>>,
        L: Deref,
    > GossipSync<&P2PGossipSync<G, &'a (dyn UtxoLookup), L>, R, G, &'a (dyn UtxoLookup), L>
where
    L::Target: Logger,
{
    /// Initializes a new [`GossipSync::Rapid`] variant.
    pub fn rapid(gossip_sync: R) -> Self {
        GossipSync::Rapid(gossip_sync)
    }
}

/// This is not exported to bindings users as the bindings concretize everything and have constructors for us
impl<'a, L: Deref>
    GossipSync<
        &P2PGossipSync<&'a NetworkGraph<L>, &'a (dyn UtxoLookup), L>,
        &RapidGossipSync<&'a NetworkGraph<L>, L>,
        &'a NetworkGraph<L>,
        &'a (dyn UtxoLookup),
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

/// Updates scorer based on event and returns whether an update occurred so we can decide whether
/// to persist.
fn update_scorer<'a, S: 'static + Deref<Target = SC>, SC: 'a + WriteableScore<'a>>(
    scorer: &'a S,
    event: &Event,
) -> bool {
    match event {
        Event::PaymentPathFailed {
            ref path,
            short_channel_id: Some(scid),
            ..
        } => {
            let mut score = scorer.write_lock();
            score.payment_path_failed(path, *scid);
        }
        Event::PaymentPathFailed {
            ref path,
            payment_failed_permanently: true,
            ..
        } => {
            // Reached if the destination explicitly failed it back. We treat this as a successful probe
            // because the payment made it all the way to the destination with sufficient liquidity.
            let mut score = scorer.write_lock();
            score.probe_successful(path);
        }
        Event::PaymentPathSuccessful { path, .. } => {
            let mut score = scorer.write_lock();
            score.payment_path_successful(path);
        }
        Event::ProbeSuccessful { path, .. } => {
            let mut score = scorer.write_lock();
            score.probe_successful(path);
        }
        Event::ProbeFailed {
            path,
            short_channel_id: Some(scid),
            ..
        } => {
            let mut score = scorer.write_lock();
            score.probe_failed(path, *scid);
        }
        _ => return false,
    }
    true
}

macro_rules! define_run_body {
	($persister: ident, $chain_monitor: ident, $process_chain_monitor_events: expr,
	 $channel_manager: ident, $process_channel_manager_events: expr,
	 $gossip_sync: ident, $peer_manager: ident, $logger: ident, $scorer: ident,
	 $loop_exit_check: expr, $await: expr, $get_timer: expr, $timer_elapsed: expr,
	 $check_slow_await: expr)
	=> { {
		log_trace!($logger, "Calling ChannelManager's timer_tick_occurred on startup");
		$channel_manager.timer_tick_occurred();
		log_trace!($logger, "Rebroadcasting monitor's pending claims on startup");
		$chain_monitor.rebroadcast_pending_claims();

		let mut last_freshness_call = $get_timer(FRESHNESS_TIMER);
		let mut last_ping_call = $get_timer(PING_TIMER);
		let mut last_prune_call = $get_timer(FIRST_NETWORK_PRUNE_TIMER);
		let mut last_scorer_persist_call = $get_timer(SCORER_PERSIST_TIMER);
		let mut last_rebroadcast_call = $get_timer(REBROADCAST_TIMER);
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
			$peer_manager.as_ref().process_events();

			// Exit the loop if the background processor was requested to stop.
			if $loop_exit_check {
				log_trace!($logger, "Terminating background processor.");
				break;
			}

			// We wait up to 100ms, but track how long it takes to detect being put to sleep,
			// see `await_start`'s use below.
			let mut await_start = None;
			if $check_slow_await { await_start = Some($get_timer(1)); }
			$await;
			let await_slow = if $check_slow_await { $timer_elapsed(&mut await_start.unwrap(), 1) } else { false };

			// Exit the loop if the background processor was requested to stop.
			if $loop_exit_check {
				log_trace!($logger, "Terminating background processor.");
				break;
			}

			if $channel_manager.get_and_clear_needs_persistence() {
				log_trace!($logger, "Persisting ChannelManager...");
				$persister.persist_manager(&*$channel_manager)?;
				log_trace!($logger, "Done persisting ChannelManager.");
			}
			if $timer_elapsed(&mut last_freshness_call, FRESHNESS_TIMER) {
				log_trace!($logger, "Calling ChannelManager's timer_tick_occurred");
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
				log_trace!($logger, "100ms sleep took more than a second, disconnecting peers.");
				$peer_manager.as_ref().disconnect_all_peers();
				last_ping_call = $get_timer(PING_TIMER);
			} else if $timer_elapsed(&mut last_ping_call, PING_TIMER) {
				log_trace!($logger, "Calling PeerManager's timer_tick_occurred");
				$peer_manager.as_ref().timer_tick_occurred();
				last_ping_call = $get_timer(PING_TIMER);
			}

			// Note that we want to run a graph prune once not long after startup before
			// falling back to our usual hourly prunes. This avoids short-lived clients never
			// pruning their network graph. We run once 60 seconds after startup before
			// continuing our normal cadence. For RGS, since 60 seconds is likely too long,
			// we prune after an initial sync completes.
			let prune_timer = if have_pruned { NETWORK_PRUNE_TIMER } else { FIRST_NETWORK_PRUNE_TIMER };
			let prune_timer_elapsed = $timer_elapsed(&mut last_prune_call, prune_timer);
			let should_prune = match $gossip_sync {
				GossipSync::Rapid(_) => !have_pruned || prune_timer_elapsed,
				_ => prune_timer_elapsed,
			};
			if should_prune {
				// The network graph must not be pruned while rapid sync completion is pending
				if let Some(network_graph) = $gossip_sync.prunable_network_graph() {
					#[cfg(not(feature = "std"))] {
						log_trace!($logger, "Persisting network graph.");
					}

					if let Err(e) = $persister.persist_graph(network_graph) {
						log_error!($logger, "Error: Failed to persist network graph, check your disk and permissions {}", e)
					}

					have_pruned = true;
				}
				let prune_timer = if have_pruned { NETWORK_PRUNE_TIMER } else { FIRST_NETWORK_PRUNE_TIMER };
				last_prune_call = $get_timer(prune_timer);
			}

			if $timer_elapsed(&mut last_scorer_persist_call, SCORER_PERSIST_TIMER) {
				if let Some(ref scorer) = $scorer {
					log_trace!($logger, "Persisting scorer");
					if let Err(e) = $persister.persist_scorer(&scorer) {
						log_error!($logger, "Error: Failed to persist scorer, check your disk and permissions {}", e)
					}
				}
				last_scorer_persist_call = $get_timer(SCORER_PERSIST_TIMER);
			}

			if $timer_elapsed(&mut last_rebroadcast_call, REBROADCAST_TIMER) {
				log_trace!($logger, "Rebroadcasting monitor's pending claims");
				$chain_monitor.rebroadcast_pending_claims();
				last_rebroadcast_call = $get_timer(REBROADCAST_TIMER);
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

pub(crate) mod futures_util {
    use core::future::Future;
    use core::marker::Unpin;
    use core::pin::Pin;
    use core::task::{Poll, RawWaker, RawWakerVTable, Waker};
    pub(crate) struct Selector<
        A: Future<Output = ()> + Unpin,
        B: Future<Output = ()> + Unpin,
        C: Future<Output = bool> + Unpin,
    > {
        pub a: A,
        pub b: B,
        pub c: C,
    }
    pub(crate) enum SelectorOutput {
        A,
        B,
        C(bool),
    }

    impl<
            A: Future<Output = ()> + Unpin,
            B: Future<Output = ()> + Unpin,
            C: Future<Output = bool> + Unpin,
        > Future for Selector<A, B, C>
    {
        type Output = SelectorOutput;
        fn poll(
            mut self: Pin<&mut Self>,
            ctx: &mut core::task::Context<'_>,
        ) -> Poll<SelectorOutput> {
            match Pin::new(&mut self.a).poll(ctx) {
                Poll::Ready(()) => {
                    return Poll::Ready(SelectorOutput::A);
                }
                Poll::Pending => {}
            }
            match Pin::new(&mut self.b).poll(ctx) {
                Poll::Ready(()) => {
                    return Poll::Ready(SelectorOutput::B);
                }
                Poll::Pending => {}
            }
            match Pin::new(&mut self.c).poll(ctx) {
                Poll::Ready(res) => {
                    return Poll::Ready(SelectorOutput::C(res));
                }
                Poll::Pending => {}
            }
            Poll::Pending
        }
    }

    // If we want to poll a future without an async context to figure out if it has completed or
    // not without awaiting, we need a Waker, which needs a vtable...we fill it with dummy values
    // but sadly there's a good bit of boilerplate here.
    fn dummy_waker_clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &DUMMY_WAKER_VTABLE)
    }
    fn dummy_waker_action(_: *const ()) {}

    const DUMMY_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        dummy_waker_clone,
        dummy_waker_action,
        dummy_waker_action,
        dummy_waker_action,
    );
    pub(crate) fn dummy_waker() -> Waker {
        unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &DUMMY_WAKER_VTABLE)) }
    }
}
use core::task;
use futures_util::{dummy_waker, Selector, SelectorOutput};

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
    EventHandlerFuture: core::future::Future<Output = ()>,
    EventHandler: Fn(Event) -> EventHandlerFuture,
    PS: 'static + Deref,
    M: 'static + Deref<Target = ChainMonitor<<SP::Target as SignerProvider>::Signer, CF, T, F, L, P>>,
    CM: 'static + Deref<Target = ChannelManager<CW, T, ES, NS, SP, F, R, L>>,
    PGS: 'static + Deref<Target = P2PGossipSync<G, UL, L>>,
    RGS: 'static + Deref<Target = RapidGossipSync<G, L>>,
    APM: APeerManager,
    PM: 'static + Deref<Target = APM>,
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
    logger: L,
    scorer: Option<S>,
    sleeper: Sleeper,
    mobile_interruptable_platform: bool,
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
    PS::Target: 'static + Persister<'a, CW, T, ES, NS, SP, F, R, L, SC>,
{
    let mut should_break = false;
    let async_event_handler = |event| {
        let network_graph = gossip_sync.network_graph();
        let event_handler = &event_handler;
        let scorer = &scorer;
        let logger = &logger;
        let persister = &persister;
        async move {
            if let Some(network_graph) = network_graph {
                handle_network_graph_update(network_graph, &event)
            }
            if let Some(ref scorer) = scorer {
                if update_scorer(scorer, &event) {
                    log_trace!(logger, "Persisting scorer after update");
                    if let Err(e) = persister.persist_scorer(&scorer) {
                        log_error!(
                            logger,
                            "Error: Failed to persist scorer, check your disk and permissions {}",
                            e
                        )
                    }
                }
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
            let fut = Selector {
                a: channel_manager.get_event_or_persistence_needed_future(),
                b: chain_monitor.get_update_future(),
                c: sleeper(if mobile_interruptable_platform {
                    Duration::from_millis(100)
                } else {
                    Duration::from_secs(FASTEST_TIMER)
                }),
            };
            match fut.await {
                SelectorOutput::A | SelectorOutput::B => {}
                SelectorOutput::C(exit) => {
                    should_break = exit;
                }
            }
        },
        |t| sleeper(Duration::from_secs(t)),
        |fut: &mut SleepFuture, _| {
            let mut waker = dummy_waker();
            let mut ctx = task::Context::from_waker(&mut waker);
            match core::pin::Pin::new(fut).poll(&mut ctx) {
                task::Poll::Ready(exit) => {
                    should_break = exit;
                    true
                }
                task::Poll::Pending => false,
            }
        },
        mobile_interruptable_platform
    )
}
