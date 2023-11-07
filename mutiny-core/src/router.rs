use crate::logging::MutinyLogger;
use crate::node::NetworkGraph;
use crate::scorer::HubPreferentialScorer;
use crate::utils::Mutex;
use bitcoin::secp256k1::PublicKey;
use lightning::ln::channelmanager::ChannelDetails;
use lightning::ln::features::ChannelFeatures;
use lightning::ln::msgs::LightningError;
use lightning::routing::gossip::NodeId;
use lightning::routing::router::{
    BlindedTail, DefaultRouter, InFlightHtlcs, Path, Payee, Route, RouteHop, RouteParameters,
    Router,
};
use lightning::routing::scoring::ProbabilisticScoringFeeParameters;
use lightning::util::ser::Writeable;
use log::warn;
use std::sync::Arc;

type LdkRouter = DefaultRouter<
    Arc<NetworkGraph>,
    Arc<MutinyLogger>,
    Arc<Mutex<HubPreferentialScorer>>,
    ProbabilisticScoringFeeParameters,
    HubPreferentialScorer,
>;

pub struct MutinyRouter {
    network_graph: Arc<NetworkGraph>,
    lsp_key: Option<PublicKey>,
    router: LdkRouter,
}

impl MutinyRouter {
    pub fn new(
        network_graph: Arc<NetworkGraph>,
        lsp_key: Option<PublicKey>,
        logger: Arc<MutinyLogger>,
        random_seed_bytes: [u8; 32],
        scorer: Arc<Mutex<HubPreferentialScorer>>,
        score_params: ProbabilisticScoringFeeParameters,
    ) -> Self {
        let router = DefaultRouter::new(
            network_graph.clone(),
            logger,
            random_seed_bytes,
            scorer,
            score_params,
        );

        Self {
            network_graph,
            lsp_key,
            router,
        }
    }
}

impl Router for MutinyRouter {
    fn find_route(
        &self,
        payer: &PublicKey,
        route_params: &RouteParameters,
        first_hops: Option<&[&ChannelDetails]>,
        inflight_htlcs: InFlightHtlcs,
    ) -> Result<Route, LightningError> {
        match &route_params.payment_params.payee {
            Payee::Clear { .. } => {
                self.router
                    .find_route(payer, route_params, first_hops, inflight_htlcs)
            }
            Payee::Blinded {
                route_hints,
                features: _,
            } => {
                // if we have no LSP, then handle normally
                if self.lsp_key.is_none() {
                    return self
                        .router
                        .find_route(payer, route_params, first_hops, inflight_htlcs);
                }

                let (blinded_info, blinded_path) = route_hints.first().unwrap();
                let graph_lock = self.network_graph.read_only();
                let lsp_node_id = NodeId::from_pubkey(&self.lsp_key.unwrap());
                let node_info = graph_lock.node(&lsp_node_id).unwrap();

                let amt = route_params.final_value_msat;

                // first our channel with enough capacity
                let first_hops = first_hops.unwrap_or(&[]);
                let first = first_hops
                    .iter()
                    .find(|c| c.outbound_capacity_msat >= amt)
                    .unwrap();

                let channel_features =
                    ChannelFeatures::from_be_bytes(first.counterparty.features.encode());

                let scid = scid_from_parts(467591, 1, 0);
                warn!("scid: {}", scid);

                let cltv_expiry_delta = first.config.unwrap().cltv_expiry_delta;
                let hops = vec![
                    RouteHop {
                        pubkey: self.lsp_key.unwrap(),
                        node_features: node_info
                            .announcement_info
                            .as_ref()
                            .unwrap()
                            .features
                            .clone(),
                        short_channel_id: first.get_outbound_payment_scid().unwrap(),
                        channel_features: channel_features.clone(),
                        fee_msat: 0,          // 0 for own channel
                        cltv_expiry_delta: 0, // 0 for own channel
                        maybe_announced_channel: false,
                    },
                    RouteHop {
                        pubkey: blinded_path.introduction_node_id,
                        node_features: node_info
                            .announcement_info
                            .as_ref()
                            .unwrap()
                            .features
                            .clone(),
                        short_channel_id: 17112782831943311000, // fixme
                        channel_features,
                        fee_msat: 10_000, // put high value just to try
                        cltv_expiry_delta: cltv_expiry_delta as u32,
                        maybe_announced_channel: false,
                    },
                ];

                let blinded_tail = Some(BlindedTail {
                    hops: blinded_path.blinded_hops.clone(),
                    blinding_point: blinded_path.blinding_point,
                    excess_final_cltv_expiry_delta: blinded_info.cltv_expiry_delta as u32,
                    final_value_msat: amt,
                });

                let path = Path { hops, blinded_tail };

                Ok(Route {
                    paths: vec![path],
                    route_params: Some(route_params.clone()),
                })
            }
        }
    }
}

/// Constructs a `short_channel_id` using the components pieces. Results in an error
/// if the block height, tx index, or vout index overflow the maximum sizes.
pub fn scid_from_parts(block: u64, tx_index: u64, vout_index: u64) -> u64 {
    (block << 40) | (tx_index << 16) | vout_index
}
