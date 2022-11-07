use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;

use crate::tcpproxy::{SocketDescriptor, TcpProxy};
use crate::{
    error::MutinyError,
    keymanager::{create_keys_manager, pubkey_from_keys_manager},
    logging::MutinyLogger,
    nodemanager::NodeIndex,
};
use anyhow::Context;
use bip39::Mnemonic;
use bitcoin::secp256k1::PublicKey;
use lightning::chain::keysinterface::KeysManager;
use lightning::ln::peer_handler::{
    ErroringMessageHandler, IgnoringMessageHandler, PeerManager as LdkPeerManager,
};
use lightning::routing::gossip;
use log::info;

pub(crate) type NetworkGraph = gossip::NetworkGraph<Arc<MutinyLogger>>;

pub(crate) type PeerManager = LdkPeerManager<
    SocketDescriptor,
    Arc<ErroringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<IgnoringMessageHandler>,
    Arc<MutinyLogger>,
    Arc<IgnoringMessageHandler>,
>;

pub struct Node {
    pub uuid: String,
    pub pubkey: PublicKey,
    pub keys_manager: Arc<KeysManager>,
}

impl Node {
    pub(crate) fn new(node_index: NodeIndex, mnemonic: Mnemonic) -> Result<Self, MutinyError> {
        info!("initialized a new node: {}", node_index.uuid);

        let keys_manager = create_keys_manager(mnemonic, node_index.child_index);
        let pubkey = pubkey_from_keys_manager(&keys_manager);

        Ok(Node {
            uuid: node_index.uuid,
            pubkey,
            keys_manager: Arc::new(keys_manager),
        })
    }

    pub async fn connect_peer(
        &self,
        websocket_proxy_addr: String,
        peer_pubkey_and_ip_addr: String,
    ) -> Result<(), MutinyError> {
        if peer_pubkey_and_ip_addr.is_empty() {
            return Err(MutinyError::PeerInfoParseFailed)
                .context("connect_peer requires peer connection info")?;
        };
        let (pubkey, peer_addr) = match parse_peer_info(peer_pubkey_and_ip_addr) {
            Ok(info) => info,
            Err(e) => {
                return Err(MutinyError::PeerInfoParseFailed)
                    .with_context(|| format!("could not parse peer info: {}", e))?;
            }
        };

        if connect_peer_if_necessary(websocket_proxy_addr, pubkey, peer_addr)
            .await
            .is_err()
        {
            Err(MutinyError::PeerInfoParseFailed)
                .with_context(|| format!("could not connect to peer: {pubkey}"))?
        }

        Ok(())
    }
}

pub(crate) async fn connect_peer_if_necessary(
    websocket_proxy_addr: String,
    _pubkey: PublicKey,
    peer_addr: SocketAddr,
    // peer_manager: Arc<PeerManager>,
) -> Result<(), ()> {
    // TODO add this when the peer manager is ready
    /*
    for node_pubkey in peer_manager.get_peer_node_ids() {
        if node_pubkey == pubkey {
            return Ok(());
        }
    }
    */

    // first make a connection to the node
    let tcp_proxy = TcpProxy::new(websocket_proxy_addr, peer_addr).await;

    // TODO remove the test send
    tcp_proxy.send(String::from("test\n").into_bytes().to_vec());

    // TODO then give that connection to the peer manager

    // TODO then schedule a reader on the connection

    Ok(())
}

pub(crate) fn parse_peer_info(
    peer_pubkey_and_ip_addr: String,
) -> Result<(PublicKey, SocketAddr), MutinyError> {
    let mut pubkey_and_addr = peer_pubkey_and_ip_addr.split('@');
    let pubkey = pubkey_and_addr.next();
    let peer_addr_str = pubkey_and_addr.next();
    if peer_addr_str.is_none() {
        return Err(MutinyError::PeerInfoParseFailed).context(
            "incorrectly formatted peer info. Should be formatted as: `pubkey@host:port`",
        )?;
    }

    let peer_addr = peer_addr_str
        .unwrap()
        .to_socket_addrs()
        .map(|mut r| r.next());
    if peer_addr.is_err() || peer_addr.as_ref().unwrap().is_none() {
        return Err(MutinyError::PeerInfoParseFailed)
            .context("couldn't parse pubkey@host:port into a socket address")?;
    }

    let pubkey = PublicKey::from_str(pubkey.unwrap());
    if pubkey.is_err() {
        return Err(MutinyError::PeerInfoParseFailed)
            .context("unable to parse given pubkey for node")?;
    }

    Ok((pubkey.unwrap(), peer_addr.unwrap().unwrap()))
}

#[cfg(test)]
mod tests {
    use crate::test::*;
    use std::{net::SocketAddr, str::FromStr};

    use crate::node::parse_peer_info;

    use secp256k1::PublicKey;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    async fn test_parse_peer_info() {
        log!("test parse peer info");

        let pub_key = PublicKey::from_str(
            "0218845781f631c48f1c9709e23092067d06837f30aa0cd0544ac887fe91ddd166",
        )
        .unwrap();
        let addr = "127.0.0.1:4000";

        let (peer_pubkey, peer_addr) =
            parse_peer_info(format!("{}@{addr}", pub_key.to_string()).to_string()).unwrap();

        assert_eq!(pub_key, peer_pubkey);
        assert_eq!(addr.parse::<SocketAddr>().unwrap(), peer_addr);
    }
}
