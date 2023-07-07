use crate::{error::MutinyError, logging::MutinyLogger};
use anyhow::anyhow;
use bdk_chain::collections::HashMap;
use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::{ecdsa, All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use lightning::util::logger::*;
use lightning::{log_error, log_info};
use lnurl::lnurl::LnUrl;
use lnurl::{AsyncClient as LnUrlClient, Response};
use std::str::FromStr;
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub struct AuthManager {
    hashing_key: SecretKey,
    xprivkey: ExtendedPrivKey,
    context: Secp256k1<All>,
}

impl AuthManager {
    pub fn new(xprivkey: ExtendedPrivKey) -> Result<Self, MutinyError> {
        let context = Secp256k1::new();

        let base_path = DerivationPath::from_str("m/138'/0")?;
        let key = xprivkey.derive_priv(&context, &base_path)?;
        let hashing_key = key.private_key;

        Ok(Self {
            hashing_key,
            xprivkey,
            context,
        })
    }

    pub(crate) fn get_secret_key(&self, url: Url) -> Result<SecretKey, MutinyError> {
        let path = lnurl::get_derivation_path(self.hashing_key.secret_bytes(), &url)?;
        let key = self
            .xprivkey
            .derive_priv(&self.context, &path)
            .map_err(|e| MutinyError::Other(anyhow!("Error deriving key for path {path}: {e}")))?;
        Ok(key.private_key)
    }

    pub fn sign(
        &self,
        url: Url,
        k1: &[u8; 32],
    ) -> Result<(ecdsa::Signature, PublicKey), MutinyError> {
        let sk = self.get_secret_key(url)?;
        let pubkey = sk.public_key(&self.context);

        let msg = Message::from_slice(k1).expect("32 bytes, guaranteed by type");
        let sig = self.context.sign_ecdsa(&msg, &sk);

        Ok((sig, pubkey))
    }
}

pub(crate) async fn make_lnurl_auth_connection(
    auth: AuthManager,
    lnurl_client: Arc<LnUrlClient>,
    lnurl: LnUrl,
    logger: Arc<MutinyLogger>,
) -> Result<(), MutinyError> {
    let url = Url::parse(&lnurl.url)?;
    let query_pairs: HashMap<String, String> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let k1 = query_pairs.get("k1").ok_or(MutinyError::LnUrlFailure)?;
    let k1: [u8; 32] = FromHex::from_hex(k1).map_err(|_| MutinyError::LnUrlFailure)?;
    let (sig, key) = auth.sign(url.clone(), &k1)?;

    let response = lnurl_client.lnurl_auth(lnurl, sig, key).await;
    match response {
        Ok(Response::Ok { .. }) => {
            log_info!(logger, "LNURL auth successful!");
            Ok(())
        }
        Ok(Response::Error { reason }) => {
            log_error!(logger, "LNURL auth failed: {reason}");
            Err(MutinyError::LnUrlFailure)
        }
        Err(e) => {
            log_error!(logger, "LNURL auth failed: {e}");
            Err(MutinyError::LnUrlFailure)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::test_utils::*;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};
    wasm_bindgen_test_configure!(run_in_browser);

    use super::*;

    #[test]
    async fn test_create_signature() {
        let test_name = "test_create_signature";
        log!("{}", test_name);

        let auth = create_manager();

        let k1 = [0; 32];

        let (sig, pk) = auth
            .sign(Url::parse("https://mutinywallet.com").unwrap(), &k1)
            .unwrap();

        auth.context
            .verify_ecdsa(&Message::from_slice(&k1).unwrap(), &sig, &pk)
            .unwrap();
    }
}
