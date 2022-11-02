use bip32::XPrv;
use bip39::Mnemonic;
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use lightning::chain::keysinterface::{KeysInterface, KeysManager, Recipient};

pub(crate) fn generate_seed() -> Mnemonic {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
    Mnemonic::from_entropy(&entropy).expect("Could not generate seed")
}

// A node private key will be derived from `m/0'/X'`, where it's node pubkey will
// be derived from the LDK default being `m/0'/X'/0'`.
pub(crate) fn create_keys_manager(mnemonic: Mnemonic, child_index: u32) -> KeysManager {
    let xpriv = XPrv::new(mnemonic.to_seed(""))
        .unwrap()
        .derive_child(bip32::ChildNumber::new(0, true).unwrap())
        .unwrap()
        .derive_child(bip32::ChildNumber::new(child_index, true).unwrap())
        .unwrap();
    let current_time = instant::now();
    KeysManager::new(
        &xpriv.to_bytes(),
        (current_time / 1000.0).round() as u64,
        (current_time * 1000.0).round() as u32,
    )
}

pub(crate) fn pubkey_from_keys_manager(keys_manager: &KeysManager) -> PublicKey {
    let mut secp_ctx = Secp256k1::new();
    secp_ctx.seeded_randomize(&keys_manager.get_secure_random_bytes());

    let our_network_key = keys_manager
        .get_node_secret(Recipient::Node)
        .expect("cannot parse node secret");

    PublicKey::from_secret_key(&secp_ctx, &our_network_key)
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};

    wasm_bindgen_test_configure!(run_in_browser);

    use crate::{keymanager::pubkey_from_keys_manager, test::*};

    use super::create_keys_manager;
    use bip39::Mnemonic;
    use std::str::FromStr;

    #[test]
    fn derive_pubkey_child_from_seed() {
        log!("creating pubkeys from a child seed");

        let mnemonic = Mnemonic::from_str("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").expect("could not generate");

        let km = create_keys_manager(mnemonic.clone(), 1);
        let pubkey = pubkey_from_keys_manager(&km);
        assert_eq!(
            "02cae09cf2c8842ace44068a5bf3117a494ebbf69a99e79712483c36f97cdb7b54",
            pubkey.to_string()
        );

        let km = create_keys_manager(mnemonic.clone(), 2);
        let second_pubkey = pubkey_from_keys_manager(&km);
        assert_eq!(
            "03fcc9eaaf0b84946ea7935e3bc4f2b498893c2f53e5d2994d6877d149601ce553",
            second_pubkey.to_string()
        );

        let km = create_keys_manager(mnemonic.clone(), 2);
        let second_pubkey_again = pubkey_from_keys_manager(&km);

        assert_eq!(second_pubkey, second_pubkey_again);
    }
}
