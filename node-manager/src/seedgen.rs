use std::str::FromStr;

use bip39::Mnemonic;

pub fn generate_seed() -> String {
    let mut entropy = [0u8; 16];
    getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
    let seed = Mnemonic::from_entropy(&entropy).expect("Could not generate seed");
    seed.to_string()
}
