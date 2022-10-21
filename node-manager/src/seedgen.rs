use bip39::Mnemonic;

pub fn generate_seed() -> Mnemonic {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).expect("Failed to generate entropy");
    Mnemonic::from_entropy(&entropy).expect("Could not generate seed")
}
