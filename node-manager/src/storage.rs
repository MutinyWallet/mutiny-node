use bip39::Mnemonic;
use gloo_storage::*;
use std::str::FromStr;

pub fn insert_mnemonic(mnemonic: Mnemonic) -> Mnemonic {
    LocalStorage::set("mnemonic", mnemonic.to_string()).expect("Failed to write to storage");
    mnemonic
}

pub fn get_mnemonic() -> Result<Mnemonic> {
    let res: Result<String> = LocalStorage::get("mnemonic");
    match res {
        Ok(str) => Ok(Mnemonic::from_str(&str).expect("could not parse specified mnemonic")),
        Err(e) => Err(e),
    }
}

#[allow(dead_code)]
pub fn delete_mnemonic() {
    LocalStorage::delete("mnemonic");
}
