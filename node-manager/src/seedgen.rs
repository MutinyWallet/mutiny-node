use std::str::FromStr;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::Hash;
use bitcoin::psbt::serialize::Serialize;
use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{
    OutPoint, PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};

pub fn generate_seed() -> String {
    let secp = Secp256k1::new();
    let internal_key = UntweakedPublicKey::from_str(
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51",
    )
    .unwrap();

    let script_builder = (0..25).into_iter().fold(Builder::new(), |b, _| {
        b.push_slice(&vec![1; 520])
            .push_opcode(opcodes::all::OP_DROP)
    });
    let script = script_builder.push_opcode(opcodes::OP_TRUE).into_script();

    let tr = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
    let spend_info = tr
        .finalize(&secp, internal_key)
        .expect("Could not create taproot spend info");
    // create control block
    let control_block = spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("Could not create control block");
    // witness is spending script followed by control block
    let witness = vec![script.serialize(), control_block.serialize()];

    let txin = TxIn {
        previous_output: OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        },
        script_sig: Script::new(),
        sequence: Sequence::default(),
        witness: Witness::from_vec(witness),
    };

    let created_tx = Transaction {
        version: 2,
        lock_time: PackedLockTime::ZERO,
        input: vec![txin],
        output: vec![TxOut {
            value: 10_000,
            script_pubkey: Script::new_p2pkh(&bitcoin::PubkeyHash::all_zeros()),
        }],
    };

    created_tx.serialize().to_hex()
}
