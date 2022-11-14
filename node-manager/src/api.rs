use bitcoin::hashes::sha256::Hash;
use bitcoin::OutPoint;
use lightning_invoice::Invoice;
use lightning_invoice::InvoiceDescription;

pub struct MutinyInvoice {
    pub bolt11: String,
    pub description: Option<String>,
    pub payment_hash: Hash,
    pub preimage: Option<[u8; 32]>,
    pub amount_sats: Option<u64>,
    pub expire: Option<u64>,
    pub paid: bool,
    pub fees_paid: u64,
    pub is_send: bool,
}

impl From<Invoice> for MutinyInvoice {
    fn from(value: Invoice) -> Self {
        let description = match value.description() {
            InvoiceDescription::Direct(a) => Some(a.to_string()),
            InvoiceDescription::Hash(_) => None,
        };

        MutinyInvoice {
            bolt11: value.to_string(),
            description,
            payment_hash: value.payment_hash().to_owned(),
            preimage: None,
            amount_sats: value.amount_milli_satoshis().map(|m| m / 1000),
            expire: None, // todo
            paid: false,
            fees_paid: 0,
            is_send: false, // todo this could be bad
        }
    }
}

pub struct MutinyChannel {
    pub balance: u64,
    pub size: u64,
    pub outpoint: OutPoint,
    pub peer: String,
    pub confirmed: bool,
}

pub struct MutinyBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub lightning: u64,
}
