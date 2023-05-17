use lightning_invoice::Invoice;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nip47Request {
    pub method: String,
    pub params: Nip47Params,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Nip47Params {
    pub invoice: Invoice,
}
