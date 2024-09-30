use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct CheckSubscribedResponse {
    pub expired_date: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct UserInvoiceResponse {
    inv: String,
}

#[derive(Serialize, Deserialize)]
pub struct WalletConnectRequest {
    wallet_connect_string: String,
}
