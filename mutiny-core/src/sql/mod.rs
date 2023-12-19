use crate::{error::MutinyError, nodemanager::MutinyInvoice, HTLCStatus};

pub mod glue;

pub(crate) trait ApplicationStore {
    async fn save_payment(&self, i: MutinyInvoice) -> Result<(), MutinyError>;
    async fn get_payment(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
    ) -> Result<Option<MutinyInvoice>, MutinyError>;
    async fn update_payment_status(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
        status: HTLCStatus,
    ) -> Result<(), MutinyError>;
    async fn update_payment_fee(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
        fee: Option<u64>,
    ) -> Result<(), MutinyError>;
    async fn update_payment_preimage(
        &self,
        payment_hash: &bitcoin::hashes::sha256::Hash,
        preimage: Option<String>,
    ) -> Result<(), MutinyError>;
    async fn list_payments(&self) -> Result<Vec<MutinyInvoice>, MutinyError>;
}
