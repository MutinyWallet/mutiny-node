use bdk::esplora_client;
use lightning::ln::peer_handler::PeerHandleError;
use lightning_invoice::payment::PaymentError;
use lightning_invoice::ParseOrSemanticError;
use thiserror::Error;
use wasm_bindgen::JsValue;

#[derive(Error, Debug)]
#[allow(dead_code)]
// copied from LDK lite
/// An error that possibly needs to be handled by the user.
pub enum MutinyError {
    /// Returned when trying to start Mutiny while it is already running.
    #[error("Mutiny is already running.")]
    AlreadyRunning,
    /// Returned when trying to stop Mutiny while it is not running.
    #[error("Mutiny is not running.")]
    NotRunning,
    /// The funding transaction could not be created.
    #[error("Funding transaction could not be created.")]
    FundingTxCreationFailed,
    /// A network connection has been closed.
    #[error("Network connection closed.")]
    ConnectionFailed,
    /// Payment of the given invoice has already been initiated.
    #[error("An invoice must not get payed twice.")]
    NonUniquePaymentHash,
    /// The given invoice is invalid.
    #[error("The given invoice is invalid.")]
    InvoiceInvalid,
    /// Invoice creation failed.
    #[error("Failed to create invoice.")]
    InvoiceCreationFailed,
    /// No route for the given target could be found.
    #[error("Failed to find route.")]
    RoutingFailed,
    /// A given peer info could not be parsed.
    #[error("Failed to parse the given peer information.")]
    PeerInfoParseFailed,
    /// A channel could not be opened.
    #[error("Failed to create channel.")]
    ChannelCreationFailed,
    /// A channel could not be closed.
    #[error("Failed to close channel.")]
    ChannelClosingFailed,
    /// Persistence failed.
    #[error("Failed to persist data.")]
    PersistenceFailed {
        #[from]
        source: MutinyStorageError,
    },
    #[error("Failed to read data from storage.")]
    ReadError { source: MutinyStorageError },
    /// A failure to generate a mnemonic seed.
    #[error("Failed to generate seed")]
    SeedGenerationFailed,
    /// User provided invalid menmonic.
    #[error("Invalid mnemonic")]
    InvalidMnemonic,
    /// A wallet operation failed.
    #[error("Failed to conduct wallet operation.")]
    WalletOperationFailed,
    /// A signing operation failed.
    #[error("Failed to sign given transaction.")]
    WalletSigningFailed,
    /// A chain access operation failed.
    #[error("Failed to conduct chain access operation.")]
    ChainAccessFailed,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum MutinyStorageError {
    #[error("Failed to use browser storage")]
    StorageError {
        #[from]
        source: gloo_storage::errors::StorageError,
    },
    #[error("Failed to serialize or deserialize")]
    SerdeError {
        #[from]
        source: serde_json::Error,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl MutinyError {
    pub fn read_err(e: MutinyStorageError) -> Self {
        MutinyError::ReadError { source: e }
    }
}

impl From<bdk::Error> for MutinyError {
    fn from(e: bdk::Error) -> Self {
        match e {
            bdk::Error::Signer(_) => Self::WalletSigningFailed,
            _ => Self::WalletOperationFailed,
        }
    }
}

// TODO add more granular errors for esplora failures
impl From<esplora_client::Error> for MutinyError {
    fn from(_e: esplora_client::Error) -> Self {
        // This is most likely a chain access failure
        Self::ChainAccessFailed
    }
}

impl From<ParseOrSemanticError> for MutinyError {
    fn from(_e: ParseOrSemanticError) -> Self {
        Self::InvoiceInvalid
    }
}

impl From<PeerHandleError> for MutinyError {
    fn from(_e: PeerHandleError) -> Self {
        // TODO handle the case where `no_connection_possible`
        Self::ConnectionFailed
    }
}

impl From<PaymentError> for MutinyError {
    fn from(e: PaymentError) -> Self {
        match e {
            PaymentError::Invoice(_) => Self::InvoiceInvalid,
            PaymentError::Routing(_) => Self::RoutingFailed,
            PaymentError::Sending(_) => Self::RoutingFailed,
        }
    }
}

impl From<MutinyStorageError> for bdk::Error {
    fn from(e: MutinyStorageError) -> Self {
        match e {
            MutinyStorageError::StorageError { source } => {
                bdk::Error::Generic(format!("Storage error: {source}"))
            }
            MutinyStorageError::SerdeError { source } => {
                bdk::Error::Generic(format!("Serde error: {source}"))
            }
            _ => bdk::Error::Generic("Unexpected Mutiny storage Error".to_string()),
        }
    }
}

impl From<std::io::Error> for MutinyError {
    fn from(e: std::io::Error) -> Self {
        MutinyError::PersistenceFailed {
            source: MutinyStorageError::Other(e.into()),
        }
    }
}

#[derive(Error, Debug)]
pub enum MutinyJsError {
    /// Returned when trying to start Mutiny while it is already running.
    #[error("Mutiny is already running.")]
    AlreadyRunning,
    /// Returned when trying to stop Mutiny while it is not running.
    #[error("Mutiny is not running.")]
    NotRunning,
    /// The funding transaction could not be created.
    #[error("Funding transaction could not be created.")]
    FundingTxCreationFailed,
    /// A network connection has been closed.
    #[error("Network connection closed.")]
    ConnectionFailed,
    /// Payment of the given invoice has already been initiated.
    #[error("An invoice must not get payed twice.")]
    NonUniquePaymentHash,
    /// The given invoice is invalid.
    #[error("The given invoice is invalid.")]
    InvoiceInvalid,
    /// Invoice creation failed.
    #[error("Failed to create invoice.")]
    InvoiceCreationFailed,
    /// No route for the given target could be found.
    #[error("Failed to find route.")]
    RoutingFailed,
    /// A given peer info could not be parsed.
    #[error("Failed to parse the given peer information.")]
    PeerInfoParseFailed,
    /// A channel could not be opened.
    #[error("Failed to create channel.")]
    ChannelCreationFailed,
    /// A channel could not be closed.
    #[error("Failed to close channel.")]
    ChannelClosingFailed,
    /// Persistence failed.
    #[error("Failed to persist data.")]
    PersistenceFailed,
    #[error("Failed to read data from storage.")]
    ReadError,
    /// A failure to generate a mnemonic seed.
    #[error("Failed to generate seed")]
    SeedGenerationFailed,
    /// User provided invalid menmonic.
    #[error("Invalid mnemonic")]
    InvalidMnemonic,
    /// A wallet operation failed.
    #[error("Failed to conduct wallet operation.")]
    WalletOperationFailed,
    /// A signing operation failed.
    #[error("Failed to sign given transaction.")]
    WalletSigningFailed,
    /// A chain access operation failed.
    #[error("Failed to conduct chain access operation.")]
    ChainAccessFailed,
    /// An error when reading/writing json to the front end.
    #[error("Failed to read or write json from the front end")]
    JsonReadWriteError,
    /// Node pubkey given is invalid
    #[error("The given node pubkey is invalid.")]
    PubkeyInvalid,
    /// Error getting the bitcoin price
    #[error("Failed to get the bitcoin price.")]
    BitcoinPriceError,
    /// Unknown error.
    #[error("Unknown Error")]
    UnknownError,
}

impl From<MutinyError> for MutinyJsError {
    fn from(e: MutinyError) -> Self {
        match e {
            MutinyError::AlreadyRunning => MutinyJsError::AlreadyRunning,
            MutinyError::NotRunning => MutinyJsError::NotRunning,
            MutinyError::FundingTxCreationFailed => MutinyJsError::FundingTxCreationFailed,
            MutinyError::ConnectionFailed => MutinyJsError::ConnectionFailed,
            MutinyError::NonUniquePaymentHash => MutinyJsError::NonUniquePaymentHash,
            MutinyError::InvoiceInvalid => MutinyJsError::InvoiceInvalid,
            MutinyError::InvoiceCreationFailed => MutinyJsError::InvoiceCreationFailed,
            MutinyError::RoutingFailed => MutinyJsError::RoutingFailed,
            MutinyError::PeerInfoParseFailed => MutinyJsError::PeerInfoParseFailed,
            MutinyError::ChannelCreationFailed => MutinyJsError::ChannelCreationFailed,
            MutinyError::ChannelClosingFailed => MutinyJsError::ChannelClosingFailed,
            MutinyError::PersistenceFailed { source: _ } => MutinyJsError::PersistenceFailed,
            MutinyError::ReadError { source: _ } => MutinyJsError::ReadError,
            MutinyError::SeedGenerationFailed => MutinyJsError::SeedGenerationFailed,
            MutinyError::WalletOperationFailed => MutinyJsError::WalletOperationFailed,
            MutinyError::InvalidMnemonic => MutinyJsError::InvalidMnemonic,
            MutinyError::WalletSigningFailed => MutinyJsError::WalletSigningFailed,
            MutinyError::ChainAccessFailed => MutinyJsError::ChainAccessFailed,
            MutinyError::Other(_) => MutinyJsError::UnknownError,
        }
    }
}

impl From<serde_wasm_bindgen::Error> for MutinyJsError {
    fn from(_: serde_wasm_bindgen::Error) -> Self {
        Self::JsonReadWriteError
    }
}

impl From<bitcoin::util::address::Error> for MutinyJsError {
    fn from(_: bitcoin::util::address::Error) -> Self {
        Self::JsonReadWriteError
    }
}

impl From<PaymentError> for MutinyJsError {
    fn from(e: PaymentError) -> Self {
        match e {
            PaymentError::Invoice(_) => Self::InvoiceInvalid,
            PaymentError::Routing(_) => Self::RoutingFailed,
            PaymentError::Sending(_) => Self::RoutingFailed,
        }
    }
}

impl From<esplora_client::Error> for MutinyJsError {
    fn from(_e: esplora_client::Error) -> Self {
        // This is most likely a chain access failure
        Self::ChainAccessFailed
    }
}

impl From<ParseOrSemanticError> for MutinyJsError {
    fn from(_e: ParseOrSemanticError) -> Self {
        Self::InvoiceInvalid
    }
}

impl From<reqwest::Error> for MutinyJsError {
    fn from(_e: reqwest::Error) -> Self {
        Self::BitcoinPriceError
    }
}

impl From<bitcoin_hashes::hex::Error> for MutinyJsError {
    fn from(_e: bitcoin_hashes::hex::Error) -> Self {
        Self::JsonReadWriteError
    }
}

impl From<MutinyJsError> for JsValue {
    fn from(e: MutinyJsError) -> Self {
        JsValue::from(e.to_string())
    }
}
