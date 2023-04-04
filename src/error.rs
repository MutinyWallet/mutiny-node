use crate::esplora::TxSyncError;
use bdk::esplora_client;
use lightning::ln::peer_handler::PeerHandleError;
use lightning_invoice::payment::PaymentError;
use lightning_invoice::ParseOrSemanticError;
use lightning_rapid_gossip_sync::GraphSyncError;
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
    /// The invoice or address is on a different network
    #[error("The invoice or address is on a different network.")]
    IncorrectNetwork,
    /// Payment of the given invoice has already been initiated.
    #[error("An invoice must not get payed twice.")]
    NonUniquePaymentHash,
    /// The given invoice is invalid.
    #[error("The given invoice is invalid.")]
    InvoiceInvalid,
    /// Invoice creation failed.
    #[error("Failed to create invoice.")]
    InvoiceCreationFailed,
    /// Failed to call on the given LNURL
    #[error("Failed to call on the given LNURL.")]
    LnUrlFailure,
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
    #[error("Failed to decode lightning data.")]
    LnDecodeError,
    /// A failure to generate a mnemonic seed.
    #[error("Failed to generate seed")]
    SeedGenerationFailed,
    /// User provided invalid mnemonic.
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
    /// An error with rapid gossip sync
    #[error("Failed to execute a rapid gossip sync function")]
    RapidGossipSyncError,
    /// A error with DLCs
    #[error("Failed to execute a dlc function")]
    DLCManagerError,
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
    #[error("Failed to use indexeddb storage")]
    IndexedDBError,
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

// impl From<lnurl::Error> for MutinyError {
//     fn from(_e: lnurl::Error) -> Self {
//         Self::LnUrlFailure
//     }
// }

impl From<TxSyncError> for MutinyError {
    fn from(_e: TxSyncError) -> Self {
        MutinyError::ChainAccessFailed
    }
}

impl From<lightning::ln::msgs::DecodeError> for MutinyError {
    fn from(_e: lightning::ln::msgs::DecodeError) -> Self {
        MutinyError::LnDecodeError
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

impl From<GraphSyncError> for MutinyError {
    fn from(_e: GraphSyncError) -> Self {
        MutinyError::RapidGossipSyncError
    }
}

impl From<std::io::Error> for MutinyError {
    fn from(e: std::io::Error) -> Self {
        MutinyError::PersistenceFailed {
            source: MutinyStorageError::Other(e.into()),
        }
    }
}

impl From<serde_wasm_bindgen::Error> for MutinyError {
    fn from(_: serde_wasm_bindgen::Error) -> Self {
        Self::ReadError {
            source: MutinyStorageError::Other(anyhow::anyhow!("Failed to deserialize")),
        }
    }
}

impl From<rexie::Error> for MutinyError {
    fn from(_e: rexie::Error) -> Self {
        MutinyError::PersistenceFailed {
            source: MutinyStorageError::IndexedDBError,
        }
    }
}

impl From<bitcoin_hashes::hex::Error> for MutinyError {
    fn from(_e: bitcoin_hashes::hex::Error) -> Self {
        MutinyError::ReadError {
            source: MutinyStorageError::Other(anyhow::anyhow!("Failed to decode hex")),
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
    /// The invoice or address is on a different network
    #[error("The invoice or address is on a different network.")]
    IncorrectNetwork,
    /// Payment of the given invoice has already been initiated.
    #[error("An invoice must not get payed twice.")]
    NonUniquePaymentHash,
    /// The given invoice is invalid.
    #[error("The given invoice is invalid.")]
    InvoiceInvalid,
    /// Invoice creation failed.
    #[error("Failed to create invoice.")]
    InvoiceCreationFailed,
    /// Failed to call on the given LNURL
    #[error("Failed to call on the given LNURL.")]
    LnUrlFailure,
    /// Called incorrect lnurl function, eg calling withdraw on a pay lnurl
    #[error("Called incorrect lnurl function.")]
    IncorrectLnUrlFunction,
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
    #[error("Failed to decode lightning data.")]
    LnDecodeError,
    /// A failure to generate a mnemonic seed.
    #[error("Failed to generate seed")]
    SeedGenerationFailed,
    /// User provided invalid mnemonic.
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
    /// An error with rapid gossip sync
    #[error("Failed to execute a rapid gossip sync function")]
    RapidGossipSyncError,
    /// An error when reading/writing json to the front end.
    #[error("Failed to read or write json from the front end")]
    JsonReadWriteError,
    /// Node pubkey given is invalid
    #[error("The given node pubkey is invalid.")]
    PubkeyInvalid,
    /// Error getting the bitcoin price
    #[error("Failed to get the bitcoin price.")]
    BitcoinPriceError,
    /// Error converting JS f64 value to Amount
    #[error("Failed to convert to satoshis")]
    BadAmountError,
    /// A error with DLCs
    #[error("Failed to execute a dlc function")]
    DLCManagerError,
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
            MutinyError::IncorrectNetwork => MutinyJsError::IncorrectNetwork,
            MutinyError::NonUniquePaymentHash => MutinyJsError::NonUniquePaymentHash,
            MutinyError::InvoiceInvalid => MutinyJsError::InvoiceInvalid,
            MutinyError::InvoiceCreationFailed => MutinyJsError::InvoiceCreationFailed,
            MutinyError::LnUrlFailure => MutinyJsError::LnUrlFailure,
            MutinyError::RoutingFailed => MutinyJsError::RoutingFailed,
            MutinyError::PeerInfoParseFailed => MutinyJsError::PeerInfoParseFailed,
            MutinyError::ChannelCreationFailed => MutinyJsError::ChannelCreationFailed,
            MutinyError::ChannelClosingFailed => MutinyJsError::ChannelClosingFailed,
            MutinyError::PersistenceFailed { source: _ } => MutinyJsError::PersistenceFailed,
            MutinyError::ReadError { source: _ } => MutinyJsError::ReadError,
            MutinyError::LnDecodeError => MutinyJsError::LnDecodeError,
            MutinyError::SeedGenerationFailed => MutinyJsError::SeedGenerationFailed,
            MutinyError::WalletOperationFailed => MutinyJsError::WalletOperationFailed,
            MutinyError::InvalidMnemonic => MutinyJsError::InvalidMnemonic,
            MutinyError::WalletSigningFailed => MutinyJsError::WalletSigningFailed,
            MutinyError::ChainAccessFailed => MutinyJsError::ChainAccessFailed,
            MutinyError::RapidGossipSyncError => MutinyJsError::RapidGossipSyncError,
            MutinyError::DLCManagerError => MutinyJsError::DLCManagerError,
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
        MutinyError::from(e).into()
    }
}

// impl From<lnurl::Error> for MutinyJsError {
//     fn from(e: lnurl::Error) -> Self {
//         MutinyError::from(e).into()
//     }
// }

impl From<esplora_client::Error> for MutinyJsError {
    fn from(_e: esplora_client::Error) -> Self {
        // This is most likely a chain access failure
        Self::ChainAccessFailed
    }
}

impl From<GraphSyncError> for MutinyJsError {
    fn from(e: GraphSyncError) -> Self {
        MutinyError::from(e).into()
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
