use bitcoin::Network;
use lightning_invoice::ParseOrSemanticError;
use mutiny_core::error::{MutinyError, MutinyStorageError};
use thiserror::Error;
use wasm_bindgen::JsValue;

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
    IncorrectNetwork(Network),
    /// Payment of the given invoice has already been initiated.
    #[error("An invoice must not get payed twice.")]
    NonUniquePaymentHash,
    /// Payment Timed out
    #[error("Payment timed out.")]
    PaymentTimeout,
    /// The given invoice is invalid.
    #[error("The given invoice is invalid.")]
    InvoiceInvalid,
    /// Invoice creation failed.
    #[error("Failed to create invoice.")]
    InvoiceCreationFailed,
    /// Failed to call on the given LNURL
    #[error("Failed to call on the given LNURL.")]
    LnUrlFailure,
    #[error("Failed to connect to LSP.")]
    LspFailure,
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
            MutinyError::IncorrectNetwork(net) => MutinyJsError::IncorrectNetwork(net),
            MutinyError::NonUniquePaymentHash => MutinyJsError::NonUniquePaymentHash,
            MutinyError::PaymentTimeout => MutinyJsError::PaymentTimeout,
            MutinyError::InvoiceInvalid => MutinyJsError::InvoiceInvalid,
            MutinyError::InvoiceCreationFailed => MutinyJsError::InvoiceCreationFailed,
            MutinyError::LnUrlFailure => MutinyJsError::LnUrlFailure,
            MutinyError::LspFailure => MutinyJsError::LspFailure,
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
            MutinyError::PubkeyInvalid => MutinyJsError::PubkeyInvalid,
            MutinyError::IncorrectLnUrlFunction => MutinyJsError::IncorrectLnUrlFunction,
            MutinyError::BadAmountError => MutinyJsError::BadAmountError,
            MutinyError::BitcoinPriceError => MutinyJsError::BitcoinPriceError,
            MutinyError::Other(_) => MutinyJsError::UnknownError,
        }
    }
}

impl From<MutinyStorageError> for MutinyJsError {
    fn from(e: MutinyStorageError) -> Self {
        MutinyError::from(e).into()
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

impl From<lnurl::Error> for MutinyJsError {
    fn from(e: lnurl::Error) -> Self {
        MutinyError::from(e).into()
    }
}

impl From<ParseOrSemanticError> for MutinyJsError {
    fn from(_e: ParseOrSemanticError) -> Self {
        Self::InvoiceInvalid
    }
}

impl From<bitcoin::hashes::hex::Error> for MutinyJsError {
    fn from(_e: bitcoin::hashes::hex::Error) -> Self {
        Self::JsonReadWriteError
    }
}

impl From<bitcoin::secp256k1::Error> for MutinyJsError {
    fn from(_e: bitcoin::secp256k1::Error) -> Self {
        Self::PubkeyInvalid
    }
}

impl From<MutinyJsError> for JsValue {
    fn from(e: MutinyJsError) -> Self {
        JsValue::from(e.to_string())
    }
}
