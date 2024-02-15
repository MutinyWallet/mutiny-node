use lightning_invoice::ParseOrSemanticError;
use log::error;
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
    /// Returned when Mutiny tries to startup with a different network than the one it was
    /// previously running on.
    #[error("Incorrect expected network.")]
    NetworkMismatch,
    /// Returned on any resource that is not found.
    #[error("Resource Not found.")]
    NotFound,
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
    /// Payment Timed out
    #[error("Payment timed out.")]
    PaymentTimeout,
    /// The given invoice is invalid.
    #[error("The given invoice is invalid.")]
    InvoiceInvalid,
    /// The given invoice is expired.
    #[error("The given invoice is expired.")]
    InvoiceExpired,
    /// Invoice creation failed.
    #[error("Failed to create invoice.")]
    InvoiceCreationFailed,
    /// We have enough balance to pay an invoice, but
    /// the this would take from our reserve amount which is not allowed.
    #[error("Channel reserve amount is too high.")]
    ReserveAmountError,
    /// We do not have enough balance to pay the given amount.
    #[error("We do not have enough balance to pay the given amount.")]
    InsufficientBalance,
    /// Failed to call on the given LNURL
    #[error("Failed to call on the given LNURL.")]
    LnUrlFailure,
    /// Could not make a request to the LSP.
    #[error("Failed to make a request to the LSP.")]
    LspGenericError,
    /// LSP indicated it could not fund the channel requested.
    #[error("Failed to request channel from LSP due to funding error.")]
    LspFundingError,
    /// LSP indicated the amount is too high to fund.
    #[error("Failed to request channel from LSP due to amount being too high.")]
    LspAmountTooHighError,
    /// LSP indicated it was not connected to the client node.
    #[error("Failed to have a connection to the LSP node.")]
    LspConnectionError,
    /// LSP required an invoice and none was provided.
    #[error("Failed to provide an invoice to the LSP.")]
    LspInvoiceRequired,
    /// Subscription Client Not Configured
    #[error("Subscription Client Not Configured")]
    SubscriptionClientNotConfigured,
    /// When an invalid parameter has been passed in by the user.
    #[error("Invalid Parameter")]
    InvalidParameter,
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
    /// A failure to sync the on-chain wallet
    #[error("Failed to to sync on-chain wallet.")]
    WalletSyncError,
    /// An error with rapid gossip sync
    #[error("Failed to execute a rapid gossip sync function")]
    RapidGossipSyncError,
    /// An error when reading/writing json to the front end.
    #[error("Failed to read or write json from the front end")]
    JsonReadWriteError,
    /// Node pubkey given is invalid
    #[error("The given node pubkey is invalid.")]
    PubkeyInvalid,
    /// Error getting nostr data
    #[error("Failed to get nostr data.")]
    NostrError,
    /// Error with Nip07 Extension
    #[error("Error with NIP-07 extension")]
    Nip07Extension,
    /// Error getting the bitcoin price
    #[error("Failed to get the bitcoin price.")]
    BitcoinPriceError,
    /// Error converting JS f64 value to Amount
    #[error("Satoshi amount is invalid")]
    BadAmountError,
    /// A error with DLCs
    #[error("Failed to execute a dlc function")]
    DLCManagerError,
    /// A error with WasmBindgen
    #[error("Failed to execute a wasm_bindgen function")]
    WasmBindgenError,
    /// Invalid Arguments were given
    #[error("Invalid Arguments were given")]
    InvalidArgumentsError,
    /// Incorrect password entered.
    #[error("Incorrect password entered.")]
    IncorrectPassword,
    /// Cannot change password to the same password
    #[error("Cannot change password to the same password.")]
    SamePassword,
    /// Payjoin request creation failed.
    #[error("Failed to create payjoin request.")]
    PayjoinCreateRequest,
    // Payjoin request failed.
    #[error("Payjoin response error: {0}")]
    PayjoinResponse(String),
    /// Payjoin configuration error
    #[error("Payjoin configuration failed.")]
    PayjoinConfigError,
    /// Unknown error.
    #[error("Unknown Error")]
    UnknownError,
}

impl From<MutinyError> for MutinyJsError {
    fn from(e: MutinyError) -> Self {
        match e {
            MutinyError::AlreadyRunning => MutinyJsError::AlreadyRunning,
            MutinyError::NotRunning => MutinyJsError::NotRunning,
            MutinyError::NotFound => MutinyJsError::NotFound,
            MutinyError::FundingTxCreationFailed => MutinyJsError::FundingTxCreationFailed,
            MutinyError::ConnectionFailed => MutinyJsError::ConnectionFailed,
            MutinyError::IncorrectNetwork => MutinyJsError::IncorrectNetwork,
            MutinyError::NonUniquePaymentHash => MutinyJsError::NonUniquePaymentHash,
            MutinyError::PaymentTimeout => MutinyJsError::PaymentTimeout,
            MutinyError::InvoiceInvalid => MutinyJsError::InvoiceInvalid,
            MutinyError::InvoiceExpired => MutinyJsError::InvoiceExpired,
            MutinyError::InvoiceCreationFailed => MutinyJsError::InvoiceCreationFailed,
            MutinyError::ReserveAmountError => MutinyJsError::ReserveAmountError,
            MutinyError::InsufficientBalance => MutinyJsError::InsufficientBalance,
            MutinyError::LnUrlFailure => MutinyJsError::LnUrlFailure,
            MutinyError::LspGenericError => MutinyJsError::LspGenericError,
            MutinyError::LspFundingError => MutinyJsError::LspFundingError,
            MutinyError::LspConnectionError => MutinyJsError::LspConnectionError,
            MutinyError::LspInvoiceRequired => MutinyJsError::LspInvoiceRequired,
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
            MutinyError::WalletSyncError => MutinyJsError::WalletSyncError,
            MutinyError::RapidGossipSyncError => MutinyJsError::RapidGossipSyncError,
            MutinyError::DLCManagerError => MutinyJsError::DLCManagerError,
            MutinyError::PubkeyInvalid => MutinyJsError::PubkeyInvalid,
            MutinyError::IncorrectLnUrlFunction => MutinyJsError::IncorrectLnUrlFunction,
            MutinyError::BadAmountError => MutinyJsError::BadAmountError,
            MutinyError::NostrError => MutinyJsError::NostrError,
            MutinyError::Nip07Extension => MutinyJsError::Nip07Extension,
            MutinyError::BitcoinPriceError => MutinyJsError::BitcoinPriceError,
            MutinyError::IncorrectPassword => MutinyJsError::IncorrectPassword,
            MutinyError::SamePassword => MutinyJsError::SamePassword,
            MutinyError::Other(e) => {
                error!("Got unhandled error: {e}");
                // FIXME: For some unknown reason, InsufficientBalance is being returned as `Other`
                if e.to_string().starts_with("Insufficient balance") {
                    MutinyJsError::InsufficientBalance
                } else {
                    MutinyJsError::UnknownError
                }
            }
            MutinyError::SubscriptionClientNotConfigured => {
                MutinyJsError::SubscriptionClientNotConfigured
            }
            MutinyError::InvalidArgumentsError => MutinyJsError::InvalidArgumentsError,
            MutinyError::LspAmountTooHighError => MutinyJsError::LspAmountTooHighError,
            MutinyError::NetworkMismatch => MutinyJsError::NetworkMismatch,
            MutinyError::PayjoinConfigError => MutinyJsError::PayjoinConfigError,
            MutinyError::PayjoinCreateRequest => MutinyJsError::PayjoinCreateRequest,
            MutinyError::PayjoinResponse(e) => MutinyJsError::PayjoinResponse(e.to_string()),
        }
    }
}

impl From<MutinyStorageError> for MutinyJsError {
    fn from(e: MutinyStorageError) -> Self {
        MutinyError::from(e).into()
    }
}

impl From<base64::DecodeError> for MutinyJsError {
    fn from(_e: base64::DecodeError) -> Self {
        Self::InvalidArgumentsError
    }
}

impl From<bip39::Error> for MutinyJsError {
    fn from(_e: bip39::Error) -> Self {
        Self::InvalidMnemonic
    }
}

impl From<bitcoin::address::Error> for MutinyJsError {
    fn from(_: bitcoin::address::Error) -> Self {
        Self::JsonReadWriteError
    }
}

impl From<lnurl::Error> for MutinyJsError {
    fn from(e: lnurl::Error) -> Self {
        MutinyError::from(e).into()
    }
}

impl From<nostr::nips::nip19::Error> for MutinyJsError {
    fn from(_: nostr::nips::nip19::Error) -> Self {
        Self::InvalidArgumentsError
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

impl From<serde_json::error::Error> for MutinyJsError {
    fn from(_e: serde_json::error::Error) -> Self {
        Self::WasmBindgenError
    }
}

impl From<MutinyJsError> for JsValue {
    fn from(e: MutinyJsError) -> Self {
        JsValue::from(e.to_string())
    }
}
