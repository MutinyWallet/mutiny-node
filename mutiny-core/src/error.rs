use crate::esplora::TxSyncError;
use bitcoin::Network;
use lightning::ln::peer_handler::PeerHandleError;
use lightning_invoice::payment::PaymentError;
use lightning_invoice::ParseOrSemanticError;
use lightning_rapid_gossip_sync::GraphSyncError;
use thiserror::Error;

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
    /// A failure to sync the on-chain wallet
    #[error("Failed to to sync on-chain wallet.")]
    WalletSyncError,
    /// An error with rapid gossip sync
    #[error("Failed to execute a rapid gossip sync function")]
    RapidGossipSyncError,
    /// A error with DLCs
    #[error("Failed to execute a dlc function")]
    DLCManagerError,
    /// Node pubkey given is invalid
    #[error("The given node pubkey is invalid.")]
    PubkeyInvalid,
    #[error("Called incorrect lnurl function.")]
    IncorrectLnUrlFunction,
    /// Error converting JS f64 value to Amount
    #[error("Satoshi amount is invalid")]
    BadAmountError,
    /// Error getting the bitcoin price
    #[error("Failed to get the bitcoin price.")]
    BitcoinPriceError,
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
    #[error("Failed to get lock on memory storage")]
    LockError,
    #[error("Failed to use indexeddb storage")]
    IndexedDBError,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl MutinyError {
    pub fn read_err(e: MutinyStorageError) -> Self {
        MutinyError::ReadError { source: e }
    }

    pub fn write_err(e: MutinyStorageError) -> Self {
        MutinyError::PersistenceFailed { source: e }
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

impl From<bdk::descriptor::error::Error> for MutinyError {
    fn from(_: bdk::descriptor::error::Error) -> Self {
        Self::WalletOperationFailed
    }
}

impl From<bdk::wallet::NewError<MutinyError>> for MutinyError {
    fn from(e: bdk::wallet::NewError<MutinyError>) -> Self {
        match e {
            bdk::wallet::NewError::Persist(e) => e,
            bdk::wallet::NewError::Descriptor(e) => e.into(),
        }
    }
}

impl From<bip39::Error> for MutinyError {
    fn from(_e: bip39::Error) -> Self {
        Self::InvalidMnemonic
    }
}

impl From<bitcoin::util::bip32::Error> for MutinyError {
    fn from(_e: bitcoin::util::bip32::Error) -> Self {
        Self::InvalidMnemonic
    }
}

impl From<lnurl::Error> for MutinyError {
    fn from(_e: lnurl::Error) -> Self {
        Self::LnUrlFailure
    }
}

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

impl From<serde_json::Error> for MutinyError {
    fn from(_: serde_json::Error) -> Self {
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

impl<G> From<std::sync::PoisonError<G>> for MutinyStorageError {
    fn from(_e: std::sync::PoisonError<G>) -> Self {
        MutinyStorageError::LockError
    }
}

impl<G> From<std::sync::TryLockError<G>> for MutinyError {
    fn from(_e: std::sync::TryLockError<G>) -> Self {
        MutinyStorageError::LockError.into()
    }
}

impl<G> From<std::sync::TryLockError<G>> for MutinyStorageError {
    fn from(_e: std::sync::TryLockError<G>) -> Self {
        MutinyStorageError::LockError
    }
}

impl From<bitcoin::hashes::hex::Error> for MutinyError {
    fn from(_e: bitcoin::hashes::hex::Error) -> Self {
        MutinyError::ReadError {
            source: MutinyStorageError::Other(anyhow::anyhow!("Failed to decode hex")),
        }
    }
}

impl From<bitcoin::util::address::Error> for MutinyError {
    fn from(_e: bitcoin::util::address::Error) -> Self {
        MutinyError::ReadError {
            source: MutinyStorageError::Other(anyhow::anyhow!("Failed to decode address")),
        }
    }
}

impl From<esplora_client::Error> for MutinyError {
    fn from(_e: esplora_client::Error) -> Self {
        // This is most likely a chain access failure
        Self::ChainAccessFailed
    }
}

impl<T> From<bdk::chain::chain_graph::UpdateError<T>> for MutinyError {
    fn from(_e: bdk::chain::chain_graph::UpdateError<T>) -> Self {
        Self::WalletSyncError
    }
}

impl<T> From<bdk::chain::chain_graph::InsertTxError<T>> for MutinyError {
    fn from(_e: bdk::chain::chain_graph::InsertTxError<T>) -> Self {
        Self::WalletSyncError
    }
}

impl From<bdk::chain::chain_graph::InsertCheckpointError> for MutinyError {
    fn from(_e: bdk::chain::chain_graph::InsertCheckpointError) -> Self {
        Self::WalletSyncError
    }
}
