use gloo_storage::errors::StorageError;
use std::fmt;

#[derive(Debug)]
#[allow(dead_code)]
// copied from LDK lite
/// An error that possibly needs to be handled by the user.
pub enum Error {
    /// Returned when trying to start Mutiny while it is already running.
    AlreadyRunning,
    /// Returned when trying to stop Mutiny while it is not running.
    NotRunning,
    /// The funding transaction could not be created.
    FundingTxCreationFailed,
    /// A network connection has been closed.
    ConnectionFailed,
    /// Payment of the given invoice has already been initiated.
    NonUniquePaymentHash,
    /// The given invoice is invalid.
    InvoiceInvalid,
    /// Invoice creation failed.
    InvoiceCreationFailed,
    /// No route for the given target could be found.
    RoutingFailed,
    /// A given peer info could not be parsed.
    PeerInfoParseFailed,
    /// A channel could not be opened.
    ChannelCreationFailed,
    /// A channel could not be closed.
    ChannelClosingFailed,
    /// Persistence failed.
    PersistenceFailed,
    /// A wallet operation failed.
    WalletOperationFailed,
    /// A signing operation failed.
    WalletSigningFailed,
    /// A chain access operation failed.
    ChainAccessFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::AlreadyRunning => write!(f, "Mutiny is already running."),
            Self::NotRunning => write!(f, "Mutiny is not running."),
            Self::FundingTxCreationFailed => {
                write!(f, "Funding transaction could not be created.")
            }
            Self::ConnectionFailed => write!(f, "Network connection closed."),
            Self::NonUniquePaymentHash => write!(f, "An invoice must not get payed twice."),
            Self::InvoiceInvalid => write!(f, "The given invoice is invalid."),
            Self::InvoiceCreationFailed => write!(f, "Failed to create invoice."),
            Self::RoutingFailed => write!(f, "Failed to find route."),
            Self::PeerInfoParseFailed => write!(f, "Failed to parse the given peer information."),
            Self::ChannelCreationFailed => write!(f, "Failed to create channel."),
            Self::ChannelClosingFailed => write!(f, "Failed to close channel."),
            Self::PersistenceFailed => write!(f, "Failed to persist data."),
            Self::WalletOperationFailed => write!(f, "Failed to conduct wallet operation."),
            Self::WalletSigningFailed => write!(f, "Failed to sign given transaction."),
            Self::ChainAccessFailed => write!(f, "Failed to conduct chain access operation."),
        }
    }
}

impl std::error::Error for Error {}

impl From<bdk::Error> for Error {
    fn from(e: bdk::Error) -> Self {
        match e {
            bdk::Error::Signer(_) => Self::WalletSigningFailed,
            _ => Self::WalletOperationFailed,
        }
    }
}

// todo uncomment when we add esplora stuff
// impl From<esplora::EsploraError> for Error {
//     fn from(_e: esplora::EsploraError) -> Self {
//         Self::ChainAccessFailed
//     }
// }

impl From<StorageError> for Error {
    fn from(_e: StorageError) -> Self {
        Self::PersistenceFailed
    }
}
