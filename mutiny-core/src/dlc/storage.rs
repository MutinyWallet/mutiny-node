use crate::error::MutinyError;
use crate::storage::{MutinyStorage, VersionedValue};
use bitcoin::consensus::ReadExt;
use bitcoin::hashes::hex::ToHex;
use bitcoin::secp256k1::PublicKey;
use dlc_manager::chain_monitor::ChainMonitor;
use dlc_manager::channel::offered_channel::OfferedChannel;
use dlc_manager::channel::signed_channel::{SignedChannel, SignedChannelStateType};
use dlc_manager::channel::Channel;
use dlc_manager::contract::accepted_contract::AcceptedContract;
use dlc_manager::contract::offered_contract::OfferedContract;
use dlc_manager::contract::ser::Serializable;
use dlc_manager::contract::signed_contract::SignedContract;
use dlc_manager::contract::{
    ClosedContract, Contract, FailedAcceptContract, FailedSignContract, PreClosedContract,
};
use dlc_manager::ChannelId;
use dlc_manager::{error::Error, ContractId};
use lightning::io::Cursor;
use serde_json::Value;
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

// copied from rust-dlc
macro_rules! convertible_enum {
    (enum $name:ident {
        $($vname:ident $(= $val:expr)?,)*;
        $($tname:ident $(= $tval:expr)?,)*
    }, $input:ident) => {
        #[derive(Debug)]
        enum $name {
            $($vname $(= $val)?,)*
            $($tname $(= $tval)?,)*
        }

        impl From<$name> for u8 {
            fn from(prefix: $name) -> u8 {
                prefix as u8
            }
        }

        impl std::convert::TryFrom<u8> for $name {
            type Error = Error;

            fn try_from(v: u8) -> Result<Self, Self::Error> {
                match v {
                    $(x if x == u8::from($name::$vname) => Ok($name::$vname),)*
                    $(x if x == u8::from($name::$tname) => Ok($name::$tname),)*
                    _ => Err(Error::StorageError("Unknown prefix".to_string())),
                }
            }
        }

        impl $name {
            #[allow(dead_code)]
            fn get_prefix(input: &$input) -> u8 {
                let prefix = match input {
                    $($input::$vname(_) => $name::$vname,)*
                    $($input::$tname{..} => $name::$tname,)*
                };
                prefix.into()
            }
        }
    }
}

// copied from rust-dlc
convertible_enum!(
    enum ContractPrefix {
        Offered = 1,
        Accepted,
        Signed,
        Confirmed,
        PreClosed,
        Closed,
        FailedAccept,
        FailedSign,
        Refunded,
        Rejected,;
    },
    Contract
);

fn to_storage_error<T>(e: T) -> Error
where
    T: std::fmt::Display,
{
    Error::StorageError(e.to_string())
}

pub const DLC_CONTRACT_KEY_PREFIX: &str = "dlc_contract/";
pub const DLC_KEY_INDEX_KEY: &str = "dlc_key_index";

#[derive(Clone)]
pub struct DlcStorage<S: MutinyStorage> {
    pub(crate) storage: S,
    key_index_counter: Arc<AtomicU32>,
}

impl<S: MutinyStorage> DlcStorage<S> {
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            key_index_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Get the next key index to use for a new contract. Saves the index to storage.
    /// This is used to generate unique keys for contracts
    pub(crate) fn get_next_key_index(&self) -> u32 {
        self.key_index_counter.fetch_add(1, Ordering::SeqCst)
    }

    pub(crate) fn add_new_key(&self, pk: PublicKey, index: u32) -> Result<(), MutinyError> {
        let mut current: HashMap<PublicKey, u32> =
            match self.storage.get_data::<VersionedValue>(DLC_KEY_INDEX_KEY)? {
                Some(value) => value.get_value()?,
                None => HashMap::with_capacity(1),
            };

        current.insert(pk, index);

        // Save the new key index map and set the version to the current index
        // this way it is stored in VSS with the latest version
        let value = VersionedValue {
            value: serde_json::to_value(current)?,
            version: index,
        };
        self.storage
            .set_data(DLC_KEY_INDEX_KEY.to_string(), value, Some(index))?;

        Ok(())
    }

    pub(crate) fn get_index_for_key(&self, pk: &PublicKey) -> Result<u32, MutinyError> {
        let current: HashMap<PublicKey, u32> =
            match self.storage.get_data::<VersionedValue>(DLC_KEY_INDEX_KEY)? {
                Some(value) => value.get_value()?,
                None => return Err(MutinyError::NotFound),
            };
        current.get(pk).copied().ok_or(MutinyError::NotFound)
    }
}

impl<S: MutinyStorage> dlc_manager::Storage for DlcStorage<S> {
    fn get_contract(&self, id: &ContractId) -> Result<Option<Contract>, Error> {
        let key = format!("{DLC_CONTRACT_KEY_PREFIX}{}", id.to_hex());
        match self
            .storage
            .get_data::<VersionedValue>(&key)
            .map_err(to_storage_error)?
        {
            None => Ok(None),
            Some(value) => {
                let string: String = value.get_value().map_err(to_storage_error)?;
                let bytes: Vec<u8> = base64::decode(string).map_err(to_storage_error)?;
                Ok(Some(deserialize_contract(&bytes)?))
            }
        }
    }

    fn get_contracts(&self) -> Result<Vec<Contract>, Error> {
        self.storage
            .scan::<VersionedValue>(DLC_CONTRACT_KEY_PREFIX, None)
            .map_err(to_storage_error)?
            .into_values()
            .map(|value| {
                let string: String = value.get_value().map_err(to_storage_error)?;
                base64::decode(string)
                    .map_err(to_storage_error)
                    .and_then(|b| deserialize_contract(&b))
            })
            .collect()
    }

    fn create_contract(&self, contract: &OfferedContract) -> Result<(), Error> {
        let serialized = serialize_contract(&Contract::Offered(contract.clone()))?;
        let key = format!("{DLC_CONTRACT_KEY_PREFIX}{}", contract.id.to_hex());

        let value = VersionedValue {
            value: Value::String(base64::encode(serialized)),
            version: 0,
        };

        self.storage
            .set_data(key, value, None)
            .map_err(to_storage_error)
    }

    fn delete_contract(&self, id: &ContractId) -> Result<(), Error> {
        let key = format!("{DLC_CONTRACT_KEY_PREFIX}{}", id.to_hex());
        self.storage.delete(&[key]).map_err(to_storage_error)
    }

    fn update_contract(&self, contract: &Contract) -> Result<(), Error> {
        let serialized = serialize_contract(contract)?;
        let key = format!("{DLC_CONTRACT_KEY_PREFIX}{}", contract.get_id().to_hex());

        let version = get_version(contract);
        let value = VersionedValue {
            value: Value::String(base64::encode(serialized)),
            version: version.unwrap_or(0),
        };

        self.storage
            .set_data(key, value, version)
            .map_err(to_storage_error)?;

        // if the contract was in the offer state, we can delete the version with the temporary id
        match contract {
            a @ Contract::Accepted(_) | a @ Contract::Signed(_) => {
                let key = format!("{DLC_CONTRACT_KEY_PREFIX}{}", a.get_temporary_id().to_hex());
                self.storage.delete(&[key]).map_err(to_storage_error)?;
            }
            _ => {}
        };

        Ok(())
    }

    fn get_contract_offers(&self) -> Result<Vec<OfferedContract>, Error> {
        Ok(self
            .get_contracts()?
            .into_iter()
            .filter_map(|c| match c {
                Contract::Offered(o) => Some(o),
                _ => None,
            })
            .collect())
    }

    fn get_signed_contracts(&self) -> Result<Vec<SignedContract>, Error> {
        Ok(self
            .get_contracts()?
            .into_iter()
            .filter_map(|c| match c {
                Contract::Signed(o) => Some(o),
                _ => None,
            })
            .collect())
    }

    fn get_confirmed_contracts(&self) -> Result<Vec<SignedContract>, Error> {
        Ok(self
            .get_contracts()?
            .into_iter()
            .filter_map(|c| match c {
                Contract::Confirmed(o) => Some(o),
                _ => None,
            })
            .collect())
    }

    fn get_preclosed_contracts(&self) -> Result<Vec<PreClosedContract>, Error> {
        Ok(self
            .get_contracts()?
            .into_iter()
            .filter_map(|c| match c {
                Contract::PreClosed(o) => Some(o),
                _ => None,
            })
            .collect())
    }

    fn upsert_channel(&self, _: Channel, _: Option<Contract>) -> Result<(), Error> {
        Ok(()) // Channels not supported
    }

    fn delete_channel(&self, _: &ChannelId) -> Result<(), Error> {
        Ok(()) // Channels not supported
    }

    fn get_channel(&self, _: &ChannelId) -> Result<Option<Channel>, Error> {
        Ok(None) // Channels not supported
    }

    fn get_signed_channels(
        &self,
        _: Option<SignedChannelStateType>,
    ) -> Result<Vec<SignedChannel>, Error> {
        Ok(vec![]) // Channels not supported
    }

    fn get_offered_channels(&self) -> Result<Vec<OfferedChannel>, Error> {
        Ok(vec![]) // Channels not supported
    }

    fn persist_chain_monitor(&self, _: &ChainMonitor) -> Result<(), Error> {
        Ok(()) // Channels not supported
    }

    fn get_chain_monitor(&self) -> Result<Option<ChainMonitor>, Error> {
        Ok(None) // Channels not supported
    }
}

fn get_version(contract: &Contract) -> Option<u32> {
    match contract {
        Contract::Offered(_) => None,
        Contract::Accepted(_) => Some(1),
        Contract::Signed(_) => Some(2),
        Contract::Confirmed(_) => Some(3),
        Contract::PreClosed(_) => Some(4),
        Contract::Closed(_) => Some(5),
        Contract::Refunded(_) => Some(5),
        Contract::FailedAccept(_) => None,
        Contract::FailedSign(_) => Some(2),
        Contract::Rejected(_) => None,
    }
}

fn serialize_contract(contract: &Contract) -> Result<Vec<u8>, lightning::io::Error> {
    let mut serialized = match contract {
        Contract::Offered(o) | Contract::Rejected(o) => o.serialize(),
        Contract::Accepted(o) => o.serialize(),
        Contract::Signed(o) | Contract::Confirmed(o) | Contract::Refunded(o) => o.serialize(),
        Contract::FailedAccept(c) => c.serialize(),
        Contract::FailedSign(c) => c.serialize(),
        Contract::PreClosed(c) => c.serialize(),
        Contract::Closed(c) => c.serialize(),
    }?;
    let mut res = Vec::with_capacity(serialized.len() + 1);
    res.push(ContractPrefix::get_prefix(contract));
    res.append(&mut serialized);
    Ok(res)
}

fn deserialize_contract(buff: &Vec<u8>) -> Result<Contract, Error> {
    let mut cursor = Cursor::new(buff);
    let prefix = cursor.read_u8().map_err(to_storage_error)?;
    let contract_prefix: ContractPrefix = prefix.try_into()?;
    let contract = match contract_prefix {
        ContractPrefix::Offered => {
            Contract::Offered(OfferedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::Accepted => Contract::Accepted(
            AcceptedContract::deserialize(&mut cursor).map_err(to_storage_error)?,
        ),
        ContractPrefix::Signed => {
            Contract::Signed(SignedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::Confirmed => {
            Contract::Confirmed(SignedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::PreClosed => Contract::PreClosed(
            PreClosedContract::deserialize(&mut cursor).map_err(to_storage_error)?,
        ),
        ContractPrefix::Closed => {
            Contract::Closed(ClosedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::FailedAccept => Contract::FailedAccept(
            FailedAcceptContract::deserialize(&mut cursor).map_err(to_storage_error)?,
        ),
        ContractPrefix::FailedSign => Contract::FailedSign(
            FailedSignContract::deserialize(&mut cursor).map_err(to_storage_error)?,
        ),
        ContractPrefix::Refunded => {
            Contract::Refunded(SignedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
        ContractPrefix::Rejected => {
            Contract::Rejected(OfferedContract::deserialize(&mut cursor).map_err(to_storage_error)?)
        }
    };
    Ok(contract)
}

#[cfg(test)]
mod test {
    const CONTRACT: &str = "AQ68ldR1g4+lMEK8Thnn6YVBQSPCmMSDE3yhTr94i6aYAQEAAwVIZWFkcwAAAAAAAE4gAAAAAAAAAAAFVGFpbHMAAAAAAAAAAAAAAAAAAE4gBU90aGVyAAAAAAAATiAAAAAAAAAAAAH+fbKa07eOeLmFEq7s+oEqLvvEezDGts8b+nde8ioDPiv/AAmOFo7qr+02HLDDWRTfbSGG+EbV2SUopvkHf28A6BSt/rJCA1591v1sZk7s0jYALK6l+FfRcP0z89JxR6X92CJWAAGlLn5AA0hFODKxAnrWjypuhXUbvz9Zfou91hPgK3LcB2Owp4D92AYUAAMFSGVhZHMFVGFpbHMFT3RoZXIXQ29pbiBGbGlwOiBwcm9tcHRfaWQ6IDMAAAAAAAAAAQINsC8f/fzu4kZIQ3fRBsLcMQgYKR37cUg0DuSghIszUAAiUSAVRsZLDbs7nb3h0iD1dJq1hJSb/75ai1bcBsnjiMoB7AH4SBYY6DbDACJRIB+HX+NTITKZXVG8cwyw/msjOzQevUrfsvK/MCxSJGXGQc9CZTYW+vgCLCil9Bsdm2wLqWMjeS/0njJx9b1u2jwd9FR0Q4h8cEMAAAABAAAAAAAAAGsAANFyTIr3AbIwfl/BWtUZ7ggHvQYTdfpsBKzXZ90VekKxdvq1Pl2UIBMAAAABAAAAAAAAAGsAAMu8nsx8bof0AAAAAAANujEAAAAAAAAnEAAAAAAAAE4gAtFyTIr3AbIw/QFlAgAAAAABAX5fwVrVGe4IB70GE3X6bASs12fdFXpCsXb6tT5dlCATAAAAAAD/////AqGGAQAAAAAAIlEggwVyU+kC22wCN614y2wCtnTvuF/Ln92cptOwzBl2j4gwNAwAAAAAACJRIPzpzEQqLkazw4rRnglUQIk+dpmmshqGTfDyc5yk5fvDBABHMEQCIGyaSYj/vfO7ODRKV/xulr3Ee58R0i1+OufMlxUa+njcAiA8OTf/Feg/IIlnA4qEtFGdm7jksIZrOTijVWBjKTFv8QFHMEQCIBvNV6dMdh9SlT5XglwK66hnod7zopHT4RVkVhfx0AHnAiAdc2mk3uMEyfMN805E4jnSN2PHywLpqihWvwTFMc6EKQFHUiECMA2WZ/AHrCQrohTqaAwu6aWJhUAfUzgDRLDlKlDyzOEhAuwZwjj5yAd/DKBptU26oE4WjHZX9wBrpKwVHyT0U7SgUq4AAAAAAAAAAf////8AawAAAQAiUSD86cxEKi5Gs8OK0Z4JVECJPnaZprIahk3w8nOcpOX7wwLLvJ7MfG6H9M0BAAAAAAEBeeE5jZDiWmQr024298DGmNniTu2umnSNjqmgMDbq5yABAAAAAP3///8CoLsNAAAAAAAiACAgWddflXslHvYkNG0voUEqe8u5S/YMpI9Ub1TTzF2RwgGGAQAAAAAAIlEgL13S33W6Alqltjr+uyrWxPdpLFGRVIhcrFzMHz0KelMBQE7cNkv7asK8qIEtMTZHbxPdpmUAuYQcygWYmquLYJkFZs5f6mJslvsiNHjEteW9yyBbgZPmoPYvM9puFHLJ4kmMGQgAAAAAAf////8AawAAAQAiUSAvXdLfdboCWqW2Ov67KtbE92ksUZFUiFysXMwfPQp6UwJp7uXSKrCglwAAAAAAAAACZVLPy2O54gACgdG50ZdBvVN5GiSylSn5wqojFmEVMlhgFBqgcRBTLXU=";

    #[test]
    fn test_parse_contract() {
        let bytes = base64::decode(CONTRACT).unwrap();
        let contract = super::deserialize_contract(&bytes).unwrap();
        assert!(matches!(contract, super::Contract::Offered(_)));
    }
}
