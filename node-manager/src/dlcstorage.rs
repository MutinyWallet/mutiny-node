use crate::error::{MutinyError, MutinyStorageError};
use crate::localstorage::MutinyBrowserStorage;
use anyhow::Context;
use bitcoin_hashes::hex::ToHex;
use dlc_manager::chain_monitor::ChainMonitor;
use dlc_manager::channel::accepted_channel::AcceptedChannel;
use dlc_manager::channel::offered_channel::OfferedChannel;
use dlc_manager::channel::signed_channel::{SignedChannel, SignedChannelStateType};
use dlc_manager::channel::{Channel, FailedAccept, FailedSign};
use dlc_manager::contract::accepted_contract::AcceptedContract;
use dlc_manager::contract::offered_contract::OfferedContract;
use dlc_manager::contract::ser::Serializable;
use dlc_manager::contract::signed_contract::SignedContract;
use dlc_manager::contract::{
    ClosedContract, Contract, FailedAcceptContract, FailedSignContract, PreClosedContract,
};
use dlc_manager::{error::Error, ChannelId, ContractId, Storage};
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{Cursor, Read};

const DLC_CONTRACT_KEY_PREFIX: &str = "dlc_contract_";
const DLC_CHANNEL_KEY_PREFIX: &str = "dlc_channel_";
const DLC_CHAIN_MONITOR_KEY: &str = "dlc_chain_monitor";

impl Storage for MutinyBrowserStorage {
    fn get_contract(&self, id: &ContractId) -> Result<Option<Contract>, Error> {
        let key = format! {"{DLC_CONTRACT_KEY_PREFIX}{}", id.to_hex()};
        let result: Result<Vec<u8>, MutinyStorageError> = self.get(key);
        match result {
            Ok(contract_bytes) => {
                let contract = deserialize_contract(contract_bytes)
                    .map_err(|e| Error::StorageError(format!("{}", e)))?;
                Ok(Some(contract))
            }
            Err(_) => Ok(None),
        }
    }

    fn get_contracts(&self) -> Result<Vec<Contract>, Error> {
        let map: HashMap<String, Vec<u8>> = self.scan(DLC_CONTRACT_KEY_PREFIX, None);
        let contracts = map.into_values().map(|b| deserialize_contract(b).unwrap());
        Ok(contracts.collect())
    }

    fn create_contract(&mut self, contract: &OfferedContract) -> Result<(), Error> {
        let serialized = serialize_contract(&Contract::Offered(contract.clone()))?;
        let id = contract.id.to_hex();
        let key = format! {"{DLC_CONTRACT_KEY_PREFIX}{id}"};

        self.set(key, serialized)?;
        Ok(())
    }

    fn delete_contract(&mut self, id: &ContractId) -> Result<(), Error> {
        let key = format! {"{DLC_CONTRACT_KEY_PREFIX}{}", id.to_hex()};
        MutinyBrowserStorage::delete(key);
        Ok(())
    }

    fn update_contract(&mut self, contract: &Contract) -> Result<(), Error> {
        let serialized = serialize_contract(contract)?;

        let key = format! {"{DLC_CONTRACT_KEY_PREFIX}{}", contract.get_id().to_hex()};
        self.set(key, serialized.clone())?;

        // delete old contract
        match contract {
            a @ Contract::Accepted(_) | a @ Contract::Signed(_) => {
                let key = format! {"{DLC_CONTRACT_KEY_PREFIX}{}", a.get_temporary_id().to_hex()};
                MutinyBrowserStorage::delete(key);
            }
            _ => {}
        };

        Ok(())
    }

    fn get_contract_offers(&self) -> Result<Vec<OfferedContract>, Error> {
        let map: HashMap<String, OfferedContract> =
            self.get_data_with_prefix(&[ContractPrefix::Offered.into()], None);

        Ok(map.into_values().collect())
    }

    fn get_signed_contracts(&self) -> Result<Vec<SignedContract>, Error> {
        let map: HashMap<String, SignedContract> =
            self.get_data_with_prefix(&[ContractPrefix::Signed.into()], None);
        Ok(map.into_values().collect())
    }

    fn get_confirmed_contracts(&self) -> Result<Vec<SignedContract>, Error> {
        let map: HashMap<String, SignedContract> =
            self.get_data_with_prefix(&[ContractPrefix::Confirmed.into()], None);
        Ok(map.into_values().collect())
    }

    fn get_preclosed_contracts(&self) -> Result<Vec<PreClosedContract>, Error> {
        let map: HashMap<String, PreClosedContract> =
            self.get_data_with_prefix(&[ContractPrefix::PreClosed.into()], None);
        Ok(map.into_values().collect())
    }

    fn upsert_channel(
        &mut self,
        channel: Channel,
        contract: Option<Contract>,
    ) -> Result<(), Error> {
        let serialized = serialize_channel(&channel)?;

        let chan_key = format!("{DLC_CHANNEL_KEY_PREFIX}{}", channel.get_id().to_hex());
        self.set(chan_key, serialized.clone())?;

        match &channel {
            a @ Channel::Accepted(_) | a @ Channel::Signed(_) => {
                let key = format! {"{DLC_CHANNEL_KEY_PREFIX}{}", a.get_temporary_id().to_hex()};
                MutinyBrowserStorage::delete(key);
            }
            _ => {}
        };

        if let Some(c) = contract.as_ref() {
            return self.update_contract(c);
        } else {
            Ok(())
        }
    }

    fn delete_channel(&mut self, channel_id: &ChannelId) -> Result<(), Error> {
        let chan_key = format!("{DLC_CHANNEL_KEY_PREFIX}{}", channel_id.to_hex());
        MutinyBrowserStorage::delete(chan_key);
        Ok(())
    }

    fn get_channel(&self, channel_id: &ChannelId) -> Result<Option<Channel>, Error> {
        let key = format! {"{DLC_CHANNEL_KEY_PREFIX}{}", channel_id.to_hex()};
        let result: Result<Vec<u8>, MutinyStorageError> = self.get(key);
        match result {
            Ok(chan_bytes) => {
                let channel = deserialize_channel(chan_bytes)
                    .map_err(|e| Error::StorageError(format!("{}", e)))?;
                Ok(Some(channel))
            }
            Err(_) => Ok(None),
        }
    }

    fn get_signed_channels(
        &self,
        channel_state: Option<SignedChannelStateType>,
    ) -> Result<Vec<SignedChannel>, Error> {
        let (prefix, consume) = if let Some(state) = &channel_state {
            (
                vec![
                    ChannelPrefix::Signed.into(),
                    SignedChannelPrefix::get_prefix(state),
                ],
                None,
            )
        } else {
            (vec![ChannelPrefix::Signed.into()], Some(1))
        };

        let map: HashMap<String, SignedChannel> = self.get_data_with_prefix(&prefix, consume);

        Ok(map.into_values().collect())
    }

    fn get_offered_channels(&self) -> Result<Vec<OfferedChannel>, Error> {
        let map: HashMap<String, OfferedChannel> =
            self.get_data_with_prefix(&[ChannelPrefix::Offered.into()], None);

        Ok(map.into_values().collect())
    }

    fn persist_chain_monitor(&mut self, monitor: &ChainMonitor) -> Result<(), Error> {
        let serialized: Vec<u8> = monitor.serialize()?;
        self.set(DLC_CHAIN_MONITOR_KEY, serialized)?;
        Ok(())
    }

    fn get_chain_monitor(&self) -> Result<Option<ChainMonitor>, Error> {
        let result: Result<Vec<u8>, MutinyStorageError> = self.get(DLC_CHAIN_MONITOR_KEY);

        match result {
            Ok(bytes) => {
                let mon = ChainMonitor::deserialize(&mut Cursor::new(bytes)).map_err(|_| {
                    Error::StorageError("Failed to decode ChainMonitor".to_string())
                })?;
                Ok(Some(mon))
            }
            Err(e) => match e {
                MutinyStorageError::SerdeError { source: _ } => Err(Error::StorageError(
                    "Failed to decode ChainMonitor".to_string(),
                )),
                _ => Ok(None),
            },
        }
    }
}

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

convertible_enum!(
    enum ChannelPrefix {
        Offered = 100,
        Accepted,
        Signed,
        FailedAccept,
        FailedSign,;
    },
    Channel
);

convertible_enum!(
    enum SignedChannelPrefix {;
        Established = 1,
        SettledOffered,
        SettledReceived,
        SettledAccepted,
        SettledConfirmed,
        Settled,
        Closing,
        Closed,
        CounterClosed,
        ClosedPunished,
        CollaborativeCloseOffered,
        CollaborativelyClosed,
        RenewAccepted,
        RenewOffered,
        RenewConfirmed,
    },
    SignedChannelStateType
);

fn serialize_contract(contract: &Contract) -> Result<Vec<u8>, std::io::Error> {
    let serialized = match contract {
        Contract::Offered(o) | Contract::Rejected(o) => o.serialize(),
        Contract::Accepted(o) => o.serialize(),
        Contract::Signed(o) | Contract::Confirmed(o) | Contract::Refunded(o) => o.serialize(),
        Contract::FailedAccept(c) => c.serialize(),
        Contract::FailedSign(c) => c.serialize(),
        Contract::PreClosed(c) => c.serialize(),
        Contract::Closed(c) => c.serialize(),
    };
    let mut serialized = serialized?;
    let mut res = Vec::with_capacity(serialized.len() + 1);
    res.push(ContractPrefix::get_prefix(contract));
    res.append(&mut serialized);
    Ok(res)
}

fn deserialize_contract(buff: Vec<u8>) -> Result<Contract, MutinyError> {
    let mut cursor = Cursor::new(buff);
    let mut prefix = [0u8; 1];
    cursor
        .read_exact(&mut prefix)
        .with_context(|| "Failed to read exact data from dlc storage")?;
    let contract_prefix: ContractPrefix = prefix[0].try_into()?;
    let contract = match contract_prefix {
        ContractPrefix::Offered => Contract::Offered(OfferedContract::deserialize(&mut cursor)?),
        ContractPrefix::Accepted => Contract::Accepted(AcceptedContract::deserialize(&mut cursor)?),
        ContractPrefix::Signed => Contract::Signed(SignedContract::deserialize(&mut cursor)?),
        ContractPrefix::Confirmed => Contract::Confirmed(SignedContract::deserialize(&mut cursor)?),
        ContractPrefix::PreClosed => {
            Contract::PreClosed(PreClosedContract::deserialize(&mut cursor)?)
        }
        ContractPrefix::Closed => Contract::Closed(ClosedContract::deserialize(&mut cursor)?),
        ContractPrefix::FailedAccept => {
            Contract::FailedAccept(FailedAcceptContract::deserialize(&mut cursor)?)
        }
        ContractPrefix::FailedSign => {
            Contract::FailedSign(FailedSignContract::deserialize(&mut cursor)?)
        }
        ContractPrefix::Refunded => Contract::Refunded(SignedContract::deserialize(&mut cursor)?),
        ContractPrefix::Rejected => Contract::Rejected(OfferedContract::deserialize(&mut cursor)?),
    };
    Ok(contract)
}

fn serialize_channel(channel: &Channel) -> Result<Vec<u8>, std::io::Error> {
    let serialized = match channel {
        Channel::Offered(o) => o.serialize(),
        Channel::Accepted(a) => a.serialize(),
        Channel::Signed(s) => s.serialize(),
        Channel::FailedAccept(f) => f.serialize(),
        Channel::FailedSign(f) => f.serialize(),
    };
    let mut serialized = serialized?;
    let mut res = Vec::with_capacity(serialized.len() + 1);
    res.push(ChannelPrefix::get_prefix(channel));
    if let Channel::Signed(s) = channel {
        res.push(SignedChannelPrefix::get_prefix(&s.state.get_type()))
    }
    res.append(&mut serialized);
    Ok(res)
}

fn deserialize_channel(buff: Vec<u8>) -> Result<Channel, MutinyError> {
    let mut cursor = Cursor::new(buff);
    let mut prefix = [0u8; 1];
    cursor.read_exact(&mut prefix)?;
    let channel_prefix: ChannelPrefix = prefix[0].try_into()?;
    let channel = match channel_prefix {
        ChannelPrefix::Offered => Channel::Offered(OfferedChannel::deserialize(&mut cursor)?),
        ChannelPrefix::Accepted => Channel::Accepted(AcceptedChannel::deserialize(&mut cursor)?),
        ChannelPrefix::Signed => {
            // Skip the channel state prefix.
            cursor.set_position(cursor.position() + 1);
            Channel::Signed(SignedChannel::deserialize(&mut cursor)?)
        }
        ChannelPrefix::FailedAccept => {
            Channel::FailedAccept(FailedAccept::deserialize(&mut cursor)?)
        }
        ChannelPrefix::FailedSign => Channel::FailedSign(FailedSign::deserialize(&mut cursor)?),
    };
    Ok(channel)
}
