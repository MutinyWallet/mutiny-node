use crate::error::MutinyError;
use crate::storage::MutinyStorage;
use crate::MutinyWallet;
use bitcoin::Address;
use lightning_invoice::Bolt11Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use nostr::Metadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use uuid::Uuid;

const ADDRESS_LABELS_MAP_KEY: &str = "address_labels";
const INVOICE_LABELS_MAP_KEY: &str = "invoice_labels";
const LABEL_PREFIX: &str = "label/";
const CONTACT_PREFIX: &str = "contact/";

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct LabelItem {
    /// List of addresses that have this label
    pub addresses: HashSet<String>,
    /// List of invoices that have this label
    pub invoices: HashSet<Bolt11Invoice>,
    /// Epoch time in seconds when this label was last used
    pub last_used_time: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Contact {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npub: Option<nostr::PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ln_address: Option<LightningAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lnurl: Option<LnUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_url: Option<String>,
    pub last_used: u64,
}

impl Contact {
    /// Update the contact with metadata from their Nostr profile
    pub fn update_with_metadata(mut self, metadata: Metadata) -> Self {
        self.name = metadata
            .display_name
            .filter(|n| !n.is_empty())
            .or(metadata.name.filter(|n| !n.is_empty()))
            .unwrap_or(self.name);

        let ln_address = metadata
            .lud16
            .and_then(|lud16| LightningAddress::from_str(&lud16).ok());
        self.ln_address = ln_address.or(self.ln_address);

        let lnurl = metadata
            .lud06
            .and_then(|lud06| LnUrl::from_str(&lud06).ok());
        self.lnurl = lnurl.or(self.lnurl);

        self.image_url = metadata
            .picture
            .filter(|p| !p.is_empty())
            .or(self.image_url);

        self
    }

    pub fn create_from_metadata(npub: nostr::PublicKey, metadata: Metadata) -> Self {
        let init = Self {
            npub: Some(npub),
            ..Default::default()
        };
        init.update_with_metadata(metadata)
    }

    /// Checks if the contact has the given lnurl as either a lnurl or a lightning address
    pub fn has_lnurl(&self, lnurl: &LnUrl) -> bool {
        if self.lnurl.as_ref().is_some_and(|l| l == lnurl) {
            return true;
        }

        if let Some(ln_address) = self.ln_address.as_ref() {
            if lnurl.lightning_address().as_ref() == Some(ln_address) {
                return true;
            }
        }

        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum TagItem {
    Label((String, LabelItem)),
    Contact((String, Contact)),
}

pub(crate) fn get_label_item_key(label: impl AsRef<str>) -> String {
    format!("{}{}", LABEL_PREFIX, label.as_ref())
}

pub(crate) fn get_contact_key(label: impl AsRef<str>) -> String {
    format!("{}{}", CONTACT_PREFIX, label.as_ref())
}

pub trait LabelStorage {
    /// Get a map of addresses to labels. This can be used to get all the labels for an address
    fn get_address_labels(&self) -> Result<HashMap<String, Vec<String>>, MutinyError>;
    /// Get a map of invoices to labels. This can be used to get all the labels for an invoice
    fn get_invoice_labels(&self) -> Result<HashMap<Bolt11Invoice, Vec<String>>, MutinyError>;
    /// Get all the existing labels
    fn get_labels(&self) -> Result<HashMap<String, LabelItem>, MutinyError>;
    /// Get information about a label
    fn get_label(&self, label: impl AsRef<str>) -> Result<Option<LabelItem>, MutinyError>;
    /// Set the labels for an address, replacing any existing labels
    /// If you do not want to replace any existing labels, use `get_address_labels` to get the existing labels,
    /// add the new labels, and then use `set_address_labels` to set the new labels
    fn set_address_labels(&self, address: Address, labels: Vec<String>) -> Result<(), MutinyError>;
    /// Set the labels for an invoice, replacing any existing labels
    /// If you do not want to replace any existing labels, use `get_invoice_labels` to get the existing labels,
    /// add the new labels, and then use `set_invoice_labels` to set the new labels
    fn set_invoice_labels(
        &self,
        invoice: Bolt11Invoice,
        labels: Vec<String>,
    ) -> Result<(), MutinyError>;
    /// Get all the existing contacts
    fn get_contacts(&self) -> Result<HashMap<String, Contact>, MutinyError>;
    /// Get a contact by label, the label should be a uuid
    fn get_contact(&self, label: impl AsRef<str>) -> Result<Option<Contact>, MutinyError>;
    /// Create a new contact from an existing label and returns the new identifying label
    fn create_contact_from_label(
        &self,
        label: impl AsRef<str>,
        contact: Contact,
    ) -> Result<String, MutinyError>;
    /// Create a new contact and return the identifying label
    fn create_new_contact(&self, contact: Contact) -> Result<String, MutinyError>;
    /// Deletes a contact and all labels associated with it
    fn delete_contact(&self, id: impl AsRef<str>) -> Result<(), MutinyError>;
    /// Edits an existing contact and replaces the existing contact
    fn edit_contact(&self, id: impl AsRef<str>, contact: Contact) -> Result<(), MutinyError>;
    /// Gets all the existing tags (labels and contacts)
    fn get_tag_items(&self) -> Result<Vec<TagItem>, MutinyError>;
    /// Finds a contact that has the given lnurl as either a lnurl or a lightning address
    fn get_contact_for_lnurl(&self, lnurl: &LnUrl) -> Result<Option<String>, MutinyError> {
        let contacts = self.get_contacts()?;
        for (id, contact) in contacts {
            if contact.has_lnurl(lnurl) {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }
    /// Finds a contact that has the given npub
    fn get_contact_for_npub(
        &self,
        npub: nostr::PublicKey,
    ) -> Result<Option<(String, Contact)>, MutinyError> {
        // todo this is not efficient, we should have a map of npub to contact
        let contacts = self.get_contacts()?;
        for (id, contact) in contacts {
            if contact.npub == Some(npub) {
                return Ok(Some((id, contact)));
            }
        }
        Ok(None)
    }
}

impl<S: MutinyStorage> LabelStorage for S {
    fn get_address_labels(&self) -> Result<HashMap<String, Vec<String>>, MutinyError> {
        let res: Option<HashMap<String, Vec<String>>> = self.get_data(ADDRESS_LABELS_MAP_KEY)?;
        Ok(res.unwrap_or_default()) // if no labels exist, return an empty map
    }

    fn get_invoice_labels(&self) -> Result<HashMap<Bolt11Invoice, Vec<String>>, MutinyError> {
        let res: Option<HashMap<Bolt11Invoice, Vec<String>>> =
            self.get_data(INVOICE_LABELS_MAP_KEY)?;
        Ok(res.unwrap_or_default()) // if no labels exist, return an empty map
    }

    fn get_labels(&self) -> Result<HashMap<String, LabelItem>, MutinyError> {
        let all = self.scan(LABEL_PREFIX, None)?;
        // remove the prefix from the keys
        let mut labels = HashMap::new();
        for (key, label_item) in all {
            let label = key.replace(LABEL_PREFIX, "");
            labels.insert(label, label_item);
        }

        Ok(labels)
    }

    fn get_label(&self, label: impl AsRef<str>) -> Result<Option<LabelItem>, MutinyError> {
        let key = get_label_item_key(label);
        self.get_data(key)
    }

    fn set_address_labels(&self, address: Address, labels: Vec<String>) -> Result<(), MutinyError> {
        // update the labels map
        let mut address_labels = self.get_address_labels()?;
        address_labels.insert(address.to_string(), labels.clone());
        self.set_data(ADDRESS_LABELS_MAP_KEY.to_string(), address_labels, None)?;

        // update the label items
        let now = crate::utils::now().as_secs();
        for label in labels {
            let key = get_label_item_key(&label);
            match self.get_label(&label)? {
                Some(mut label_item) => {
                    // Add the address to the label item
                    // and sort so we can dedup the addresses
                    label_item.addresses.insert(address.to_string());

                    // Update the last used timestamp
                    label_item.last_used_time = now;

                    // if it is a contact, update last used
                    if let Some(contact) = self.get_contact(&label)? {
                        let mut contact = contact;
                        contact.last_used = now;
                        self.edit_contact(&label, contact)?;
                    }

                    self.set_data(key, label_item, None)?;
                }
                None => {
                    let mut addresses = HashSet::with_capacity(1);
                    addresses.insert(address.to_string());
                    // Create a new label item
                    let label_item = LabelItem {
                        addresses,
                        invoices: HashSet::new(),
                        last_used_time: now,
                    };
                    self.set_data(key, label_item, None)?;
                }
            }
        }

        Ok(())
    }

    fn set_invoice_labels(
        &self,
        invoice: Bolt11Invoice,
        labels: Vec<String>,
    ) -> Result<(), MutinyError> {
        // update the labels map
        let mut invoice_labels = self.get_invoice_labels()?;
        invoice_labels.insert(invoice.clone(), labels.clone());
        self.set_data(INVOICE_LABELS_MAP_KEY.to_string(), invoice_labels, None)?;

        // update the label items
        let now = crate::utils::now().as_secs();
        for label in labels {
            let key = get_label_item_key(&label);
            match self.get_label(&label)? {
                Some(mut label_item) => {
                    // Add the invoice to the label item
                    // and sort so we can dedup the invoices
                    label_item.invoices.insert(invoice.clone());

                    // Update the last used timestamp
                    label_item.last_used_time = now;

                    // if it is a contact, update last used
                    if let Some(contact) = self.get_contact(&label)? {
                        let mut contact = contact;
                        contact.last_used = now;
                        self.edit_contact(&label, contact)?;
                    }

                    self.set_data(key, label_item, None)?;
                }
                None => {
                    // Create a new label item
                    let invoices = HashSet::from_iter(vec![invoice.clone()]);
                    let label_item = LabelItem {
                        addresses: HashSet::new(),
                        invoices,
                        last_used_time: now,
                    };
                    self.set_data(key, label_item, None)?;
                }
            }
        }

        Ok(())
    }

    fn get_contacts(&self) -> Result<HashMap<String, Contact>, MutinyError> {
        let all = self.scan::<Contact>(CONTACT_PREFIX, None)?;
        // remove the prefix from the keys
        let mut contacts = HashMap::with_capacity(all.len());
        for (key, contact) in all {
            let label = key.replace(CONTACT_PREFIX, "");
            contacts.insert(label, contact);
        }

        Ok(contacts)
    }

    fn get_contact(&self, label: impl AsRef<str>) -> Result<Option<Contact>, MutinyError> {
        self.get_data(get_contact_key(label))
    }

    fn create_contact_from_label(
        &self,
        label: impl AsRef<str>,
        contact: Contact,
    ) -> Result<String, MutinyError> {
        match self.get_label(&label)? {
            None => Err(MutinyError::NotFound),
            Some(current) => {
                // convert label into a uuid for uniqueness
                let id = Uuid::new_v4().to_string();
                // create label item
                self.set_data(get_label_item_key(&id), current, None)?;

                // replace label in address_labels with new uuid
                let addr_labels = self.get_address_labels()?;
                let mut updated = HashMap::new();
                let label_str = label.as_ref().to_string();
                for (addr, labels) in addr_labels {
                    if labels.contains(&label_str) {
                        let new_labels: Vec<String> = labels
                            .into_iter()
                            // replace the label with the new id, otherwise keep old one
                            .map(|l| if l == label_str { id.clone() } else { l })
                            .collect();

                        updated.insert(addr, new_labels);
                    }
                }
                self.set_data(ADDRESS_LABELS_MAP_KEY.to_string(), updated, None)?;

                // replace label in invoice_labels with new uuid
                let invoice_labels = self.get_invoice_labels()?;
                let mut updated = HashMap::new();
                let label_str = label.as_ref().to_string();
                for (inv, labels) in invoice_labels {
                    if labels.contains(&label_str) {
                        let new_labels: Vec<String> = labels
                            .into_iter()
                            // replace the label with the new id, otherwise keep old one
                            .map(|l| if l == label_str { id.clone() } else { l })
                            .collect();

                        updated.insert(inv, new_labels);
                    }
                }
                self.set_data(INVOICE_LABELS_MAP_KEY.to_string(), updated, None)?;

                // create the contact
                let key = get_contact_key(&id);
                self.set_data(key, contact, None)?;

                // delete old label item
                self.delete(&[get_label_item_key(&label)])?;
                Ok(id)
            }
        }
    }

    /// Create a new contact and return the identifying label
    fn create_new_contact(&self, contact: Contact) -> Result<String, MutinyError> {
        // generate a uuid, this will be the "label" that we use to store the contact
        let id = Uuid::new_v4().to_string();
        let key = get_contact_key(&id);
        self.set_data(key, contact, None)?;

        let key = get_label_item_key(&id);
        let label_item = LabelItem {
            last_used_time: crate::utils::now().as_secs(),
            ..Default::default()
        };
        self.set_data(key, label_item, None)?;
        Ok(id)
    }

    fn delete_contact(&self, id: impl AsRef<str>) -> Result<(), MutinyError> {
        // first remove from all labels
        let mut inv_labels = self.get_invoice_labels()?;
        for value in inv_labels.values_mut() {
            value.retain(|s| *s != id.as_ref());
        }
        let mut addr_labels = self.get_address_labels()?;
        for value in addr_labels.values_mut() {
            value.retain(|s| *s != id.as_ref());
        }
        let to_set: Vec<(String, Value)> = vec![
            (
                ADDRESS_LABELS_MAP_KEY.to_string(),
                serde_json::to_value(addr_labels)?,
            ),
            (
                INVOICE_LABELS_MAP_KEY.to_string(),
                serde_json::to_value(inv_labels)?,
            ),
        ];
        self.set(to_set)?;

        // then delete actual label
        let contact_key = get_contact_key(&id);
        let label_item_key = get_label_item_key(&id);
        self.delete(&[contact_key, label_item_key])?;
        Ok(())
    }

    fn edit_contact(&self, id: impl AsRef<str>, contact: Contact) -> Result<(), MutinyError> {
        self.set_data(get_contact_key(&id), contact, None)
    }

    fn get_tag_items(&self) -> Result<Vec<TagItem>, MutinyError> {
        let mut tag_items = vec![];

        // Get all the contacts
        let contacts = self.get_contacts()?;
        // Get all the labels
        let mut labels = self.get_labels()?;

        // filter out labels that have a contact
        labels.retain(|label, _| contacts.get(label).is_none());

        // Convert the labels into tag items
        tag_items.extend(
            labels
                .into_iter()
                .map(|(label, label_item)| TagItem::Label((label, label_item))),
        );

        // Convert the contacts into tag items
        tag_items.extend(
            contacts
                .into_iter()
                .map(|(id, c)| TagItem::Contact((id, c))),
        );

        Ok(tag_items)
    }
}

impl<S: MutinyStorage> LabelStorage for MutinyWallet<S> {
    fn get_address_labels(&self) -> Result<HashMap<String, Vec<String>>, MutinyError> {
        self.storage.get_address_labels()
    }

    fn get_invoice_labels(&self) -> Result<HashMap<Bolt11Invoice, Vec<String>>, MutinyError> {
        self.storage.get_invoice_labels()
    }

    fn get_labels(&self) -> Result<HashMap<String, LabelItem>, MutinyError> {
        self.storage.get_labels()
    }

    fn get_label(&self, label: impl AsRef<str>) -> Result<Option<LabelItem>, MutinyError> {
        self.storage.get_label(label)
    }

    fn set_address_labels(&self, address: Address, labels: Vec<String>) -> Result<(), MutinyError> {
        self.storage.set_address_labels(address, labels)
    }

    fn set_invoice_labels(
        &self,
        invoice: Bolt11Invoice,
        labels: Vec<String>,
    ) -> Result<(), MutinyError> {
        self.storage.set_invoice_labels(invoice, labels)
    }

    fn get_contacts(&self) -> Result<HashMap<String, Contact>, MutinyError> {
        self.storage.get_contacts()
    }

    fn get_contact(&self, label: impl AsRef<str>) -> Result<Option<Contact>, MutinyError> {
        self.storage.get_contact(label)
    }

    fn create_contact_from_label(
        &self,
        label: impl AsRef<str>,
        contact: Contact,
    ) -> Result<String, MutinyError> {
        self.storage.create_contact_from_label(label, contact)
    }

    fn create_new_contact(&self, contact: Contact) -> Result<String, MutinyError> {
        self.storage.create_new_contact(contact)
    }

    fn delete_contact(&self, id: impl AsRef<str>) -> Result<(), MutinyError> {
        self.storage.delete_contact(id)
    }

    fn edit_contact(&self, id: impl AsRef<str>, contact: Contact) -> Result<(), MutinyError> {
        self.storage.edit_contact(id, contact)
    }

    fn get_tag_items(&self) -> Result<Vec<TagItem>, MutinyError> {
        self.storage.get_tag_items()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use bitcoin::Address;
    use itertools::Itertools;
    use lightning_invoice::Bolt11Invoice;
    use std::collections::HashMap;
    use std::str::FromStr;

    use crate::storage::MemoryStorage;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};
    wasm_bindgen_test_configure!(run_in_browser);

    const ADDRESS: &str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    const INVOICE: &str = "lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm";

    fn create_test_address_labels_map() -> HashMap<String, Vec<String>> {
        let mut labels = HashMap::new();
        labels.insert(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            vec!["test1".to_string()],
        );
        labels.insert(
            "1BitcoinEaterAddressDontSendf59kuE".to_string(),
            vec!["test2".to_string()],
        );
        labels.insert(
            "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S".to_string(),
            vec!["test3".to_string()],
        );
        labels
    }

    fn create_test_invoice_labels_map() -> HashMap<Bolt11Invoice, Vec<String>> {
        let mut labels = HashMap::new();
        labels.insert(
            Bolt11Invoice::from_str("lnbc923720n1pj9nrefpp5pczykgk37af5388n8dzynljpkzs7sje4melqgazlwv9y3apay8jqhp5rd8saxz3juve3eejq7z5fjttxmpaq88d7l92xv34n4h3mq6kwq2qcqzzsxqzfvsp5z0jwpehkuz9f2kv96h62p8x30nku76aj8yddpcust7g8ad0tr52q9qyyssqfy622q25helv8cj8hyxqltws4rdwz0xx2hw0uh575mn7a76cp3q4jcptmtjkjs4a34dqqxn8uy70d0qlxqleezv4zp84uk30pp5q3nqq4c9gkz").unwrap(),
            vec!["test1".to_string()],
        );
        labels.insert(
            Bolt11Invoice::from_str("lnbc923720n1pj9nre4pp58zjsgd3xkyj33wv6rfmsshg9hqdpqrh8dyaulzwg62x6h3qs39tqhp5vqcr4c3tnxyxr08rk28n8mkphe6c5gfusmyncpmdh604trq3cafqcqzzsxqzfvsp5un4ey9rh0pl23648xtng2k6gtw7w2p6ldaexl6ylwcuhnsnxnsfs9qyyssqxnhr6jvdqfwr97qk7dtsnqaps78r7fjlpyz5z57r2k70az5tvvss4tpucycqpph8gx0vxxr7xse442zf8wxlskln8n77qkd4kad4t5qp92lvrm").unwrap(),
            vec!["test2".to_string()],
        );
        labels.insert(
            Bolt11Invoice::from_str("lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm").unwrap(),
            vec!["test3".to_string()],
        );
        labels
    }

    fn create_test_labels() -> HashMap<String, LabelItem> {
        let mut labels = HashMap::new();
        labels.insert(
            "test1".to_string(),
            LabelItem {
                addresses: HashSet::from_iter(vec![
                    "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string()
                ]),
                ..Default::default()
            },
        );
        labels.insert(
            "test2".to_string(),
            LabelItem {
                addresses: HashSet::from_iter(vec!["1BitcoinEaterAddressDontSendf59kuE".to_string()]),
                invoices: HashSet::from_iter(vec![Bolt11Invoice::from_str("lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm").unwrap()]),
                ..Default::default()
            },
        );
        labels.insert(
            "test3".to_string(),
            LabelItem {
                addresses: HashSet::from_iter(vec![
                    "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S".to_string()
                ]),
                ..Default::default()
            },
        );
        labels
    }

    fn create_test_contacts() -> HashMap<String, Contact> {
        let mut labels = HashMap::new();

        labels.insert(
            Uuid::new_v4().to_string(),
            Contact {
                name: "Satoshi Nakamoto".to_string(),
                npub: None,
                ln_address: None,
                lnurl: None,
                image_url: None,
                last_used: 0,
            },
        );
        labels.insert(
            Uuid::new_v4().to_string(),
            Contact {
                name: "Hal Finney".to_string(),
                npub: None,
                ln_address: None,
                lnurl: None,
                image_url: None,
                last_used: 0,
            },
        );
        labels.insert(
            Uuid::new_v4().to_string(),
            Contact {
                name: "Nick Szabo".to_string(),
                npub: None,
                ln_address: None,
                lnurl: None,
                image_url: None,
                last_used: 0,
            },
        );

        labels
    }

    #[test]
    async fn test_get_address_labels() {
        let test_name = "test_get_address_labels";
        log!("{}", test_name);

        let storage = MemoryStorage::default();
        let labels_map = create_test_address_labels_map();
        storage
            .set_data(ADDRESS_LABELS_MAP_KEY.to_string(), labels_map.clone(), None)
            .unwrap();

        let result = storage.get_address_labels();
        assert_eq!(result.unwrap(), labels_map);
    }

    #[test]
    async fn test_get_invoice_labels() {
        let test_name = "test_get_invoice_labels";
        log!("{}", test_name);

        let storage = MemoryStorage::default();
        let labels_map = create_test_invoice_labels_map();
        storage
            .set_data(INVOICE_LABELS_MAP_KEY.to_string(), labels_map.clone(), None)
            .unwrap();

        let result = storage.get_invoice_labels();
        assert_eq!(result.unwrap(), labels_map);
    }

    #[test]
    async fn test_get_labels() {
        let test_name = "test_get_labels";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let labels = create_test_labels();
        for (label, label_item) in labels.clone() {
            storage
                .set_data(get_label_item_key(label), label_item, None)
                .unwrap();
        }

        let result = storage.get_labels().unwrap();

        // convert to vectors and sort for comparison
        let mut result: Vec<(String, LabelItem)> = result.into_iter().collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        let mut labels: Vec<(String, LabelItem)> = labels.into_iter().collect();
        labels.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(result, labels);
    }

    #[test]
    async fn test_get_label() {
        let test_name = "test_get_label";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let labels = create_test_labels();
        for (label, label_item) in labels.clone() {
            storage
                .set_data(get_label_item_key(label), label_item, None)
                .unwrap();
        }

        let label = "test_label".to_string();
        let result = storage.get_label(&label);
        assert_eq!(result.unwrap(), labels.get(&label).cloned());
    }

    #[test]
    async fn test_set_address_labels() {
        let test_name = "test_set_address_labels";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let address = Address::from_str(ADDRESS).unwrap().assume_checked();
        let labels = vec!["label1".to_string(), "label2".to_string()];

        let result = storage.set_address_labels(address.clone(), labels.clone());
        assert!(result.is_ok());

        let address_labels = storage.get_address_labels().unwrap();
        assert_eq!(address_labels.get(&address.to_string()), Some(&labels));
    }

    #[test]
    async fn test_set_invoice_labels() {
        let test_name = "test_set_invoice_labels";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let invoice = Bolt11Invoice::from_str(INVOICE).unwrap();
        let labels = vec!["label1".to_string(), "label2".to_string()];

        let result = storage.set_invoice_labels(invoice.clone(), labels.clone());
        assert!(result.is_ok());

        let invoice_labels = storage.get_invoice_labels().unwrap();
        assert_eq!(invoice_labels.get(&invoice), Some(&labels));
    }

    #[test]
    async fn test_get_contacts() {
        let test_name = "test_get_contacts";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let contacts = create_test_contacts();
        for (id, contact) in contacts.clone() {
            storage
                .set_data(get_contact_key(id), contact, None)
                .unwrap();
        }

        let result = storage.get_contacts().unwrap();

        // convert to vectors and sort for comparison
        let mut result: Vec<(String, Contact)> = result.into_iter().collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        let mut contacts: Vec<(String, Contact)> = contacts.into_iter().collect();
        contacts.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(result, contacts);
    }

    #[test]
    async fn test_get_contact() {
        let test_name = "test_get_contact";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let contact = Contact {
            name: "Satoshi Nakamoto".to_string(),
            npub: None,
            ln_address: None,
            lnurl: None,
            image_url: None,
            last_used: 0,
        };
        let id = storage.create_new_contact(contact.clone()).unwrap();

        let result = storage.get_contact(id).unwrap();
        assert_eq!(result.unwrap(), contact);
    }

    #[test]
    fn test_edit_contact() {
        let test_name = "test_edit_contact";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let contact = Contact {
            name: "Satoshi Nakamoto".to_string(),
            npub: None,
            ln_address: None,
            lnurl: None,
            image_url: None,
            last_used: 0,
        };
        let id = storage.create_new_contact(contact).unwrap();

        let mut contact = storage.get_contact(&id).unwrap().unwrap();
        contact.name = "Satoshi Nakamoto 2".to_string();
        storage.edit_contact(&id, contact.clone()).unwrap();

        let result = storage.get_contact(&id).unwrap();
        assert_eq!(result.unwrap(), contact);
    }

    #[test]
    fn test_delete_contact() {
        let test_name = "test_delete_contact";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let contact = Contact {
            name: "Satoshi Nakamoto".to_string(),
            npub: None,
            ln_address: None,
            lnurl: None,
            image_url: None,
            last_used: 0,
        };
        let id = storage.create_new_contact(contact).unwrap();
        let contact = storage.get_contact(&id).unwrap();
        assert!(contact.is_some());

        // set labels for invoice and address
        let invoice = Bolt11Invoice::from_str(INVOICE).unwrap();
        storage
            .set_invoice_labels(invoice.clone(), vec![id.clone()])
            .unwrap();
        let address = Address::from_str(ADDRESS).unwrap().assume_checked();
        storage
            .set_address_labels(address, vec![id.clone()])
            .unwrap();

        // delete contact
        storage.delete_contact(&id).unwrap();

        // make sure it is deleted
        let result = storage.get_contact(&id).unwrap();
        assert!(result.is_none());
        let contacts = storage.get_contacts().unwrap();
        assert!(contacts.get(&id).is_none());

        // check invoice labels are empty
        let inv_labels = storage.get_invoice_labels().unwrap();
        let labels = inv_labels.get(&invoice).cloned().unwrap_or_default();
        assert!(labels.is_empty());

        // check address labels are empty
        let addr_labels = storage.get_address_labels().unwrap();
        let labels = addr_labels.get(ADDRESS).cloned().unwrap_or_default();
        assert!(labels.is_empty());
    }

    #[test]
    async fn test_create_contact_from_label() {
        let test_name = "test_create_contact_from_label";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let address = Address::from_str(ADDRESS).unwrap().assume_checked();
        let invoice = Bolt11Invoice::from_str(INVOICE).unwrap();
        let label = "test_label".to_string();
        let other_label = "other_label".to_string();
        let contact = create_test_contacts().iter().next().unwrap().1.to_owned();

        storage
            .set_address_labels(address.clone(), vec![label.clone(), other_label.clone()])
            .unwrap();

        storage
            .set_invoice_labels(invoice.clone(), vec![label.clone(), other_label.clone()])
            .unwrap();

        let new_label = storage
            .create_contact_from_label(&label, contact.clone())
            .unwrap();

        let stored_contact = storage.get_contact(&new_label).unwrap();
        assert_eq!(stored_contact, Some(contact));

        let label_item = storage.get_label(&new_label).unwrap();
        assert!(label_item.is_some());
        assert_eq!(
            label_item
                .clone()
                .unwrap()
                .invoices
                .into_iter()
                .collect_vec(),
            vec![invoice]
        );
        assert_eq!(
            label_item.unwrap().addresses.into_iter().collect_vec(),
            vec![address.to_string()]
        );

        // check we properly converted the old label to a new label
        // check we also kept the other label
        let address_labels = storage.get_address_labels().unwrap();
        for (_, labels) in address_labels {
            assert!(!labels.contains(&label));
            assert!(labels.contains(&new_label));
            assert!(labels.contains(&other_label));
        }
        let invoice_labels = storage.get_invoice_labels().unwrap();
        for (_, labels) in invoice_labels {
            assert!(!labels.contains(&label));
            assert!(labels.contains(&new_label));
            assert!(labels.contains(&other_label));
        }

        // verify we deleted the old label
        let label_item = storage.get_label(&label).unwrap();
        assert!(label_item.is_none());
    }

    #[test]
    async fn test_create_new_contact() {
        let test_name = "test_create_new_contact";
        log!("{}", test_name);

        let storage = MemoryStorage::default();

        let contact = create_test_contacts().iter().next().unwrap().1.to_owned();

        let result = storage.create_new_contact(contact.clone());
        assert!(result.is_ok());

        let id = result.unwrap();
        let stored_contact = storage.get_contact(id).unwrap();
        assert_eq!(stored_contact, Some(contact));
    }

    #[test]
    async fn test_get_tag_items() {
        let test_name = "test_get_tag_items";
        log!("{}", test_name);

        let mut expected_tag_items = Vec::new();
        let storage = MemoryStorage::default();

        let contacts = create_test_contacts().into_values();
        for contact in contacts {
            let id = storage.create_new_contact(contact.clone()).unwrap();
            expected_tag_items.push(TagItem::Contact((id, contact)));
        }

        let labels = create_test_labels();
        for (label, label_item) in labels {
            storage
                .set_data(get_label_item_key(label.clone()), label_item.clone(), None)
                .unwrap();
            expected_tag_items.push(TagItem::Label((label, label_item)));
        }

        let result = storage.get_tag_items().unwrap();

        // check they have same items
        if result.len() != expected_tag_items.len() {
            panic!("Incorrect tag items length")
        }

        for item in expected_tag_items {
            if !result.contains(&item) {
                panic!("Tag item missing! {item:?}")
            }
        }
    }

    #[test]
    async fn test_labeling_contact_with_address() {
        let test_name = "test_labeling_contact_with_address";
        log!("{test_name}");

        let storage = MemoryStorage::default();

        let contacts = create_test_contacts();
        let contact = contacts.iter().next().unwrap().1.to_owned();
        assert_eq!(contact.last_used, 0);
        let id = storage.create_new_contact(contact.clone()).unwrap();

        let address = Address::from_str(ADDRESS).unwrap().assume_checked();

        storage
            .set_address_labels(address, vec![id.clone()])
            .unwrap();

        // check that the contact was updated
        let contact = storage.get_contact(&id).unwrap().unwrap();
        assert_ne!(contact.last_used, 0)
    }

    #[test]
    async fn test_labeling_contact_with_invoice() {
        let test_name = "test_labeling_contact_with_invoice";
        log!("{test_name}");

        let storage = MemoryStorage::default();

        let contacts = create_test_contacts();
        let contact = contacts.iter().next().unwrap().1.to_owned();
        assert_eq!(contact.last_used, 0);
        let id = storage.create_new_contact(contact.clone()).unwrap();

        let invoice = Bolt11Invoice::from_str(INVOICE).unwrap();

        storage
            .set_invoice_labels(invoice, vec![id.clone()])
            .unwrap();

        // check that the contact was updated
        let contact = storage.get_contact(&id).unwrap().unwrap();
        assert_ne!(contact.last_used, 0)
    }
}
