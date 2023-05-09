use crate::error::MutinyError;
use crate::indexed_db::MutinyStorage;
use crate::nodemanager::NodeManager;
use bitcoin::{Address, XOnlyPublicKey};
use lightning_invoice::Invoice;
use lnurl::lightning_address::LightningAddress;
use lnurl::lnurl::LnUrl;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

const ADDRESS_LABELS_MAP_KEY: &str = "address_labels";
const INVOICE_LABELS_MAP_KEY: &str = "invoice_labels";
const LABEL_PREFIX: &str = "label/";
const CONTACT_PREFIX: &str = "contact/";

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd, Hash, Default)]
pub struct LabelItem {
    /// List of addresses that have this label
    pub addresses: Vec<Address>,
    /// List of invoices that have this label
    pub invoices: Vec<String>, // fixme: use Invoice type after https://github.com/lightningdevkit/rust-lightning/pull/2279
    /// Epoch time in seconds when this label was last used
    pub last_used_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Contact {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npub: Option<XOnlyPublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ln_address: Option<LightningAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lnurl: Option<LnUrl>,
    pub last_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub enum TagItem {
    Label((String, LabelItem)),
    Contact((String, Contact)),
}

fn get_label_item_key(label: impl AsRef<str>) -> String {
    format!("{}{}", LABEL_PREFIX, label.as_ref())
}

fn get_contact_key(label: impl AsRef<str>) -> String {
    format!("{}{}", CONTACT_PREFIX, label.as_ref())
}

pub trait LabelStorage {
    /// Get a map of addresses to labels. This can be used to get all the labels for an address
    fn get_address_labels(&self) -> Result<HashMap<Address, Vec<String>>, MutinyError>;
    /// Get a map of invoices to labels. This can be used to get all the labels for an invoice
    fn get_invoice_labels(&self) -> Result<HashMap<Invoice, Vec<String>>, MutinyError>;
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
    fn set_invoice_labels(&self, invoice: Invoice, labels: Vec<String>) -> Result<(), MutinyError>;
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
    /// Gets all the existing tags (labels and contacts)
    fn get_tag_items(&self) -> Result<Vec<TagItem>, MutinyError>;
}

impl LabelStorage for MutinyStorage {
    fn get_address_labels(&self) -> Result<HashMap<Address, Vec<String>>, MutinyError> {
        let res: Option<HashMap<Address, Vec<String>>> = self.get(ADDRESS_LABELS_MAP_KEY)?;
        Ok(res.unwrap_or_default()) // if no labels exist, return an empty map
    }

    fn get_invoice_labels(&self) -> Result<HashMap<Invoice, Vec<String>>, MutinyError> {
        let res: Option<HashMap<Invoice, Vec<String>>> = self.get(INVOICE_LABELS_MAP_KEY)?;
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
        self.get(key)
    }

    fn set_address_labels(&self, address: Address, labels: Vec<String>) -> Result<(), MutinyError> {
        // update the labels map
        let mut address_labels = self.get_address_labels()?;
        address_labels.insert(address.clone(), labels.clone());
        self.set(ADDRESS_LABELS_MAP_KEY, address_labels)?;

        // update the label items
        let now = crate::utils::now().as_secs();
        for label in labels {
            let key = get_label_item_key(&label);
            match self.get_label(label)? {
                Some(mut label_item) => {
                    // Add the address to the label item
                    // and sort so we can dedup the addresses
                    label_item.addresses.push(address.clone());
                    label_item.addresses.sort();
                    label_item.addresses.dedup();

                    // Update the last used timestamp
                    label_item.last_used_time = now;

                    self.set(key, label_item)?;
                }
                None => {
                    // Create a new label item
                    let label_item = LabelItem {
                        addresses: vec![address.clone()],
                        invoices: vec![],
                        last_used_time: now,
                    };
                    self.set(key, label_item)?;
                }
            }
        }

        Ok(())
    }

    fn set_invoice_labels(&self, invoice: Invoice, labels: Vec<String>) -> Result<(), MutinyError> {
        // update the labels map
        let mut invoice_labels = self.get_invoice_labels()?;
        invoice_labels.insert(invoice.clone(), labels.clone());
        self.set(INVOICE_LABELS_MAP_KEY, invoice_labels)?;

        // update the label items
        let now = crate::utils::now().as_secs();
        for label in labels {
            let key = get_label_item_key(&label);
            match self.get_label(label)? {
                Some(mut label_item) => {
                    // Add the invoice to the label item
                    // and sort so we can dedup the invoices
                    label_item.invoices.push(invoice.to_string());
                    label_item.invoices.sort();
                    label_item.invoices.dedup();

                    // Update the last used timestamp
                    label_item.last_used_time = now;

                    self.set(key, label_item)?;
                }
                None => {
                    // Create a new label item
                    let label_item = LabelItem {
                        addresses: vec![],
                        invoices: vec![invoice.to_string()],
                        last_used_time: now,
                    };
                    self.set(key, label_item)?;
                }
            }
        }

        Ok(())
    }

    fn get_contacts(&self) -> Result<HashMap<String, Contact>, MutinyError> {
        let all = self.scan(CONTACT_PREFIX, None)?;
        // remove the prefix from the keys
        let mut contacts = HashMap::new();
        for (key, contact) in all {
            let label = key.replace(CONTACT_PREFIX, "");
            contacts.insert(label, contact);
        }

        Ok(contacts)
    }

    fn get_contact(&self, label: impl AsRef<str>) -> Result<Option<Contact>, MutinyError> {
        self.get(get_contact_key(label))
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
                self.set(get_label_item_key(&id), current)?;

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
                self.set(ADDRESS_LABELS_MAP_KEY, updated)?;

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
                self.set(INVOICE_LABELS_MAP_KEY, updated)?;

                // create the contact
                let key = get_contact_key(&id);
                self.set(key, contact)?;

                // delete old label item
                self.delete(get_label_item_key(&label))?;
                Ok(id)
            }
        }
    }

    /// Create a new contact and return the identifying label
    fn create_new_contact(&self, contact: Contact) -> Result<String, MutinyError> {
        // generate a uuid, this will be the "label" that we use to store the contact
        let id = Uuid::new_v4().to_string();
        let key = get_contact_key(&id);
        self.set(key, contact)?;
        Ok(id)
    }

    fn get_tag_items(&self) -> Result<Vec<TagItem>, MutinyError> {
        let mut tag_items = vec![];

        // Get all the contacts
        let mut contacts = self.get_contacts()?;
        // Get all the labels
        let mut labels = self.get_labels()?;

        // filter out contacts that have a label
        contacts.retain(|label, _| labels.get(label).is_none());
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

impl LabelStorage for NodeManager {
    fn get_address_labels(&self) -> Result<HashMap<Address, Vec<String>>, MutinyError> {
        self.storage.get_address_labels()
    }

    fn get_invoice_labels(&self) -> Result<HashMap<Invoice, Vec<String>>, MutinyError> {
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

    fn set_invoice_labels(&self, invoice: Invoice, labels: Vec<String>) -> Result<(), MutinyError> {
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

    fn get_tag_items(&self) -> Result<Vec<TagItem>, MutinyError> {
        self.storage.get_tag_items()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Address;
    use lightning_invoice::Invoice;
    use std::collections::HashMap;
    use std::str::FromStr;

    use crate::test_utils::cleanup_all;
    use wasm_bindgen_test::{wasm_bindgen_test as test, wasm_bindgen_test_configure};
    wasm_bindgen_test_configure!(run_in_browser);

    fn create_test_address_labels_map() -> HashMap<Address, Vec<String>> {
        let mut labels = HashMap::new();
        labels.insert(
            Address::from_str("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap(),
            vec!["test1".to_string()],
        );
        labels.insert(
            Address::from_str("1BitcoinEaterAddressDontSendf59kuE").unwrap(),
            vec!["test2".to_string()],
        );
        labels.insert(
            Address::from_str("12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S").unwrap(),
            vec!["test3".to_string()],
        );
        labels
    }

    fn create_test_invoice_labels_map() -> HashMap<Invoice, Vec<String>> {
        let mut labels = HashMap::new();
        labels.insert(
            Invoice::from_str("lnbc923720n1pj9nrefpp5pczykgk37af5388n8dzynljpkzs7sje4melqgazlwv9y3apay8jqhp5rd8saxz3juve3eejq7z5fjttxmpaq88d7l92xv34n4h3mq6kwq2qcqzzsxqzfvsp5z0jwpehkuz9f2kv96h62p8x30nku76aj8yddpcust7g8ad0tr52q9qyyssqfy622q25helv8cj8hyxqltws4rdwz0xx2hw0uh575mn7a76cp3q4jcptmtjkjs4a34dqqxn8uy70d0qlxqleezv4zp84uk30pp5q3nqq4c9gkz").unwrap(),
            vec!["test1".to_string()],
        );
        labels.insert(
            Invoice::from_str("lnbc923720n1pj9nre4pp58zjsgd3xkyj33wv6rfmsshg9hqdpqrh8dyaulzwg62x6h3qs39tqhp5vqcr4c3tnxyxr08rk28n8mkphe6c5gfusmyncpmdh604trq3cafqcqzzsxqzfvsp5un4ey9rh0pl23648xtng2k6gtw7w2p6ldaexl6ylwcuhnsnxnsfs9qyyssqxnhr6jvdqfwr97qk7dtsnqaps78r7fjlpyz5z57r2k70az5tvvss4tpucycqpph8gx0vxxr7xse442zf8wxlskln8n77qkd4kad4t5qp92lvrm").unwrap(),
            vec!["test2".to_string()],
        );
        labels.insert(
            Invoice::from_str("lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm").unwrap(),
            vec!["test3".to_string()],
        );
        labels
    }

    fn create_test_labels() -> HashMap<String, LabelItem> {
        let mut labels = HashMap::new();
        labels.insert(
            "test1".to_string(),
            LabelItem {
                addresses: vec![Address::from_str("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap()],
                ..Default::default()
            },
        );
        labels.insert(
            "test2".to_string(),
            LabelItem {
                addresses: vec![Address::from_str("1BitcoinEaterAddressDontSendf59kuE").unwrap()],
                invoices: vec!["lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm".to_string()],
                ..Default::default()
            },
        );
        labels.insert(
            "test3".to_string(),
            LabelItem {
                addresses: vec![Address::from_str("12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S").unwrap()],
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
                last_used: 0,
            },
        );

        labels
    }

    #[test]
    async fn test_get_address_labels() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let labels_map = create_test_address_labels_map();
        storage
            .set(ADDRESS_LABELS_MAP_KEY, labels_map.clone())
            .unwrap();

        let result = storage.get_address_labels();
        assert_eq!(result.unwrap(), labels_map);

        cleanup_all().await;
    }

    #[test]
    async fn test_get_invoice_labels() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let labels_map = create_test_invoice_labels_map();
        storage
            .set(INVOICE_LABELS_MAP_KEY, labels_map.clone())
            .unwrap();

        let result = storage.get_invoice_labels();
        assert_eq!(result.unwrap(), labels_map);

        cleanup_all().await;
    }

    #[test]
    async fn test_get_labels() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let labels = create_test_labels();
        for (label, label_item) in labels.clone() {
            storage.set(get_label_item_key(label), label_item).unwrap();
        }

        let result = storage.get_labels().unwrap();

        // convert to vectors and sort for comparison
        let mut result: Vec<(String, LabelItem)> = result.into_iter().collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        let mut labels: Vec<(String, LabelItem)> = labels.into_iter().collect();
        labels.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(result, labels);

        cleanup_all().await;
    }

    #[test]
    async fn test_get_label() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let labels = create_test_labels();
        for (label, label_item) in labels.clone() {
            storage.set(get_label_item_key(label), label_item).unwrap();
        }

        let label = "test_label".to_string();
        let result = storage.get_label(&label);
        assert_eq!(result.unwrap(), labels.get(&label).cloned());

        cleanup_all().await;
    }

    #[test]
    async fn test_set_address_labels() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let address = Address::from_str("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        let labels = vec!["label1".to_string(), "label2".to_string()];

        let result = storage.set_address_labels(address.clone(), labels.clone());
        assert!(result.is_ok());

        let address_labels = storage.get_address_labels().unwrap();
        assert_eq!(address_labels.get(&address), Some(&labels));

        cleanup_all().await;
    }

    #[test]
    async fn test_set_invoice_labels() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let invoice = Invoice::from_str("lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm").unwrap();
        let labels = vec!["label1".to_string(), "label2".to_string()];

        let result = storage.set_invoice_labels(invoice.clone(), labels.clone());
        assert!(result.is_ok());

        let invoice_labels = storage.get_invoice_labels().unwrap();
        assert_eq!(invoice_labels.get(&invoice), Some(&labels));

        cleanup_all().await;
    }

    #[test]
    async fn test_get_contacts() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let contacts = create_test_contacts();
        for (id, contact) in contacts.clone() {
            storage.set(get_contact_key(id), contact).unwrap();
        }

        let result = storage.get_contacts().unwrap();

        // convert to vectors and sort for comparison
        let mut result: Vec<(String, Contact)> = result.into_iter().collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        let mut contacts: Vec<(String, Contact)> = contacts.into_iter().collect();
        contacts.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(result, contacts);

        cleanup_all().await;
    }

    #[test]
    async fn test_get_contact() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let contact = Contact {
            name: "Satoshi Nakamoto".to_string(),
            npub: None,
            ln_address: None,
            lnurl: None,
            last_used: 0,
        };
        let id = storage.create_new_contact(contact.clone()).unwrap();

        let result = storage.get_contact(&id).unwrap();
        assert_eq!(result.unwrap(), contact);

        cleanup_all().await;
    }

    #[test]
    async fn test_create_contact_from_label() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let address = Address::from_str("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        let invoice = Invoice::from_str("lnbc923720n1pj9nr6zpp5xmvlq2u5253htn52mflh2e6gn7pk5ht0d4qyhc62fadytccxw7hqhp5l4s6qwh57a7cwr7zrcz706qx0qy4eykcpr8m8dwz08hqf362egfscqzzsxqzfvsp5pr7yjvcn4ggrf6fq090zey0yvf8nqvdh2kq7fue0s0gnm69evy6s9qyyssqjyq0fwjr22eeg08xvmz88307yqu8tqqdjpycmermks822fpqyxgshj8hvnl9mkh6srclnxx0uf4ugfq43d66ak3rrz4dqcqd23vxwpsqf7dmhm").unwrap();
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
            label_item.clone().unwrap().invoices,
            vec![invoice.to_string()]
        );
        assert_eq!(label_item.unwrap().addresses, vec![address]);

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

        cleanup_all().await;
    }

    #[test]
    async fn test_create_new_contact() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let contact = create_test_contacts().iter().next().unwrap().1.to_owned();

        let result = storage.create_new_contact(contact.clone());
        assert!(result.is_ok());

        let id = result.unwrap();
        let stored_contact = storage.get_contact(id).unwrap();
        assert_eq!(stored_contact, Some(contact));

        cleanup_all().await;
    }

    #[test]
    async fn test_get_tag_items() {
        let storage = MutinyStorage::new("".to_string()).await.unwrap();
        let contacts = create_test_contacts();
        for (id, contact) in contacts.clone() {
            storage.set(get_contact_key(id), contact).unwrap();
        }

        let labels = create_test_labels();
        for (label, label_item) in labels.clone() {
            storage.set(get_label_item_key(label), label_item).unwrap();
        }

        let mut result = storage.get_tag_items().unwrap();
        let mut expected_tag_items = Vec::new();

        // Add expected Label tag items
        for (label, label_item) in labels {
            expected_tag_items.push(TagItem::Label((label, label_item)));
        }

        // Add expected Contact tag items
        for (id, contact) in contacts {
            expected_tag_items.push(TagItem::Contact((id, contact.clone())));
        }

        // Sort the resulting vectors to ensure proper comparison
        result.sort();
        expected_tag_items.sort();

        assert_eq!(result, expected_tag_items);

        cleanup_all().await;
    }
}
