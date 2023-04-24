use bitcoin::secp256k1::PublicKey;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub(crate) struct LspClient {
    pub pubkey: PublicKey,
    pub connection_string: String,
    pub url: String,
    pub http_client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct GetInfoResponse {
    pub pubkey: PublicKey,
    pub connection_methods: Vec<GetInfoAddress>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct GetInfoAddress {
    #[serde(rename = "type")]
    pub item_type: GetInfoAddressType,
    pub port: u16,
    pub address: String,
}

/// Type of connection
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum GetInfoAddressType {
    Dns,
    IPV4,
    IPV6,
    TORV2,
    TORV3,
    Websocket,
}

#[derive(Serialize, Deserialize)]
pub struct ProposalRequest {
    pub bolt11: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct ProposalResponse {
    pub jit_bolt11: String,
}

#[derive(Serialize, Deserialize)]
pub struct FeeRequest {
    pub pubkey: String,
    pub amount_msat: u64,
}

#[derive(Serialize, Deserialize)]
pub struct FeeResponse {
    pub fee_amount_msat: u64,
}

const GET_INFO_PATH: &str = "/api/v1/info";
const PROPOSAL_PATH: &str = "/api/v1/proposal";
const FEE_PATH: &str = "/api/v1/fee";

impl LspClient {
    pub async fn new(url: &str) -> anyhow::Result<Self> {
        let http_client = Client::new();
        let get_info_response: GetInfoResponse = http_client
            .get(format!("{}{}", url, GET_INFO_PATH))
            .send()
            .await?
            .json()
            .await?;

        let connection_string = get_info_response
            .connection_methods
            .iter()
            .filter(|address| {
                matches!(
                    address.item_type,
                    GetInfoAddressType::IPV4 | GetInfoAddressType::IPV6 | GetInfoAddressType::TORV3
                )
            })
            .min_by_key(|address| match address.item_type {
                // Prioritize IPV4, then 6, then tor
                // TODO support websocket one day
                GetInfoAddressType::IPV4 => 0,
                GetInfoAddressType::IPV6 => 1,
                GetInfoAddressType::TORV3 => 2,
                _ => unreachable!(),
            })
            .map(|address| {
                format!(
                    "{}@{}:{}",
                    get_info_response.pubkey.to_string(),
                    address.address,
                    address.port
                )
            })
            .ok_or_else(|| anyhow::anyhow!("No suitable connection method found"))?;

        Ok(LspClient {
            pubkey: get_info_response.pubkey,
            url: String::from(url),
            connection_string,
            http_client,
        })
    }

    pub(crate) async fn get_lsp_invoice(&self, bolt11: String) -> anyhow::Result<String> {
        let payload = ProposalRequest {
            bolt11,
            host: None,
            port: None,
        };

        let proposal_response: ProposalResponse = self
            .http_client
            .post(format!("{}{}", &self.url, PROPOSAL_PATH))
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        Ok(proposal_response.jit_bolt11)
    }

    pub(crate) async fn get_lsp_fee_msat(&self, fee_request: FeeRequest) -> anyhow::Result<u64> {
        let fee_response: FeeResponse = self
            .http_client
            .post(format!("{}{}", &self.url, FEE_PATH))
            .json(&fee_request)
            .send()
            .await?
            .json()
            .await?;

        Ok(fee_response.fee_amount_msat)
    }
}
