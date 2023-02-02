use anyhow::{anyhow, Result};
use ripemd::Digest;
use ripemd::Ripemd160;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;

#[derive(Deserialize, Clone)]
pub struct Block {
    pub hash: String,
    pub height: u64,
    pub tx: Vec<String>,
}

#[derive(Deserialize, Clone)]
pub struct Transaction {
    pub txid: String,
    pub hash: String,
    pub version: u32,
    pub size: u32,
    pub vsize: u32,
    pub weight: u32,
    pub locktime: u32,
    pub vin: Vec<VIn>,
    pub vout: Vec<VOut>,
}

#[derive(Deserialize, Clone)]
pub struct VIn {
    pub txid: Option<String>,
    pub coinbase: Option<String>,
    pub txinwitness: Vec<String>,
    pub sequence: u32,
    pub vout: Option<u32>,
}

#[derive(Deserialize, Clone)]
pub struct ScriptSig {
    pub asm: String,
    pub hex: String,
}

#[derive(Deserialize, Clone)]
pub struct VOut {
    pub value: f64,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKey,
}

#[derive(Deserialize, Clone)]
pub struct ScriptPubKey {
    pub asm: String,
    pub hex: String,
    pub desc: String,
    pub r#type: String,
    pub address: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct JsonRpcBody {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: String,
}

impl JsonRpcBody {
    fn new(method: &str, params: Vec<serde_json::Value>) -> JsonRpcBody {
        JsonRpcBody {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: "wallet-rs".to_string(),
        }
    }
}
use std::env::var;

async fn create_raw_transaction() {
    // Version
    let version = "01000000";
    // Number of Inputs
    let tx_in_count = "01";

    // Previous Transaction ID
    let prev_tx_id = "671c26cf0d7bf8d056d783e5bb4f785eb28adbe12de112c1b9d9a0af118cf2a7";

    // Previous Transaction Reversed
    let mut prev_tx_rev = hex::decode(prev_tx_id).unwrap();
    prev_tx_rev.reverse();

    // Previous Output Index
    let prev_output_index = "00000000";

    //TODO: Script Length
    let script_length = "";

    //TODO: Script
    let script_sig = "";

    // Sequence
    let sequence = "ffffffff";

    // Number of Outputs
    let tx_out_count = "01";
}

async fn btc_json_rpc<T>(body: &Vec<JsonRpcBody>) -> Result<Vec<T>>
where
    T: DeserializeOwned,
{
    let client = reqwest::Client::new();

    let url = var("BTC_JSON_RPC_URL").expect("BTC_JSON_RPC_URL is not set");
    let user = var("BTC_JSON_RPC_USER").expect("BTC_JSON_RPC_USER is not set");
    let password = var("BTC_JSON_RPC_PASSWORD").expect("BTC_JSON_RPC_PASSWORD is not set");

    let json = client
        .post(url)
        .basic_auth(user, Some(password))
        .json(body)
        .send()
        .await?
        .json::<Vec<serde_json::Value>>()
        .await?;

    let results = json
        .into_iter()
        .filter_map(|j| serde_json::from_value(j["result"].clone()).ok())
        .collect();

    Ok(results)
}

async fn get_block_count() -> Result<u64> {
    let body = vec![JsonRpcBody::new("getblockcount", vec![])];
    let count: Vec<u64> = btc_json_rpc(&body).await?;
    Ok(count[0])
}

async fn get_block_hashes(block_heights: Vec<u64>) -> Result<Vec<String>> {
    let body: Vec<JsonRpcBody> = block_heights
        .into_iter()
        .map(|block_height| JsonRpcBody::new("getblockhash", vec![block_height.into()]))
        .collect();

    let hashes: Vec<String> = btc_json_rpc(&body).await?;
    Ok(hashes)
}

async fn get_block_hash(block_height: u64) -> Result<String> {
    Ok(get_block_hashes(vec![block_height])
        .await?
        .get(0)
        .ok_or_else(|| anyhow!("no block_hash found for block_height {}", block_height))?
        .clone())
}

async fn get_block(block_hash: &str) -> Result<Block> {
    Ok(get_blocks(vec![block_hash.to_string()])
        .await?
        .get(0)
        .ok_or_else(|| anyhow!("no block found for {}", block_hash))?
        .clone())
}

async fn get_blocks(block_hashes: Vec<String>) -> Result<Vec<Block>> {
    let body: Vec<JsonRpcBody> = block_hashes
        .into_iter()
        .map(|block_hash| JsonRpcBody::new("getblock", vec![block_hash.into()]))
        .collect();
    let blocks: Vec<Block> = btc_json_rpc(&body).await?;
    Ok(blocks)
}

async fn get_transaction(txid: &str) -> Result<Transaction> {
    Ok(get_transactions(vec![txid.to_string()])
        .await?
        .get(0)
        .ok_or_else(|| anyhow!("no transaction found for {}", txid))?
        .clone())
}

async fn get_transactions(txids: Vec<String>) -> Result<Vec<Transaction>> {
    let body: Vec<JsonRpcBody> = txids
        .into_iter()
        .map(|txid| JsonRpcBody::new("getrawtransaction", vec![txid.into(), true.into()]))
        .collect();

    let txs: Vec<Transaction> = btc_json_rpc(&body).await?;
    Ok(txs)
}

async fn get_transactions_by_address(address: &str) -> Result<Vec<Transaction>> {
    let block_count = get_block_count().await?;
    let block_hashes = get_block_hashes((0..block_count).collect()).await?;
    let blocks = get_blocks(block_hashes).await?;
    let txids: Vec<String> = blocks.into_iter().flat_map(|block| block.tx).collect();
    let txs = get_transactions(txids).await?;
    let txs = txs
        .into_iter()
        .filter(|tx| {
            tx.vout
                .iter()
                .any(|vout| vout.script_pub_key.address == Some(address.to_string()))
        })
        .collect();
    Ok(txs)
}

pub async fn get_tx_closest_to_amount(address: &str, amount: f64) -> Result<Transaction> {
    let mut txs = get_transactions_by_address(address).await?;
    txs.sort_by(|a, b| a.vout[0].value.partial_cmp(&b.vout[0].value).unwrap());
    let tx = txs
        .into_iter()
        .find(|tx| tx.vout[0].value >= amount)
        .ok_or_else(|| anyhow!("no transaction found for {}", address))?;
    Ok(tx)
}

pub async fn create_transaction(
    from_address: &str,
    to_address: &str,
    amount: f64,
) -> Result<String> {
    let tx = get_tx_closest_to_amount(from_address, amount).await?;
    let body = JsonRpcBody::new(
        "createrawtransaction",
        vec![
            vec![json!({
                "txid": tx.txid,
                "vout": 0,
            })]
            .into(),
            vec![json!({
                to_address: amount,
            })]
            .into(),
        ],
    );
    let tx: Vec<String> = btc_json_rpc(&vec![body]).await?;

    Ok(tx[0].clone())
}

pub async fn decode_raw_transaction(tx_hex: &str) -> Result<Transaction> {
    let body = JsonRpcBody::new("decoderawtransaction", vec![tx_hex.into()]);
    let tx: Vec<Transaction> = btc_json_rpc(&vec![body]).await?;
    Ok(tx[0].clone())
}

pub async fn send_transaction(signed_hex: &str) -> Result<String> {
    let body = JsonRpcBody::new("sendrawtransaction", vec![signed_hex.into()]);
    let txid: Vec<String> = btc_json_rpc(&vec![body]).await?;
    Ok(txid[0].clone())
}

pub async fn calculate_utxo(address: &str) -> Result<f64> {
    let mut utxo = 0.;
    let txs = get_transactions_by_address(address).await?;

    for tx in txs {
        for vout in tx.vout {
            utxo += vout.value;
        }
    }

    Ok(utxo)
}

fn sha256(input: &[u8]) -> Vec<u8> {
    let mut sha = Sha256::new();
    sha.update(input);
    let result = sha.finalize();
    result.to_vec()
}

fn hash160(input: &[u8]) -> Vec<u8> {
    let mut rip = Ripemd160::new();
    rip.update(input);
    let result = rip.finalize();
    result.to_vec()
}

fn btc_prefix(input: &[u8]) -> Vec<u8> {
    let mut prefix = vec![0x00];
    prefix.extend(input);
    prefix
}

fn testnet_btc_prefix(input: &[u8]) -> Vec<u8> {
    let mut prefix = vec![0x6f];
    prefix.extend(input);
    prefix
}

pub fn xpub_to_btc_address(public_key: &[u8], testnet: bool) -> String {
    let mut payload = hash160(&sha256(public_key));
    if testnet {
        payload = testnet_btc_prefix(&payload);
    } else {
        payload = btc_prefix(&payload);
    }

    let checksum = sha256(&sha256(&payload));
    payload.extend(checksum[0..4].to_vec());

    bs58::encode(&payload).into_string()
}

#[cfg(test)]
mod tests {
    use crate::{
        account::{Account, CoinType},
        get_seed,
    };

    use super::*;

    #[tokio::test]
    async fn test_get_block_count() -> anyhow::Result<()> {
        dotenvy::dotenv().ok();
        let count = get_block_count().await?;
        assert!(count > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_block_hash() -> anyhow::Result<()> {
        dotenvy::dotenv().ok();
        let hash = get_block_hash(1).await?;
        assert!(!hash.is_empty());
        Ok(())
    }
    #[tokio::test]
    async fn test_get_block_hashes() -> anyhow::Result<()> {
        dotenvy::dotenv().ok();
        let hash = get_block_hashes((1..10).collect()).await?;
        assert!(!hash.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_block() -> anyhow::Result<()> {
        dotenvy::dotenv().ok();
        let hash = get_block_hash(1).await?;
        let block = get_block(&hash).await?;
        assert_eq!(block.height, 1);
        assert_eq!(block.hash, hash);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_transaction() -> anyhow::Result<()> {
        dotenvy::dotenv().ok();
        let hash = get_block_hash(1).await?;
        let block = get_block(&hash).await?;
        let tx = get_transaction(&block.tx[0]).await?;
        assert_eq!(tx.txid, block.tx[0]);
        Ok(())
    }

    async fn get_test_address() -> anyhow::Result<String> {
        dotenvy::dotenv().ok();
        let seed = get_seed("password")?;
        let btc_testnet = Account::new(&seed, 0, CoinType::BitcoinTestnet)?;
        let address = btc_testnet.get_address()?;
        Ok(address)
    }

    #[tokio::test]
    async fn test_calculate_utxo() -> anyhow::Result<()> {
        let address = get_test_address().await?;
        let utxo = calculate_utxo(&address).await?;
        assert!(utxo > 0.);
        Ok(())
    }

    #[tokio::test]
    async fn test_create_transaction() -> anyhow::Result<()> {
        let address = get_test_address().await?;
        let hex = create_transaction(&address, &address, 0.0001).await?;
        assert!(!hex.is_empty());
        Ok(())
    }
}
