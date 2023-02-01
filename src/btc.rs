use anyhow::Result;
use ripemd::Digest;
use ripemd::Ripemd160;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;

#[derive(Deserialize)]
pub struct Transaction {
    pub txid: String,
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<VIn>,
    pub vout: Vec<VOut>,
}

#[derive(Deserialize)]
pub struct VIn {
    pub coinbase: String,
    pub txinwitness: Vec<String>,
    pub sequence: u32,
}

#[derive(Deserialize)]
pub struct VOut {
    pub value: f64,
    pub n: u32,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: ScriptPubKey,
}

#[derive(Deserialize)]
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

async fn btc_json_rpc<S, T>(body: &S) -> Result<T>
where
    S: Serialize,
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
        .json::<serde_json::Value>()
        .await?;

    Ok(serde_json::from_value(json["result"].clone())?)
}

async fn get_block_count() -> Result<u64> {
    let body = JsonRpcBody::new("getblockcount", vec![]);
    let count: u64 = btc_json_rpc(&body).await?;
    Ok(count)
}

async fn get_block_hash(block_height: u64) -> Result<String> {
    let body = JsonRpcBody::new("getblockhash", vec![block_height.into()]);
    let hash: String = btc_json_rpc(&body).await?;
    Ok(hash)
}

#[derive(Deserialize)]
pub struct Block {
    pub hash: String,
    pub height: u64,
    pub tx: Vec<String>,
}

async fn get_block(block_hash: &str) -> Result<Block> {
    let body = JsonRpcBody::new("getblock", vec![block_hash.into()]);
    let block: Block = btc_json_rpc(&body).await?;

    Ok(block)
}

async fn get_transaction(txid: &str) -> Result<Transaction> {
    let body = JsonRpcBody::new("getrawtransaction", vec![txid.into(), true.into()]);
    let tx: Transaction = btc_json_rpc(&body).await?;
    Ok(tx)
}

fn calculate_utxo(address: &str) -> u32 {
    let mut utxo = 0;

    0
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
}
