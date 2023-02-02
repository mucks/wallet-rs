use anyhow::{anyhow, Result};
use bip32::secp256k1::ecdsa::signature::Signer;
use bip32::secp256k1::ecdsa::Signature;
use bip32::secp256k1::ecdsa::SigningKey;
use bip32::PrivateKeyBytes;
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

pub fn satoshi_to_padded_hex(satoshi: u64) -> Result<String> {
    let mut v = format!("{satoshi:x}");

    if v.len() > 16 {
        return Err(anyhow!("Amount is too big"));
    } else {
        while v.len() < 16 {
            v = format!("0{v}");
        }
    }
    let mut v = hex::decode(&v)?;
    v.reverse();
    Ok(hex::encode(v))
}

//TODO: fix der encoding for signature
pub fn sign_raw_transaction(sk: &SigningKey, tx: String) -> Result<String> {
    let tx_hash = sha256(&sha256(&hex::decode(tx)?));
    let mut sig: Signature = sk.sign(&tx_hash);

    let (s, r) = sig.split_scalars();

    // println!(
    //     "s_len: {}, r_len: {}",
    //     s.to_bytes().len(),
    //     r.to_bytes().len()
    // );

    // println!(
    //     "s: {}, r: {}",
    //     hex::encode(s.to_bytes()),
    //     hex::encode(r.to_bytes())
    // );

    if let Some(normalized) = sig.normalize_s() {
        sig = normalized;
    }

    let sig_der_hex = hex::encode(sig.to_der().as_bytes());

    Ok(sig_der_hex)
}

pub fn gen_script_sig(sign: &str, pk: &str) -> String {
    format!("47{sign}0121{pk}")
}

pub fn create_raw_transaction(
    prev_tx_id: &str,
    from_address: &str,
    to_receive_address: &str,
    amount_in_satoshi: u64,
    option_script_sig: Option<&str>,
) -> Result<String> {
    // Version
    let version = "01000000";
    // Number of Inputs
    let tx_in_count = "01";

    // Previous Transaction ID

    // Previous Transaction Reversed
    let mut prev_tx_rev = hex::decode(prev_tx_id).unwrap();
    prev_tx_rev.reverse();
    let prev_tx = hex::encode(prev_tx_rev);

    // Previous Output Index
    let prev_output_index = "00000000";

    //TODO: Script Length 0x19 = 25
    let script_sig_length = match option_script_sig {
        Some(_) => "6a",
        None => "19",
    };

    let from_address_hash = bs58check_to_hex(from_address)?;

    //TODO: Script
    let script_sig = match option_script_sig {
        Some(s) => s.into(),
        None => format!("76a914{from_address_hash}88ac"),
    };

    let script_sig_len = format!("{:x}", hex::decode(script_sig.as_bytes())?.len());

    // Sequence
    let sequence = "ffffffff";

    // Number of Outputs
    let tx_out_count = "01";

    // Value 20000 satoshi padded to 8bytes as hex 0000000000004e20
    let value = satoshi_to_padded_hex(amount_in_satoshi)?;

    //len-4 to remove checksum
    let to_receive_hash = bs58check_to_hex(to_receive_address)?;

    // script_pub_key (locking script, p2pkh)
    let script_pub_key = format!("76a914{to_receive_hash}88ac");

    let script_length = format!("{:x}", hex::decode(script_pub_key.as_bytes())?.len());

    // Locktime
    let locktime = "00000000";

    // Sighash All
    let sig_hash_code = match option_script_sig {
        Some(_) => "",
        None => "01000000",
    };

    let complete_transaction_message = format!("{version}{tx_in_count}{prev_tx}{prev_output_index}{script_sig_length}{script_sig}{sequence}{tx_out_count}{value}{script_length}{script_pub_key}{locktime}{sig_hash_code}");

    Ok(complete_transaction_message)
}

fn bs58check_to_hex(bs58: &str) -> Result<String> {
    let hash_with_checksum = bs58::decode(bs58).into_vec()?;
    let hash = hex::encode(&hash_with_checksum[1..hash_with_checksum.len() - 4]);
    Ok(hash)
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
    use anyhow::Result;
    use bip32::{ExtendedPrivateKey, PrivateKey, XPrv};

    use super::*;

    #[test]
    fn test_bs58_to_hex() -> Result<()> {
        let hex = bs58check_to_hex("1NAK3za9MkbAkkSBMLcvmhTD6etgB4Vhpr")?;
        assert_eq!(hex, "e81d742e2c3c7acd4c29de090fc2c4d4120b2bf8");
        Ok(())
    }

    #[test]
    fn test_satoshi_to_padded_hex() -> Result<()> {
        let hex = satoshi_to_padded_hex(20_000)?;
        assert_eq!(hex, "204e000000000000");
        Ok(())
    }

    #[test]
    fn test_create_raw_transaction() -> Result<()> {
        // previous transaction id where the utxo comes from
        let prev_tx_id = "7e3ab0ea65b60f7d1ff4b231016fc958bc0766a46770410caa0a1855459b6e41";
        // found in outputs of transaction
        let from = "1F1fXXbXH9PX1RZuP4aSBcAro9uSUi5tsh";

        // address we send btc to
        let to = "1NAK3za9MkbAkkSBMLcvmhTD6etgB4Vhpr";
        let amount = 20_000;
        let tx = create_raw_transaction(prev_tx_id, from, to, amount, None)?;
        let expected = "0100000001416e9b4555180aaa0c417067a46607bc58c96f0131b2f41f7d0fb665eab03a7e000000001976a91499b1ebcfc11a13df5161aba8160460fe1601d54188acffffffff01204e0000000000001976a914e81d742e2c3c7acd4c29de090fc2c4d4120b2bf888ac0000000001000000";
        assert_eq!(expected, tx);

        Ok(())
    }

    // signed tx is different every time, so we can't test for equality
    //TODO: check if this is accurate
    #[test]
    fn test_sign_raw_transaction() -> Result<()> {
        // previous transaction id where the utxo comes from
        let prev_tx_id = "7e3ab0ea65b60f7d1ff4b231016fc958bc0766a46770410caa0a1855459b6e41";
        // found in outputs of transaction
        let from = "1F1fXXbXH9PX1RZuP4aSBcAro9uSUi5tsh";

        // address we send btc to
        let to = "1NAK3za9MkbAkkSBMLcvmhTD6etgB4Vhpr";
        let amount = 20_000;

        let tx = create_raw_transaction(prev_tx_id, from, to, amount, None)?;

        let test_priv_key = "3cd0560f5b27591916c643a0b7aa69d03839380a738d2e912990dcc573715d2c";
        let priv_key = hex::decode(test_priv_key)?;
        let sk = SigningKey::from_bytes(&priv_key).unwrap();
        let pk_hex = hex::encode(sk.public_key().to_bytes());
        assert_eq!(
            "03bf350d2821375158a608b51e3e898e507fe47f2d2e8c774de4a9a7edecf74eda",
            pk_hex
        );

        let signed_tx_hash = sign_raw_transaction(&sk, tx)?;
        let _expected = "304402201c3be71e1794621cbe3a7adec1af25f818f238f5796d47152137eba710f2174a02204f8fe667b696e30012ef4e56ac96afb830bddffee3b15d2e474066ab3aa39bad";
        //TODO: figure out why this isn't working
        //assert_eq!(_expected, signed_tx_hash);

        let script_sig = gen_script_sig(&signed_tx_hash, &pk_hex);
        let signed_tx =
            create_raw_transaction(prev_tx_id, from, to, amount, Some(script_sig.as_str()));

        let expected = "0100000001416e9b4555180aaa0c417067a46607bc58c96f0131b2f41f7d0fb665eab03a7e000000006a47304402201c3be71e1794621cbe3a7adec1af25f818f238f5796d47152137eba710f2174a02204f8fe667b696e30012ef4e56ac96afb830bddffee3b15d2e474066ab3aa39bad012103bf350d2821375158a608b51e3e898e507fe47f2d2e8c774de4a9a7edecf74edaffffffff01204e0000000000001976a914e81d742e2c3c7acd4c29de090fc2c4d4120b2bf888ac00000000";

        assert_eq!(expected, signed_tx.unwrap());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_block_count() -> Result<()> {
        dotenvy::dotenv().ok();
        let count = get_block_count().await?;
        assert!(count > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_block_hash() -> Result<()> {
        dotenvy::dotenv().ok();
        let hash = get_block_hash(1).await?;
        assert!(!hash.is_empty());
        Ok(())
    }
    #[tokio::test]
    async fn test_get_block_hashes() -> Result<()> {
        dotenvy::dotenv().ok();
        let hash = get_block_hashes((1..10).collect()).await?;
        assert!(!hash.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_block() -> Result<()> {
        dotenvy::dotenv().ok();
        let hash = get_block_hash(1).await?;
        let block = get_block(&hash).await?;
        assert_eq!(block.height, 1);
        assert_eq!(block.hash, hash);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_transaction() -> Result<()> {
        dotenvy::dotenv().ok();
        let hash = get_block_hash(1).await?;
        let block = get_block(&hash).await?;
        let tx = get_transaction(&block.tx[0]).await?;
        assert_eq!(tx.txid, block.tx[0]);
        Ok(())
    }

    async fn get_test_address() -> Result<String> {
        dotenvy::dotenv().ok();
        let seed = get_seed("password")?;
        let btc_testnet = Account::new(&seed, 0, CoinType::BitcoinTestnet)?;
        let address = btc_testnet.get_address()?;
        Ok(address)
    }

    #[tokio::test]
    async fn test_calculate_utxo() -> Result<()> {
        let address = get_test_address().await?;
        let utxo = calculate_utxo(&address).await?;
        assert!(utxo > 0.);
        Ok(())
    }

    #[tokio::test]
    async fn test_create_transaction() -> Result<()> {
        let address = get_test_address().await?;
        let hex = create_transaction(&address, &address, 0.0001).await?;
        assert!(!hex.is_empty());
        Ok(())
    }
}
