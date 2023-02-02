use std::io::{Read, Write};
use std::path::Path;

use bip32::secp256k1::ecdsa::SigningKey;
use bip32::{ExtendedPrivateKey, Seed};
use bip32::{Mnemonic, XPrv};
use btc::create_raw_transaction;
use rand_core::OsRng;

use crate::account::{Account, CoinType};
use crate::btc::send_transaction;

mod account;
mod btc;
mod pkdf2;

fn create_seed() -> Seed {
    // Generate random Mnemonic using the default language (English)
    let mnemonic = Mnemonic::random(OsRng, Default::default());
    println!("Write down this phrase!\n{}\n", mnemonic.phrase());

    // seed phrase with empty salt
    mnemonic.to_seed("")
}

fn create_xpriv(seed: &Seed) -> anyhow::Result<ExtendedPrivateKey<SigningKey>> {
    // Derive the root `XPrv` from the `seed` value
    let root_xprv = XPrv::new(seed)?;
    Ok(root_xprv)
}

fn encrypt_and_backup_seed(seed: &Seed, password: &str) -> anyhow::Result<()> {
    let encrypted_seed = pkdf2::encrypt(password.as_bytes(), seed.as_bytes());
    let hex_encrypted_seed = hex::encode(encrypted_seed);

    let mut f = std::fs::File::create("seed.txt")?;
    f.write_all(hex_encrypted_seed.as_bytes())?;

    Ok(())
}

fn get_seed(password: &str) -> anyhow::Result<Seed> {
    if Path::exists(Path::new("seed.txt")) {
        let mut f = std::fs::File::open("seed.txt")?;
        let mut hex_encrypted_seed = String::new();
        f.read_to_string(&mut hex_encrypted_seed)?;

        let encrypted_seed = hex::decode(hex_encrypted_seed)?;
        let seed = pkdf2::decrypt(password.as_bytes(), &encrypted_seed);
        Ok(Seed::new(seed.try_into().unwrap()))
    } else {
        let seed = create_seed();
        encrypt_and_backup_seed(&seed, password)?;
        Ok(seed)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let seed = get_seed("password")?;

    let btc_account = Account::new(&seed, 0, CoinType::Bitcoin)?;
    let btc_testnet_account = Account::new(&seed, 0, CoinType::BitcoinTestnet)?;
    let btc_testnet_account_2 = Account::new(&seed, 1, CoinType::BitcoinTestnet)?;

    let accounts = vec![
        btc_account.clone(),
        btc_testnet_account.clone(),
        btc_testnet_account_2.clone(),
    ];

    for account in accounts {
        let address = account.get_address()?;
        println!(
            "{:?} | Account: {} | Address: {} | Balance: {}",
            account.coin_type,
            account.index,
            address,
            account.get_balance().await?
        );
    }

    let prev_tx_id = "671c26cf0d7bf8d056d783e5bb4f785eb28adbe12de112c1b9d9a0af118cf2a7";
    let from_address = "mmsKA9wjZjxh6bdemdzQLzsWjAiEt8aes7";
    let to_address = "mrv6BbWSeETPyQV7DwkSobKqZCsL1aJdnx";
    let amount = 20_000;

    let tx = create_raw_transaction(prev_tx_id, from_address, to_address, amount, None)?;

    println!("Transaction: {tx}");

    let signed_tx =
        btc_testnet_account.sign_transaction(&tx, prev_tx_id, from_address, to_address, amount)?;

    println!("Signed Transaction: {signed_tx}");

    send_transaction(&signed_tx).await?;

    // let tx = btc::create_transaction(
    //     &btc_testnet_account.get_address()?,
    //     &btc_testnet_account_2.get_address()?,
    //     0.0001,
    // )
    // .await?;

    // println!("Transaction: {tx}");

    // let signed_tx = btc_testnet_account.sign_transaction(&tx);

    // println!("Signed Transaction: {signed_tx}");

    Ok(())
}
