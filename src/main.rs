use std::io::{Read, Write};
use std::path::Path;

use bip32::secp256k1::ecdsa::SigningKey;
use bip32::{ExtendedPrivateKey, Seed};
use bip32::{Mnemonic, XPrv};
use rand_core::OsRng;

use crate::account::{Account, CoinType};

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

fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let seed = get_seed("password")?;

    let root_xprv = create_xpriv(&seed)?;

    let btc_account = Account::new(CoinType::Bitcoin);
    let btc_testnet_account = Account::new(CoinType::BitcoinTestnet);
    let accounts = vec![btc_account, btc_testnet_account];

    for account in accounts {
        let address = account.get_address(&seed)?;
        println!("{:?}: {}", account.coin_type, address);
    }

    Ok(())

    // // Get the ECDSA/secp256k1 signing and verification keys for the xprv and xpub
    // let signing_key = btc_xprv.private_key();
    // let verification_key = btc_xpub.public_key();

    // // Sign and verify an example message using the derived keys.
    // use bip32::secp256k1::ecdsa::{
    //     signature::{Signer, Verifier},
    //     Signature,
    // };

    // let example_msg = b"Hello, world!";
    // let signature: Signature = signing_key.sign(example_msg);
    // assert!(verification_key.verify(example_msg, &signature).is_ok());
    // Ok(())
}
