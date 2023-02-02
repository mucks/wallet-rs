use bip32::{
    secp256k1::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    ExtendedPrivateKey, ExtendedPublicKey, Seed, XPrv,
};

use crate::btc::{
    calculate_utxo, create_raw_transaction, gen_script_sig, sign_raw_transaction,
    xpub_to_btc_address,
};
use anyhow::Result;

#[derive(Debug, Clone, Copy)]
pub enum CoinType {
    Bitcoin = 0,
    BitcoinTestnet = 1,
    Ethereum = 60,
    Litecoin = 2,
}

#[derive(Clone)]
pub struct Account {
    path: String,
    pub coin_type: CoinType,
    pub index: u32,
    xpriv: ExtendedPrivateKey<SigningKey>,
    xpub: ExtendedPublicKey<VerifyingKey>,
}

impl Account {
    pub fn new(seed: &Seed, index: u32, coin_type: CoinType) -> Result<Self> {
        let path = Self::make_path(&coin_type, index);

        let child_path = path.parse()?;
        let child_xprv = XPrv::derive_from_path(seed, &child_path)?;
        let child_xpub = child_xprv.public_key();

        Ok(Self {
            index,
            path,
            coin_type,
            xpriv: child_xprv,
            xpub: child_xpub,
        })
    }

    pub fn sign_transaction(
        &self,
        tx_hash: &str,
        prev_tx_id: &str,
        from_address: &str,
        to_address: &str,
        amount: u64,
    ) -> Result<String> {
        let signed_tx_hash = sign_raw_transaction(self.xpriv.private_key(), tx_hash.into())?;
        let script_sign = gen_script_sig(
            &signed_tx_hash,
            &hex::encode(self.xpub.public_key().to_bytes()),
        );

        let signed_tx = create_raw_transaction(
            prev_tx_id,
            from_address,
            to_address,
            amount,
            Some(&script_sign),
        )?;

        Ok(signed_tx)
    }

    fn make_path(coin_type: &CoinType, i: u32) -> String {
        match coin_type {
            CoinType::Bitcoin => format!("m/44'/0'/{i}'/0/0"),
            CoinType::BitcoinTestnet => format!("m/44'/1'/{i}'/0/0"),
            CoinType::Ethereum => format!("m/44'/60'/{i}'/0/0"),
            CoinType::Litecoin => format!("m/44'/2'/{i}'/0/0"),
        }
    }

    pub async fn get_balance(&self) -> Result<f64> {
        match self.coin_type {
            CoinType::Bitcoin => Ok(0.0),
            CoinType::BitcoinTestnet => calculate_utxo(&self.get_address()?).await ,
            _ => {
                todo!()
            }
            // CoinType::Ethereum => Ok(xpub_to_eth_address(&child_xpub.to_bytes())),
            // CoinType::Litecoin => Ok(xpub_to_btc_address(&child_xpub.to_bytes())),
        }
    }

    pub fn get_address(&self) -> Result<String> {
        match self.coin_type {
            CoinType::Bitcoin => Ok(xpub_to_btc_address(&self.xpub.to_bytes(), false)),
            CoinType::BitcoinTestnet => Ok(xpub_to_btc_address(&self.xpub.to_bytes(), true)),
            _ => {
                todo!()
            }
            // CoinType::Ethereum => Ok(xpub_to_eth_address(&child_xpub.to_bytes())),
            // CoinType::Litecoin => Ok(xpub_to_btc_address(&child_xpub.to_bytes())),
        }
    }
}
