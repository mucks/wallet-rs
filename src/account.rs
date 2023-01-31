use bip32::{Seed, XPrv};

use crate::btc::xpub_to_btc_address;

#[derive(Debug)]
pub enum CoinType {
    Bitcoin = 0,
    BitcoinTestnet = 1,
    Ethereum = 60,
    Litecoin = 2,
}

pub struct Account {
    path: String,
    pub coin_type: CoinType,
}

impl Account {
    pub fn new(coin_type: CoinType) -> Self {
        Self {
            path: Self::make_path(&coin_type),
            coin_type,
        }
    }

    fn make_path(coin_type: &CoinType) -> String {
        match coin_type {
            CoinType::Bitcoin => "m/44'/0'/0'/0/0".to_string(),
            CoinType::BitcoinTestnet => "m/44'/1'/0'/0/0".to_string(),
            CoinType::Ethereum => "m/44'/60'/0'/0/0".to_string(),
            CoinType::Litecoin => "m/44'/2'/0'/0/0".to_string(),
        }
    }

    pub fn get_address(&self, seed: &Seed) -> anyhow::Result<String> {
        let child_path = self.path.parse()?;
        let child_xprv = XPrv::derive_from_path(seed, &child_path)?;
        let child_xpub = child_xprv.public_key();

        match self.coin_type {
            CoinType::Bitcoin => Ok(xpub_to_btc_address(&child_xpub.to_bytes(), false)),
            CoinType::BitcoinTestnet => Ok(xpub_to_btc_address(&child_xpub.to_bytes(), true)),
            _ => {
                todo!()
            }
            // CoinType::Ethereum => Ok(xpub_to_eth_address(&child_xpub.to_bytes())),
            // CoinType::Litecoin => Ok(xpub_to_btc_address(&child_xpub.to_bytes())),
        }
    }
}
