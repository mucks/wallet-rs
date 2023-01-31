use ripemd::Digest;
use ripemd::Ripemd160;
use sha2::Sha256;

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
