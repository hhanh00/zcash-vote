use anyhow::Result;
use bip39::Mnemonic;
use zcash_address::unified::Encoding;

pub fn validate_key(key: String) -> Result<bool> {
    if Mnemonic::parse(&key).is_ok() {
        return Ok(true);
    }
    if zcash_address::unified::Ufvk::decode(&key).is_ok() {
        return Ok(true);
    }
    Ok(false)
}
