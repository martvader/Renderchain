#![allow(dead_code)]
use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha2::Sha256;
use thiserror::Error;
use bs58;

const VERSION_MAINNET: u8 = 0x00;
const VERSION_TESTNET: u8 = 0x6F;
const CHECKSUM_LENGTH: usize = 4;

#[derive(Debug, Error)]

pub enum AddressError {
    #[error("Invalid base58 character")]
    Base58Invalid,
    #[error("Checksum mismatch")]
    ChecksumMismatch,
    #[error("Invalid version byte {0}")]
    InvalidVersion(u8),
    #[error("Invalid address length")]
    InvalidLength,

}

#[derive(Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,

}

pub fn new_address(pub_key: &[u8], network: Network) -> String {
    let pub_key_hash = hash_pub_key(pub_key);
    let version = match network {
        Network::Mainnet => VERSION_MAINNET,
        Network::Testnet => VERSION_TESTNET,
    };
    let mut payload = vec![version];
    payload.extend_from_slice(&pub_key_hash);
    let checksum = checksum(&payload);
    payload.extend_from_slice(&checksum);
    bs58::encode(payload).into_string()

}

pub fn validate_address(address: &str) -> Result<Network, AddressError> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|_| AddressError::Base58Invalid)?;

    if decoded.len() <= CHECKSUM_LENGTH {
        return Err(AddressError::InvalidLength);
    }

    let version_byte = decoded[0];
    let payload = &decoded[1..decoded.len() - CHECKSUM_LENGTH];
    let actual_checksum = &decoded[decoded.len() - CHECKSUM_LENGTH..];
    let mut versioned_payload = vec![version_byte];
    versioned_payload.extend_from_slice(payload);
    let expected_checksum = checksum(&versioned_payload);

    if actual_checksum != expected_checksum {
        return Err(AddressError::ChecksumMismatch);
    }
    match version_byte {
        VERSION_MAINNET => Ok(Network::Mainnet),
        VERSION_TESTNET => Ok(Network::Testnet),
        _ => Err(AddressError::InvalidVersion(version_byte)),
    }
}

fn hash_pub_key(pub_key: &[u8]) -> Vec<u8> {
    let pub_key_sha256 = Sha256::digest(pub_key);
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(pub_key_sha256);
    ripemd_hasher.finalize().to_vec()
}

fn checksum(payload: &[u8]) -> Vec<u8> {
    let first_sha = Sha256::digest(payload);
    let second_sha = Sha256::digest(first_sha);
    second_sha[..CHECKSUM_LENGTH].to_vec()

}