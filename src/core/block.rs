#![allow(dead_code)]
use super::transaction::Transaction;
use crate::oracle_api::certificate::CertificateOfWork;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use chrono::Utc;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub version: u32,
    pub timestamp: i64,
    pub transactions: Vec<Transaction>,
    pub prev_hash: Vec<u8>,
    pub hash: Vec<u8>,
    pub proofs: Vec<CertificateOfWork>,
    pub nonce: u32,
}

#[derive(Error, Debug)]
pub enum BlockError {
    #[error("Consensus error: {0}")]
    ConsensusError(#[from] crate::consensus::pow::PowError),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
}

impl Block {
    pub fn new(version: u32, transactions: Vec<Transaction>, prev_hash: Vec<u8>) -> Result<Self, BlockError> {
        let timestamp = Utc::now().timestamp();
        let mut block = Block {
            version,
            timestamp,
            transactions,
            prev_hash,
            hash: vec![],
            proofs: vec![],
            nonce: 0,
        };
        
        block.hash = block.calculate_hash()?;
        Ok(block)
    }

    pub fn new_genesis_block(coinbase: Transaction) -> Self {
        let mut block = Block {
            version: 1,
            timestamp: Utc::now().timestamp(),
            transactions: vec![coinbase],
            prev_hash: vec![0; 32],
            hash: vec![],
            proofs: vec![],
            nonce: 0,
        };
        block.hash = block.calculate_hash().unwrap_or_else(|_| vec![0; 32]);
        block
    }
    
    pub fn finalize(&mut self, proofs: Vec<CertificateOfWork>, nonce: u32) -> Result<(), BlockError> {
        self.proofs = proofs;
        self.nonce = nonce;
        self.hash = self.calculate_hash()?;
        Ok(())
    }
    
    pub fn calculate_hash(&self) -> Result<Vec<u8>, bincode::Error> {
        let mut headers = Vec::new();
        headers.extend_from_slice(&self.version.to_be_bytes());
        headers.extend_from_slice(&self.prev_hash);
        headers.extend_from_slice(&self.merkle_root()?);
        headers.extend_from_slice(&self.timestamp.to_be_bytes());
        headers.extend_from_slice(&self.nonce.to_be_bytes());
        
        let mut hasher = Sha256::new();
        hasher.update(&headers);
        Ok(hasher.finalize().to_vec())
    }

    pub fn merkle_root(&self) -> Result<Vec<u8>, bincode::Error> {
        if self.transactions.is_empty() { return Ok(vec![0; 32]); }
        
        let mut hashes: Vec<Vec<u8>> = self.transactions
            .iter()
            .map(|tx| tx.hash())
            .collect::<Result<Vec<_>, _>>()?;

        if hashes.is_empty() { return Ok(vec![0; 32]); }

        while hashes.len() > 1 {
            if hashes.len() % 2 != 0 {
                hashes.push(hashes.last().unwrap().clone());
            }
            let mut next_level = Vec::new();
            for chunk in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                next_level.push(hasher.finalize().to_vec());
            }
            hashes = next_level;
        }
        Ok(hashes[0].clone())
    }
}