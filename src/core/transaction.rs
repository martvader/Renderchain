#![allow(dead_code)]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use k256::ecdsa::{SigningKey, Signature, VerifyingKey, signature::{Signer, Verifier}};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TXOutput {
    pub value: u64,
    pub pub_key_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TXInput {
    pub txid: Vec<u8>,
    pub vout: usize,
    pub signature: Vec<u8>,
    pub pub_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: Vec<u8>,
    pub vin: Vec<TXInput>,
    pub vout: Vec<TXOutput>,
}

impl Transaction {
    pub fn new_coinbase_tx(to: &[u8], data: String) -> Self {
        let txin = TXInput {
            txid: vec![],
            vout: 0,
            signature: vec![],
            pub_key: data.into_bytes(),
        };
        
        let txout = TXOutput {
            value: 100,
            pub_key_hash: to.to_vec(),
        };
        
        let mut tx = Transaction {
            id: vec![],
            vin: vec![txin],
            vout: vec![txout],
        };
        
        tx.id = tx.hash().unwrap_or_else(|_| vec![0; 32]);
        tx
    }
    
    pub fn is_coinbase(&self) -> bool {
        self.vin.len() == 1 && self.vin[0].txid.is_empty()
    }

    /// Hashes the transaction for signing and identification.
    pub fn hash(&self) -> Result<Vec<u8>, bincode::Error> {
        let tx_copy = self.trimmed_copy();
        let serialized = bincode::serialize(&tx_copy)?;
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        Ok(hasher.finalize().to_vec())
    }

    /// Signs the transaction's inputs.
    pub fn sign(&mut self, priv_key: &SigningKey, prev_txs: HashMap<Vec<u8>, Transaction>) -> Result<(), String> {
        if self.is_coinbase() { return Ok(()); }

        let mut tx_copy = self.trimmed_copy();

        for (i, vin) in self.vin.iter_mut().enumerate() {
            let prev_tx = prev_txs.get(&vin.txid)
                .ok_or("Previous transaction not found")?;
            
            tx_copy.vin[i].signature.clear();
            tx_copy.vin[i].pub_key = prev_tx.vout[vin.vout].pub_key_hash.clone();

            let hash_to_sign = tx_copy.hash().map_err(|e| e.to_string())?;
            tx_copy.id = hash_to_sign.clone();

            tx_copy.vin[i].pub_key.clear();

            let signature: Signature = priv_key.sign(&hash_to_sign);
            vin.signature = signature.to_bytes().to_vec();
        }
        Ok(())
    }

    /// Verifies the transaction's signatures.
    pub fn verify(&self, prev_txs: HashMap<Vec<u8>, Transaction>) -> Result<bool, String> {
        if self.is_coinbase() { return Ok(true); }

        let mut tx_copy = self.trimmed_copy();

        for (i, vin) in self.vin.iter().enumerate() {
            let prev_tx = prev_txs.get(&vin.txid)
                .ok_or("Previous transaction not found")?;
            
            tx_copy.vin[i].signature.clear();
            tx_copy.vin[i].pub_key = prev_tx.vout[vin.vout].pub_key_hash.clone();
            
            let hash_to_verify = tx_copy.hash().map_err(|e| e.to_string())?;
            tx_copy.id = hash_to_verify.clone();

            tx_copy.vin[i].pub_key.clear();

            let signature = Signature::from_slice(&vin.signature)
                .map_err(|e| e.to_string())?;
            
            let verifying_key = VerifyingKey::from_sec1_bytes(&vin.pub_key)
                .map_err(|e| e.to_string())?;

            if verifying_key.verify(&hash_to_verify, &signature).is_err() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Creates a copy of the transaction with empty signature and pub_key fields
    fn trimmed_copy(&self) -> Self {
        let mut vin = Vec::new();
        for vi in &self.vin {
            vin.push(TXInput {
                txid: vi.txid.clone(),
                vout: vi.vout,
                signature: vec![],
                pub_key: vec![],
            });
        }
        Transaction {
            id: self.id.clone(),
            vin,
            vout: self.vout.clone(),
        }
    }
}