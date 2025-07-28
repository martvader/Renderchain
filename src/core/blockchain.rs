#![allow(dead_code)]
use super::block::Block;
use super::transaction::{Transaction, TXOutput};
use crate::wallets::Wallets;
use bs58;
use rocksdb::{IteratorMode, Options, WriteBatch, DB};
use std::collections::HashMap;
use thiserror::Error;

pub const DB_PATH: &str = "blockchain.db";
const TIP_KEY: &[u8] = b"l";
const UTXO_PREFIX: &[u8] = b"u";
const HEIGHT_KEY: &[u8] = b"h";

#[derive(Error, Debug)]
pub enum BlockchainError {
    #[error("Database error: {0}")]
    DbError(#[from] rocksdb::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Block error: {0}")]
    BlockError(#[from] super::block::BlockError),
    #[error("Insufficient funds")]
    InsufficientFunds,
    #[error("Transaction validation failed")]
    TxValidationFailed,
}

pub struct Blockchain {
    pub tip: Vec<u8>,
    pub height: u64,
    pub db: DB,
}

impl Blockchain {
    pub fn new() -> Result<Self, BlockchainError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, DB_PATH)?;
        match db.get(TIP_KEY)? {
            Some(tip) => {
                let height_bytes = db.get(HEIGHT_KEY)?.unwrap_or_else(|| 0u64.to_be_bytes().to_vec());
                let height = u64::from_be_bytes(height_bytes.try_into().unwrap_or([0; 8]));
                Ok(Blockchain { tip, height, db })
            }
            None => {
                let wallets = Wallets::load_from_file("wallets.json").map_err(|e| BlockchainError::VerificationFailed(format!("Failed to load wallets: {}", e)))?;
                let genesis_address_str = wallets.get_all_addresses().get(0).ok_or_else(|| BlockchainError::VerificationFailed("Genesis requires at least one wallet".into()))?.clone();
                let decoded_address = bs58::decode(&genesis_address_str).into_vec().map_err(|e| BlockchainError::VerificationFailed(format!("Invalid genesis address format: {}", e)))?;
                let pub_key_hash = decoded_address[1..decoded_address.len() - 4].to_vec();
                let coinbase = Transaction::new_coinbase_tx(&pub_key_hash, "Genesis Block".to_string());
                let genesis = Block::new_genesis_block(coinbase);
                
                let mut batch = WriteBatch::default();
                batch.put(&genesis.hash, bincode::serialize(&genesis)?);
                batch.put(TIP_KEY, &genesis.hash);
                batch.put(HEIGHT_KEY, &0u64.to_be_bytes());
                let tx = &genesis.transactions[0];
                for (i, output) in tx.vout.iter().enumerate() {
                    let key = [UTXO_PREFIX, tx.id.as_slice(), &i.to_be_bytes()].concat();
                    batch.put(&key, bincode::serialize(output)?);
                }
                db.write(batch)?;
                Ok(Blockchain { tip: genesis.hash, height: 0, db })
            }
        }
    }

    pub fn new_readonly() -> Result<Self, BlockchainError> {
        let opts = Options::default();
        let db = DB::open_for_read_only(&opts, DB_PATH, false)?;
        let tip = db.get(TIP_KEY)?.ok_or_else(|| BlockchainError::VerificationFailed("DB exists but is malformed (missing tip).".into()))?;
        let height_bytes = db.get(HEIGHT_KEY)?.unwrap_or_else(|| 0u64.to_be_bytes().to_vec());
        let height = u64::from_be_bytes(height_bytes.try_into().unwrap_or([0; 8]));
        Ok(Blockchain { tip, height, db })
    }
    
    pub fn add_block(&mut self, block: Block) -> Result<(), BlockchainError> {
        let calculated_hash = block.calculate_hash()?;
        if block.hash != calculated_hash {
            return Err(BlockchainError::VerificationFailed("Invalid block hash".into()));
        }
        
        let prev_txs = self.get_transaction_inputs_for_block(&block)?;
        for tx in &block.transactions {
            if !tx.is_coinbase() {
                if !tx.verify(prev_txs.clone()).map_err(BlockchainError::VerificationFailed)? {
                    return Err(BlockchainError::TxValidationFailed);
                }
            }
        }
        
        let mut batch = WriteBatch::default();
        batch.put(&block.hash, bincode::serialize(&block)?);
        batch.put(TIP_KEY, &block.hash);
        batch.put(&(self.height + 1).to_be_bytes(), &block.hash);
        batch.put(HEIGHT_KEY, &(self.height + 1).to_be_bytes());
        
        for tx in &block.transactions {
            if !tx.is_coinbase() {
                for input in &tx.vin {
                    let key = [UTXO_PREFIX, input.txid.as_slice(), &input.vout.to_be_bytes()].concat();
                    batch.delete(&key);
                }
            }
            for (i, output) in tx.vout.iter().enumerate() {
                let key = [UTXO_PREFIX, tx.id.as_slice(), &i.to_be_bytes()].concat();
                batch.put(&key, bincode::serialize(output)?);
            }
        }
        
        self.db.write(batch)?;
        self.tip = block.hash.clone();
        self.height += 1;
        
        Ok(())
    }
    
    fn get_transaction_inputs_for_block(&self, block: &Block) -> Result<HashMap<Vec<u8>, Transaction>, BlockchainError> {
        let mut prev_txs = HashMap::new();
        for tx in &block.transactions {
            if tx.is_coinbase() { continue; }
            for input in &tx.vin {
                if let Some(prev_tx) = self.find_transaction(&input.txid)? {
                    prev_txs.insert(input.txid.clone(), prev_tx);
                } else {
                    return Err(BlockchainError::VerificationFailed(format!("Referenced transaction not found: {}", hex::encode(&input.txid))));
                }
            }
        }
        Ok(prev_txs)
    }
    
    pub fn get_balance(&self, pub_key_hash: &[u8]) -> u64 {
        let mut balance = 0;
        let prefix = [UTXO_PREFIX].concat();
        let iter = self.db.iterator(IteratorMode::From(&prefix, rocksdb::Direction::Forward));
        for item in iter {
            if let Ok((key, value)) = item {
                if !key.starts_with(&prefix) { break; }
                if let Ok(output) = bincode::deserialize::<TXOutput>(&value) {
                    if output.pub_key_hash == pub_key_hash {
                        balance += output.value;
                    }
                }
            }
        }
        balance
    }

    pub fn find_spendable_outputs(&self, pub_key_hash: &[u8], amount: u64) -> Result<(u64, HashMap<Vec<u8>, Vec<usize>>), BlockchainError> {
        let mut unspent_outputs = HashMap::new();
        let mut accumulated = 0;
        let prefix = [UTXO_PREFIX].concat();
        let iter = self.db.iterator(IteratorMode::From(&prefix, rocksdb::Direction::Forward));
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(&prefix) { break; }
            if let Ok(output) = bincode::deserialize::<TXOutput>(&value) {
                if output.pub_key_hash == pub_key_hash {
                    const TXID_LEN: usize = 32;
                    const INDEX_LEN: usize = std::mem::size_of::<usize>();
                    let key_len = key.len();
                    if key_len != UTXO_PREFIX.len() + TXID_LEN + INDEX_LEN { continue; }
                    let txid_end = UTXO_PREFIX.len() + TXID_LEN;
                    let txid = key[UTXO_PREFIX.len()..txid_end].to_vec();
                    let out_idx_bytes: [u8; INDEX_LEN] = key[txid_end..].try_into().map_err(|_| BlockchainError::VerificationFailed("Invalid UTXO key format".into()))?;
                    let out_idx = usize::from_be_bytes(out_idx_bytes);
                    accumulated += output.value;
                    unspent_outputs.entry(txid).or_insert_with(Vec::new).push(out_idx);
                    if accumulated >= amount { break; }
                }
            }
        }
        if accumulated < amount { return Err(BlockchainError::InsufficientFunds); }
        Ok((accumulated, unspent_outputs))
    }

    pub fn find_transaction(&self, txid: &[u8]) -> Result<Option<Transaction>, BlockchainError> {
        let mut current_hash = self.tip.clone();
        loop {
            let block_data = self.db.get(current_hash)?.ok_or_else(|| BlockchainError::VerificationFailed("Failed to find block in iterator".into()))?;
            let block: Block = bincode::deserialize(&block_data)?;
            for tx in block.transactions {
                if tx.id == txid {
                    return Ok(Some(tx));
                }
            }
            if block.prev_hash == vec![0; 32] { break; }
            current_hash = block.prev_hash;
        }
        Ok(None)
    }
}