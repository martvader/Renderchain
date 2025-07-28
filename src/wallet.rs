#![allow(dead_code)]

use crate::core::transaction::Transaction;
use crate::address::{new_address, Network};
use anyhow::Result;
use k256::ecdsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Wallet {
    pub private_key: SigningKey,
    pub public_key: VerifyingKey,
}

impl Wallet {
    pub fn new() -> Self {
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = *private_key.verifying_key();
        Wallet {
            private_key,
            public_key,
        }
    }

    pub fn get_address(&self, network: Network) -> String {
        new_address(&self.public_key.to_sec1_bytes(), network)
    }

    

    /// Signs a transaction.

    /// It populates the `pub_key` field in the inputs before calling the transaction's own sign method.

    pub fn sign_transaction(
        &self, 
        tx: &mut Transaction, 
        prev_txs: HashMap<Vec<u8>, Transaction>
    ) -> Result<(), String> {
        for vin in &mut tx.vin {
            vin.pub_key = self.public_key.to_sec1_bytes().to_vec();
        }
        tx.sign(&self.private_key, prev_txs)
    }
}



// Custom serde implementations to handle cryptographic types

impl Serialize for Wallet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {

        #[derive(Serialize)]
        struct SerializableWallet<'a> {
            private_key: &'a [u8],
            public_key: Vec<u8>,
        }
        let private_key_bytes = self.private_key.to_bytes();
        let serializable = SerializableWallet {
            private_key: &private_key_bytes,
            public_key: self.public_key.to_sec1_bytes().to_vec(),
        };
        serializable.serialize(serializer)
    }
}


impl<'de> Deserialize<'de> for Wallet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {

        #[derive(Deserialize)]
        struct SerializableWallet {
            private_key: Vec<u8>,
            public_key: Vec<u8>,
        }
        let temp_wallet = SerializableWallet::deserialize(deserializer)?;
        let private_key = SigningKey::from_bytes(temp_wallet.private_key.as_slice().into())
            .map_err(serde::de::Error::custom)?;
        let public_key = VerifyingKey::from_sec1_bytes(&temp_wallet.public_key)
            .map_err(serde::de::Error::custom)?;
        Ok(Wallet {
            private_key,
            public_key,

        })
    }
}