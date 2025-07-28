#![allow(dead_code)]
use crate::address::Network;
use crate::wallet::Wallet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wallets {
    #[serde(flatten)]
    pub wallets: HashMap<String, Wallet>,
}

impl Wallets {
    pub fn new() -> Self {
        Wallets {
            wallets: HashMap::new(),
        }
    }

    pub fn add_wallet(&mut self) -> String {
        let wallet = Wallet::new();
        let address = wallet.get_address(Network::Mainnet);
        self.wallets.insert(address.clone(), wallet);
        address

    }
    pub fn get_wallet(&self, address: &str) -> Option<&Wallet> {
        self.wallets.get(address)
    }
    pub fn get_all_addresses(&self) -> Vec<String> {
        self.wallets.keys().cloned().collect()
    }
    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let serialized = serde_json::to_string_pretty(self)?;
        fs::write(path, serialized)
    }
    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        if !std::path::Path::new(path).exists() {
            let new_wallets = Wallets::new();
            new_wallets.save_to_file(path)?;
            Ok(new_wallets)

        } else {
            let data = fs::read_to_string(path)?;
            serde_json::from_str(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
    }
}