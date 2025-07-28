#![allow(dead_code)]
use crate::core::transaction::Transaction;
use std::collections::VecDeque;

pub struct Mempool {
    pending: VecDeque<Transaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            pending: VecDeque::new(),
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) {
        // In a real mempool, you would validate the transaction here before adding.
        self.pending.push_back(tx);
    }

    /// Drains a specified number of transactions from the mempool.
    /// This is a simple method that removes the transactions as it returns them.
    pub fn drain_pending_transactions(&mut self, limit: usize) -> Vec<Transaction> {
        let count = std::cmp::min(limit, self.pending.len());
        self.pending.drain(0..count).collect()
    }

    /// A more robust alternative: "peeks" at transactions without removing them.
    pub fn get_pending_transactions(&self, limit: usize) -> Vec<Transaction> {
        self.pending.iter().take(limit).cloned().collect()
    }

    /// Removes specific transactions by their ID, typically after they are confirmed in a block.
    pub fn remove_transactions(&mut self, tx_ids: &[Vec<u8>]) {
        self.pending.retain(|tx| !tx_ids.contains(&tx.id));
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Clears all pending transactions from the mempool.
    pub fn clear(&mut self) {
        self.pending.clear();
    }

    /// Peek at the next transaction without removing it from the queue.
    pub fn peek_next_transaction(&self) -> Option<&Transaction> {
        self.pending.front()
    }

    /// Returns all pending transaction IDs.
    pub fn get_pending_tx_ids(&self) -> Vec<Vec<u8>> {
        self.pending.iter().map(|tx| tx.id.clone()).collect()
    }
}
