#![allow(dead_code)]
use crate::oracle_api::WorkUnit;
use std::collections::VecDeque;

pub struct JobPool {
    pending_jobs: VecDeque<WorkUnit>,
}

impl JobPool {
    pub fn new() -> Self {
        JobPool { pending_jobs: VecDeque::new() }
    }

    pub fn add_job(&mut self, job: WorkUnit) {
        self.pending_jobs.push_back(job);
    }

    pub fn get_next_job(&mut self) -> Option<WorkUnit> {
        self.pending_jobs.pop_front()
    }
    
    /// Checks if there are any pending jobs without removing them.
    pub fn has_jobs(&self) -> bool {
        !self.pending_jobs.is_empty()
    }

    /// Returns the number of pending jobs in the pool.
    pub fn len(&self) -> usize {
        self.pending_jobs.len()
    }

    /// Returns true if the job pool is empty.
    pub fn is_empty(&self) -> bool {
        self.pending_jobs.is_empty()
    }

    /// Clears all pending jobs from the pool.
    pub fn clear(&mut self) {
        self.pending_jobs.clear();
    }

    /// Peek at the next job without removing it from the queue.
    pub fn peek_next_job(&self) -> Option<&WorkUnit> {
        self.pending_jobs.front()
    }
}
