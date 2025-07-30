use crate::oracle_api::WorkUnit;
use std::collections::VecDeque;

pub struct JobPool {
    work_units: VecDeque<WorkUnit>,
}

impl JobPool {
    pub fn new() -> Self {
        JobPool {
            work_units: VecDeque::new(),
        }
    }
    
    pub fn add_jobs(&mut self, new_jobs: Vec<WorkUnit>) {
        for job in new_jobs {
            self.work_units.push_back(job);
        }
    }
    
    pub fn take_next_job(&mut self) -> Option<WorkUnit> {
        self.work_units.pop_front()
    }
    
    pub fn len(&self) -> usize {
        self.work_units.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.work_units.is_empty()
    }
}