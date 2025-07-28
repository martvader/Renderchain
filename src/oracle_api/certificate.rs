use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateOfWork {
    pub task_id: String,
    pub miner_id: String,
    pub oracle_id: usize,
    pub timestamp: i64,
    pub oracle_signature: Vec<u8>,
    pub simulation_result: RenderResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderResult {
    pub scene_file: String,
    pub tile_index: u32,
    pub nonce: u32,
    pub output_hash: String,
}