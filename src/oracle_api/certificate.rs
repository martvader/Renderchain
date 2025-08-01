use serde::{Deserialize, Serialize};
// Note: We need to bring RenderResult into scope for the CertificateOfWork struct.
// Assuming RenderResult is defined in this file. If it's elsewhere, adjust the use statement.
// From your file structure, it seems it is defined right here.

// This is a forward declaration if needed, but your file has it defined below.
// pub struct RenderResult; 

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
    pub total_tiles: u32, // <-- ADD THIS FIELD
    pub nonce: u32,
    pub output_hash: String,
}