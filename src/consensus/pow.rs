#![allow(dead_code)]
use crate::core::block::Block;
use crate::oracle_api::{CertificateOfWork, RenderResult, WorkUnit};
use crate::job_pool::JobPool;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::{Signer, Verifier}};
use anyhow::anyhow;
use chrono::Utc;
use getrandom::getrandom;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub const NUM_ORACLES: usize = 5;
pub const REQUIRED_SIGNATURES: usize = 3;

const BLENDER_EXECUTABLE_PATH: &str = "C:\\Program Files\\Blender Foundation\\Blender 4.1\\blender.exe";

pub struct RenderEngine;

impl RenderEngine {
    pub fn run(work_unit: &WorkUnit, nonce: u32, unique_id: &str) -> Result<Vec<u8>, anyhow::Error> {
        // --- START OF DEFINITIVE FIX ---
        // 1. Get the current working directory (e.g., C:\Users\...\foldchain).
        let current_dir = std::env::current_dir()?;

        // 2. Create the absolute path to the output folder *inside* the project directory.
        let output_dir = current_dir.join("render_output");
        fs::create_dir_all(&output_dir)?;

        // 3. Create the full, unambiguous, absolute path for the output file.
        let output_filename = format!("tile_{}_{}_{}.png", work_unit.tile_index, nonce, unique_id);
        let absolute_output_path = output_dir.join(&output_filename);
        
        // 4. Convert to a string that Python on Windows can reliably understand.
        let python_safe_output_path = absolute_output_path.to_string_lossy().replace('\\', "/");
        // --- END OF DEFINITIVE FIX ---

        let python_script = format!(r#"
import bpy
bpy.context.scene.cycles.seed = {}
tile_count_x = 4; tile_count_y = 4; tile_index = {}
tile_x = tile_index % tile_count_x; tile_y = tile_index // tile_count_x
bpy.context.scene.render.engine = 'CYCLES'
settings = bpy.context.scene.render
settings.resolution_x = 1024
settings.resolution_y = 768
settings.filepath = r"{}"
settings.use_border = True
settings.border_min_x = float(tile_x) / tile_count_x
settings.border_max_x = float(tile_x + 1) / tile_count_x
settings.border_min_y = float(tile_y) / tile_count_y
settings.border_max_y = float(tile_y + 1) / tile_count_y
img_settings = settings.image_settings
img_settings.file_format = 'PNG'
img_settings.color_mode = 'RGBA'
img_settings.color_depth = '8'
img_settings.compression = 15
bpy.context.scene.cycles.samples = 16 
bpy.context.scene.cycles.device = 'CPU'
bpy.context.scene.cycles.use_adaptive_sampling = False
bpy.context.scene.render.threads_mode = 'FIXED'
bpy.context.scene.render.threads = 1
bpy.ops.render.render(write_still=True)
"#, nonce, work_unit.tile_index, python_safe_output_path);

        let cmd_output = Command::new(BLENDER_EXECUTABLE_PATH)
            .arg("-b").arg(&work_unit.scene_file).arg("--python-expr").arg(&python_script)
            .output()?;
        
        if !cmd_output.status.success() {
            let stderr = String::from_utf8_lossy(&cmd_output.stderr);
            return Err(anyhow!("Blender process failed: {}", stderr));
        }

        if !absolute_output_path.exists() {
            let stdout = String::from_utf8_lossy(&cmd_output.stdout);
            return Err(anyhow!(
                "Rendered image file not found at '{}'. Blender output:\n{}", 
                absolute_output_path.display(),
                stdout
            ));
        }
        
        let image_bytes = fs::read(&absolute_output_path)?;
        
        // --- NOTE FOR YOU ---
        // I have commented out the line that deletes the file,
        // so you can see the rendered tiles appear in the `render_output` folder.
        // fs::remove_file(&absolute_output_path).ok();
        
        Ok(image_bytes)
    }
}

#[derive(Error, Debug)]
pub enum PowError {
    #[error("Mining failed: insufficient certificates")]
    InsufficientCertificates,
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Render engine error: {0}")]
    RenderError(String),
    #[error("Idle task aborted for new job")]
    AbortedForNewJob,
}

fn oracle_issue_certificate(
    oracle_key: &SigningKey, oracle_index: usize, work_unit: &WorkUnit, miner_id: String, nonce: u32
) -> Result<CertificateOfWork, PowError> {
    println!("[Oracle #{}] Verifying render for tile #{}...", oracle_index, work_unit.tile_index);
    let unique_id = format!("oracle_{}", oracle_index);
    let verification_bytes = RenderEngine::run(work_unit, nonce, &unique_id).map_err(|e| PowError::RenderError(e.to_string()))?;
    
    let mut hasher = Sha256::new();
    hasher.update(&verification_bytes);
    let result_hash = hasher.finalize();
    let result_hash_hex = hex::encode(result_hash);
    println!("[Oracle #{}] Verification complete. Hash: {}... Issuing certificate.", oracle_index, &result_hash_hex[..10]);

    let render_result = RenderResult {
        scene_file: work_unit.scene_file.clone(),
        tile_index: work_unit.tile_index,
        nonce,
        output_hash: result_hash_hex,
    };

    let timestamp = Utc::now().timestamp();
    let message_to_sign = format!("{}|{}|{}|{}", work_unit.task_id, miner_id, oracle_index, timestamp);
    let signature: Signature = oracle_key.sign(message_to_sign.as_bytes());

    Ok(CertificateOfWork {
        task_id: work_unit.task_id.clone(),
        miner_id,
        oracle_id: oracle_index,
        timestamp,
        oracle_signature: signature.to_bytes().to_vec(),
        simulation_result: render_result,
    })
}

pub struct ProofOfWork {
    block: Block,
}

impl ProofOfWork {
    fn get_oracle_private_keys(&self) -> Vec<SigningKey> {
        (0..NUM_ORACLES).map(|i| {
            let mut secret_bytes = [0u8; 32];
            getrandom(&mut secret_bytes).expect("RNG failure");
            secret_bytes[0] = i as u8;
            SigningKey::from_bytes((&secret_bytes).into()).expect("Invalid oracle key")
        }).collect()
    }

    pub fn new(block: Block) -> Self { 
        ProofOfWork { block } 
    }

    pub fn into_block(self) -> Block {
        self.block
    }

    pub fn run(&mut self, job_pool: Arc<Mutex<JobPool>>) -> Result<(Vec<CertificateOfWork>, u32), PowError> {
        println!("\n[Miner] Starting Proof of Service...");
        
        let work_unit = {
            let mut job_pool_guard = job_pool.lock().unwrap();
            match job_pool_guard.get_next_job() {
                Some(job) => {
                    log::info!("[Miner] Picked up user job: {}", job.task_id);
                    job
                }
                None => {
                    println!("[Miner] No jobs in pool. Awaiting work.");
                    return Err(PowError::AbortedForNewJob); 
                }
            }
        };

        println!("[Miner] Submitting tile #{} for verification by oracles...", work_unit.tile_index);
        
        let nonce = work_unit.tile_index;
        
        let oracle_keys = self.get_oracle_private_keys();
        let miner_id = "miner_node_1".to_string();

        let collected_certificates: Vec<_> = (0..NUM_ORACLES).into_par_iter()
            .map(|i| oracle_issue_certificate(&oracle_keys[i], i, &work_unit, miner_id.clone(), nonce))
            .collect::<Result<Vec<_>, _>>()?;

        let federation_pub_keys: Vec<VerifyingKey> = oracle_keys.iter().map(|k| *k.verifying_key()).collect();
        let valid_certificates: Vec<_> = collected_certificates.into_iter()
            .filter(|cert| self.validate_certificate(cert, &federation_pub_keys).is_ok())
            .collect();
        
        if valid_certificates.len() < REQUIRED_SIGNATURES { 
            return Err(PowError::InsufficientCertificates);
        }

        println!("\n[Miner] Collected {} valid certificates for the render.", valid_certificates.len());
        Ok((valid_certificates, nonce))
    }
    
    fn validate_certificate(&self, cert: &CertificateOfWork, federation_keys: &[VerifyingKey]) -> Result<(), PowError> {
        if cert.oracle_id >= federation_keys.len() {
            return Err(PowError::SignatureError(format!("Invalid oracle ID: {}", cert.oracle_id)));
        }
        let pub_key = &federation_keys[cert.oracle_id];
        let message = format!("{}|{}|{}|{}", cert.task_id, cert.miner_id, cert.oracle_id, cert.timestamp);
        let signature = Signature::from_slice(&cert.oracle_signature).map_err(|e| PowError::SignatureError(e.to_string()))?;
        pub_key.verify(message.as_bytes(), &signature).map_err(|e| PowError::SignatureError(e.to_string()))?;
        Ok(())
    }
}