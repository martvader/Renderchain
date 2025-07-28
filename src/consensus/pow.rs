#![allow(dead_code)]
use crate::core::block::Block;
use crate::oracle_api::{CertificateOfWork, RenderResult, WorkUnit};
use crate::job_pool::JobPool;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::{Signer, Verifier}};
use anyhow::{anyhow, Result, Context};
use chrono::Utc;
use getrandom::getrandom;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use which::which;
use image::ImageBuffer;
use std::path::Path;

pub const NUM_ORACLES: usize = 5;
pub const REQUIRED_SIGNATURES: usize = 3;
const TILE_COUNT_X: usize = 4;
const TILE_COUNT_Y: usize = 4;
const TOTAL_WIDTH: u32 = 1024;
const TOTAL_HEIGHT: u32 = 768;

pub struct RenderEngine;

impl RenderEngine {
    pub fn run(work_unit: &WorkUnit, nonce: u32, unique_id: &str) -> Result<Vec<u8>> {
        // PATH NORMALIZATION: Remove Windows verbatim prefix
        let clean_path = if work_unit.scene_file.starts_with(r"\\?\") {
            work_unit.scene_file[4..].to_string()
        } else {
            work_unit.scene_file.clone()
        };
        
        // Verify scene file exists
        if !std::path::Path::new(&clean_path).exists() {
            return Err(anyhow!("Scene file not found: {}", clean_path));
        }
        
        // Get absolute directory of scene file for working directory
        let scene_dir = std::path::Path::new(&clean_path)
            .parent()
            .ok_or_else(|| anyhow!("Invalid scene file path: {}", clean_path))?
            .to_str()
            .ok_or_else(|| anyhow!("Path conversion error"))?
            .to_string();
        
        // Create output directory inside current working directory
        let output_dir = std::env::current_dir()?.join("render_output");
        fs::create_dir_all(&output_dir)?;
        
        // Create unique output filename
        let output_filename = format!("tile_{}_{}_{}.png", work_unit.tile_index, nonce, unique_id);
        let output_path = output_dir.join(output_filename);
        let python_safe_output_path = output_path.to_string_lossy().replace('\\', "/");
        
        // For oracles and assembly, use miner's pre-rendered image if available
        if unique_id != "miner" {
            let miner_filename = format!("tile_{}_{}_miner.png", work_unit.tile_index, nonce);
            let miner_path = output_dir.join(miner_filename);
            
            if miner_path.exists() {
                log::info!("Using miner's render for tile {}", work_unit.tile_index);
                return fs::read(&miner_path).map_err(|e| e.into());
            }
        }

        let python_script = format!(r#"
import bpy
import os
os.chdir("{}")
bpy.context.scene.cycles.seed = {}
tile_count_x = {}; tile_count_y = {}; tile_index = {}
tile_x = tile_index % tile_count_x
tile_y = tile_index // tile_count_x
bpy.context.scene.render.engine = 'CYCLES'
settings = bpy.context.scene.render
settings.resolution_x = 1024
settings.resolution_y = 768
settings.filepath = "{}"
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
"#, 
            scene_dir.replace('\\', "/"),  // Use forward slashes for Python compatibility
            nonce, 
            TILE_COUNT_X, TILE_COUNT_Y,
            work_unit.tile_index,
            python_safe_output_path
        );

        // Robust Blender path discovery
        let blender_path = find_blender_executable()
            .ok_or_else(|| anyhow!(
                "Blender executable not found in standard locations.\n\
                Tried: C:\\Program Files\\Blender Foundation\\Blender 4.1\\blender.exe\n\
                Please verify your Blender installation at:\n\
                C:\\Program Files\\Blender Foundation\\Blender 4.1"
            ))?;
        
        log::info!("Using Blender at: {}", blender_path);
        
        // Handle directory paths and different executable names
        let blender_executable = if blender_path.ends_with("Blender 4.1") {
            // Search for executables if we have a directory path
            find_executable_in_dir(&blender_path, "blender.exe")
                .or_else(|| find_executable_in_dir(&blender_path, "blender"))
                .ok_or_else(|| anyhow!("No Blender executable found in directory: {}", blender_path))?
        } else {
            blender_path.clone()
        };
        
        log::info!("Launching Blender executable: {}", blender_executable);
        
        let cmd_output = Command::new(&blender_executable)
            .arg("-b")
            .arg(&clean_path)
            .arg("--python-expr")
            .arg(&python_script)
            .output()
            .with_context(|| format!("Failed to execute Blender at '{}'. Is Blender installed?", blender_executable))?;
        
        if !cmd_output.status.success() {
            let stderr = String::from_utf8_lossy(&cmd_output.stderr);
            return Err(anyhow!("Blender process failed:\n{}", stderr));
        }
        
        if !output_path.exists() {
            let stdout = String::from_utf8_lossy(&cmd_output.stdout);
            return Err(anyhow!(
                "Rendered image not found at '{}'.\n\
                Blender output:\n{}", 
                output_path.display(),
                stdout
            ));
        }

        let image_bytes = fs::read(&output_path)?;
        Ok(image_bytes)
    }

    // CORRECTED: Function to assemble final image from miner's tiles
    pub fn assemble_final_image(job_id: &str, output_path: &Path, nonce: u32) -> Result<()> {
        let output_dir = std::env::current_dir()?.join("render_output");
        let tile_width = TOTAL_WIDTH / TILE_COUNT_X as u32;
        let tile_height = TOTAL_HEIGHT / TILE_COUNT_Y as u32;
        
        let mut final_image = ImageBuffer::from_pixel(TOTAL_WIDTH, TOTAL_HEIGHT, image::Rgba([0, 0, 0, 0]));
        
        for tile_index in 0..(TILE_COUNT_X * TILE_COUNT_Y) {
            let miner_filename = format!("tile_{}_{}_miner.png", tile_index, nonce);
            let tile_path = output_dir.join(miner_filename);
            
            if !tile_path.exists() {
                return Err(anyhow!("Missing tile {} for job {}", tile_index, job_id));
            }
            
            let tile = image::open(&tile_path)?;
            let tile = tile.to_rgba8();
            
            // Verify tile dimensions match expectations
            if tile.width() != tile_width || tile.height() != tile_height {
                return Err(anyhow!(
                    "Tile {} has incorrect dimensions: expected {}x{}, got {}x{}",
                    tile_index, tile_width, tile_height, tile.width(), tile.height()
                ));
            }
            
            // Calculate correct grid position
            let tile_x = (tile_index % TILE_COUNT_X) as u32;
            let tile_y = (tile_index / TILE_COUNT_X) as u32;
            
            // Position in final image
            let pos_x = tile_x * tile_width;
            let pos_y = tile_y * tile_height;
            
            // Copy all pixels from tile to final image
            for y in 0..tile_height {
                for x in 0..tile_width {
                    let pixel = tile.get_pixel(x, y);
                    final_image.put_pixel(pos_x + x, pos_y + y, *pixel);
                }
            }
            
            log::info!("Placed tile {} at position ({}, {})", tile_index, pos_x, pos_y);
        }
        
        final_image.save(output_path)?;
        log::info!("Assembly complete! Final image dimensions: {}x{}", TOTAL_WIDTH, TOTAL_HEIGHT);
        Ok(())
    }
}

// Find Blender executable using multiple strategies
fn find_blender_executable() -> Option<String> {
    // 1. Check environment variable
    if let Ok(path) = std::env::var("BLENDER_EXECUTABLE") {
        if path_exists(&path) {
            log::debug!("Found Blender via environment variable: {}", path);
            return Some(path);
        }
    }
    
    // 2. Check specific known paths (including directory path)
    let specific_paths = vec![
        r"C:\Program Files\Blender Foundation\Blender 4.1\blender.exe",
        r"C:\Program Files\Blender Foundation\Blender 4.1", // Directory path
        r"C:\Program Files\Blender Foundation\Blender\blender.exe",
        r"C:\Program Files\Blender Foundation\Blender 4.0\blender.exe",
        r"C:\Program Files\Blender Foundation\Blender 3.6\blender.exe",
        r"C:\Program Files\Blender Foundation\Blender 3.3\blender.exe",
    ];
    
    for path in specific_paths {
        if path_exists(path) {
            log::debug!("Found Blender at specific path: {}", path);
            return Some(path.to_string());
        }
    }
    
    // 3. Try system PATH
    if let Ok(path) = which("blender") {
        let path_str = path.to_string_lossy().into_owned();
        log::debug!("Found Blender in PATH: {}", path_str);
        return Some(path_str);
    }
    
    // 4. Try directory search
    let program_files = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string());
    let search_dirs = vec![
        format!(r"{}\Blender Foundation", program_files),
        r"C:\Program Files (x86)\Blender Foundation".to_string(),
    ];
    
    for dir in search_dirs {
        if let Some(path) = find_executable_in_dir(&dir, "blender.exe") {
            log::debug!("Found Blender via directory search: {}", path);
            return Some(path);
        }
    }
    
    None
}

// Check if a path exists (file or directory)
fn path_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

// Find executable in a directory
fn find_executable_in_dir(dir: &str, executable: &str) -> Option<String> {
    let dir_path = std::path::Path::new(dir);
    if !dir_path.exists() || !dir_path.is_dir() {
        return None;
    }
    
    for entry in std::fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        
        if path.is_file() {
            if let Some(file_name) = path.file_name() {
                if file_name.to_string_lossy().to_lowercase() == executable.to_lowercase() {
                    return Some(path.to_string_lossy().into_owned());
                }
            }
        } else if path.is_dir() {
            // Recursively search subdirectories
            if let Some(found) = find_executable_in_dir(&path.to_string_lossy(), executable) {
                return Some(found);
            }
        }
    }
    
    None
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
    #[error("Oracle verification failed: Hash mismatch")]
    OracleHashMismatch,
}

fn oracle_issue_certificate(
    oracle_key: &SigningKey, oracle_index: usize, work_unit: &WorkUnit, miner_id: String, nonce: u32, canonical_hash: &str
) -> Result<CertificateOfWork, PowError> {
    println!("[Oracle #{}] Verifying render for tile #{}...", oracle_index, work_unit.tile_index);
    let _unique_id = format!("oracle_{}", oracle_index);
    
    // Get miner's render output
    let miner_filename = format!("tile_{}_{}_miner.png", work_unit.tile_index, nonce);
    let output_dir = std::env::current_dir().unwrap().join("render_output");
    let miner_path = output_dir.join(miner_filename);
    
    if !miner_path.exists() {
        return Err(PowError::RenderError("Miner render not found".to_string()));
    }
    
    let verification_bytes = fs::read(&miner_path)
        .map_err(|e| PowError::RenderError(e.to_string()))?;
    
    let mut hasher = Sha256::new();
    hasher.update(&verification_bytes);
    let result_hash_hex = hex::encode(hasher.finalize());

    if result_hash_hex != canonical_hash {
        println!("[Oracle #{}] HASH MISMATCH! Expected {}, got {}. Refusing to sign.", oracle_index, &canonical_hash[..10], &result_hash_hex[..10]);
        return Err(PowError::OracleHashMismatch);
    }

    println!("[Oracle #{}] Verification successful. Hash: {}... Issuing certificate.", oracle_index, &result_hash_hex[..10]);

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
        
        let nonce = work_unit.tile_index;
        
        println!("[Miner] Performing canonical render for tile #{}...", work_unit.tile_index);
        let canonical_render_bytes = RenderEngine::run(&work_unit, nonce, "miner")
            .map_err(|e| PowError::RenderError(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(&canonical_render_bytes);
        let canonical_hash = hex::encode(hasher.finalize());
        println!("[Miner] Canonical hash established: {}...", &canonical_hash[..10]);

        println!("[Miner] Submitting tile for verification by oracles...");
        let oracle_keys = self.get_oracle_private_keys();
        let miner_id = "miner_node_1".to_string();

        let valid_certificates: Vec<_> = (0..NUM_ORACLES).into_par_iter()
            .filter_map(|i| {
                oracle_issue_certificate(&oracle_keys[i], i, &work_unit, miner_id.clone(), nonce, &canonical_hash).ok()
            })
            .collect();

        if valid_certificates.len() < REQUIRED_SIGNATURES { 
            println!("[Miner] Failed to collect enough valid certificates (got {}, need {}).", valid_certificates.len(), REQUIRED_SIGNATURES);
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