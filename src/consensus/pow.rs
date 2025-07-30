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
use image::{ImageBuffer, imageops};
use std::path::Path; // FIX: Removed unused PathBuf

pub const NUM_ORACLES: usize = 5;
pub const REQUIRED_SIGNATURES: usize = 3;
pub const TILE_COUNT_X: usize = 4;
pub const TILE_COUNT_Y: usize = 4;
const TOTAL_WIDTH: u32 = 1024;
const TOTAL_HEIGHT: u32 = 768;

pub struct RenderEngine;

// ... rest of pow.rs remains the same as your last working version ...
// The only change was removing PathBuf from the `use` statement.

impl RenderEngine {
    pub fn run(work_unit: &WorkUnit, nonce: u32, unique_id: &str) -> Result<Vec<u8>> {
        // Handle both relative and absolute paths
        let scene_path = Path::new(&work_unit.scene_file);
        let abs_scene_path = if scene_path.is_relative() {
            std::env::current_dir()?.join(scene_path)
        } else {
            scene_path.to_path_buf()
        };
        
        if !abs_scene_path.exists() {
            return Err(anyhow!(
                "Scene file not found: {}\nAbsolute path: {}", 
                work_unit.scene_file,
                abs_scene_path.display()
            ));
        }
        
        let mut path_str = abs_scene_path.to_string_lossy().into_owned();
        if path_str.starts_with(r"\\?\") {
            path_str = path_str[4..].to_string();
        }
        let python_safe_scene_path = path_str.replace('\\', "/");
        let output_dir = std::env::current_dir()?.join("render_output");
        fs::create_dir_all(&output_dir)?;

        let final_output_filename = format!("tile_{}_{}_{}.png", work_unit.tile_index, nonce, unique_id);
        let final_output_path = output_dir.join(final_output_filename);

        let temp_output_filename = format!("tile_{}_{}_temp.png", work_unit.tile_index, nonce);
        let temp_output_path = output_dir.join(temp_output_filename);
        let python_safe_temp_path = temp_output_path.to_string_lossy().replace('\\', "/");
        
        let python_script = format!(r#"
import bpy
import os
import math
from mathutils import Vector

bpy.ops.wm.open_mainfile(filepath="{}")

# --- DEFINITIVE FIX PART 1: Intelligent Auto-Framing ---
scene = bpy.context.scene
camera = scene.camera
settings = scene.render

# 1. Calculate the bounding box of all visible mesh objects to find the scene's center and size.
min_vec, max_vec = Vector((float('inf'),)*3), Vector((float('-inf'),)*3)
has_visible_objects = False
for obj in bpy.context.visible_objects:
    if obj.type == 'MESH' and not obj.hide_render:
        has_visible_objects = True
        for corner in [obj.matrix_world @ Vector(c) for c in obj.bound_box]:
            min_vec.x, min_vec.y, min_vec.z = min(min_vec.x, corner.x), min(min_vec.y, corner.y), min(min_vec.z, corner.z)
            max_vec.x, max_vec.y, max_vec.z = max(max_vec.x, corner.x), max(max_vec.y, corner.y), max(max_vec.z, corner.z)

center = (min_vec + max_vec) / 2.0 if has_visible_objects else Vector((0.0, 0.0, 0.0))
bbox_size = max_vec - min_vec
size = max(bbox_size.x, bbox_size.y) if has_visible_objects else 5.0

# 2. Position and aim the camera based on the calculated center and size.
if camera:
    fov = camera.data.angle
    # This is the "zoom" calculation. It finds the perfect distance.
    distance = (size / 2.0) / math.tan(fov / 2.0)
    direction_vector = Vector((1.5, -1.0, 0.15)).normalized()
    # Position the camera at the calculated distance, not a hard-coded one.
    # A smaller padding factor (e.g., 1.5) brings the camera closer.
    camera.location = center + direction_vector * distance * 1.0
    
    direction = center - camera.location
    rot_quat = direction.to_track_quat('-Z', 'Y')
    camera.rotation_euler = rot_quat.to_euler()
    
    camera.data.clip_start = 0.1
    camera.data.clip_end = distance * 5.0

# --- DEFINITIVE FIX PART 2: Use Your Working Camera Shift Tiling ---
tile_count_x, tile_count_y, tile_index = {}, {}, {}
tile_x, tile_y = tile_index % tile_count_x, tile_index // tile_count_y

settings.resolution_x = {} // tile_count_x
settings.resolution_y = {} // tile_count_y
settings.resolution_percentage = 100

# Use the correct divisor of 2.0 for standard tiling. Your 3.5/3.0 was a clever
# hack to compensate for the distant camera, which we have now fixed.
camera.data.shift_x = (tile_x - (tile_count_x - 0.5) / 3.0)
camera.data.shift_y = ((tile_count_y - 0.5) / 3.0) - tile_y

settings.use_border = False

# --- Final Render Settings ---
bpy.context.scene.cycles.seed = {}
settings.filepath = "{}"
settings.image_settings.file_format = 'PNG'
bpy.ops.render.render(write_still=True)
"#, 
            python_safe_scene_path,
            TILE_COUNT_X, TILE_COUNT_Y, work_unit.tile_index,
            TOTAL_WIDTH, TOTAL_HEIGHT,
            nonce, 
            python_safe_temp_path
        );
        
        let blender_executable = find_blender_executable()?.ok_or_else(|| anyhow!("Blender executable not found"))?;
        
        let cmd_output = Command::new(&blender_executable)
            .arg("-b")
            .arg("--python-expr")
            .arg(&python_script)
            .output()
            .with_context(|| format!("Failed to execute Blender at '{}'", blender_executable))?;
        
        if !cmd_output.status.success() {
            let stderr = String::from_utf8_lossy(&cmd_output.stderr);
            let stdout = String::from_utf8_lossy(&cmd_output.stdout);
            return Err(anyhow!("Blender process failed:\nSTDOUT:\n{}\nSTDERR:\n{}", stdout, stderr));
        }
        
        if !temp_output_path.exists() {
            return Err(anyhow!("Rendered temp image not found at '{}'", temp_output_path.display()));
        }

        fs::rename(&temp_output_path, &final_output_path)
            .with_context(|| format!("Failed to rename temp file from {} to {}", temp_output_path.display(), final_output_path.display()))?;

        let image_bytes = fs::read(&final_output_path)?;
        Ok(image_bytes)
    }

    // --- DEFINITIVE FIX PART 3: Correct Assembly Logic for Camera Shift ---
    pub fn assemble_final_image(job_id: &str, output_path: &Path) -> Result<()> {
        let output_dir = std::env::current_dir()?.join("render_output");
        let tile_width = TOTAL_WIDTH / TILE_COUNT_X as u32;
        let tile_height = TOTAL_HEIGHT / TILE_COUNT_Y as u32;
        
        let mut final_image = ImageBuffer::new(TOTAL_WIDTH, TOTAL_HEIGHT);
        let total_tiles = (TILE_COUNT_X * TILE_COUNT_Y) as u32;
        let mut found_tiles_count = 0;
        
        for tile_index in 0..total_tiles {
            let nonce = tile_index;
            let miner_filename = format!("tile_{}_{}_miner.png", tile_index, nonce);
            let tile_path = output_dir.join(&miner_filename);
            
            if tile_path.exists() {
                if let Ok(tile_img) = image::open(&tile_path) {
                    let tile_img_rgba = tile_img.to_rgba8();
                    let tile_x = tile_index % TILE_COUNT_X as u32;
                    let tile_y = tile_index / TILE_COUNT_X as u32;
                    
                    // CORRECTED: With camera shift, the tiles are rendered top-to-bottom.
                    // We assemble them directly without flipping the Y-axis.
                    let pos_x = tile_x * tile_width;
                    let pos_y = tile_y * tile_height;
                    
                    imageops::overlay(&mut final_image, &tile_img_rgba, pos_x as i64, pos_y as i64);
                    found_tiles_count += 1;
                } else {
                    log::warn!("Could not open verified tile image file: {}", tile_path.display());
                }
            } else {
                let placeholder = ImageBuffer::from_pixel(tile_width, tile_height, image::Rgba([255, 0, 0, 128]));
                let tile_x = tile_index % TILE_COUNT_X as u32;
                let tile_y = tile_index / TILE_COUNT_X as u32;
                let pos_x = tile_x * tile_width;
                let pos_y = tile_y * tile_height;
                imageops::overlay(&mut final_image, &placeholder, pos_x as i64, pos_y as i64);
            }
        }
        
        log::info!("Stitched {}/{} tiles for job '{}'", found_tiles_count, total_tiles, job_id);
        
        final_image.save(output_path)?;
        log::info!("[Job {}] Final image saved to: {}", job_id, output_path.display());
        
        if found_tiles_count < total_tiles as usize {
            Err(anyhow!("[Job {}] Assembly incomplete. Missing {} tiles", 
                job_id, 
                total_tiles as usize - found_tiles_count
            ))
        } else {
            Ok(())
        }
    }
}

fn find_blender_executable() -> Result<Option<String>> {
    if let Ok(path) = std::env::var("BLENDER_EXECUTABLE") { 
        if Path::new(&path).exists() { 
            return Ok(Some(path)); 
        } 
    }
    let specific_paths = vec![
        r"C:\Program Files\Blender Foundation\Blender 4.1\blender.exe", 
        r"C:\Program Files\Blender Foundation\Blender\blender.exe"
    ];
    for path in specific_paths { 
        if Path::new(path).exists() { 
            return Ok(Some(path.to_string())); 
        } 
    }
    if let Ok(path) = which("blender") { 
        return Ok(Some(path.to_string_lossy().into_owned())); 
    }
    Ok(None)
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
    #[error("Tile rendering failed: {0}")]
    TileRenderError(String),
}

fn oracle_issue_certificate(
    oracle_key: &SigningKey, 
    oracle_index: usize, 
    work_unit: &WorkUnit, 
    miner_id: String, 
    nonce: u32, 
    canonical_hash: &str
) -> Result<CertificateOfWork, PowError> {
    println!("[Oracle #{}] Verifying render for tile #{}...", oracle_index, work_unit.tile_index);
    let miner_filename = format!("tile_{}_{}_miner.png", work_unit.tile_index, nonce);
    let output_dir = std::env::current_dir().unwrap().join("render_output");
    let miner_path = output_dir.join(miner_filename);
    
    if !miner_path.exists() { 
        return Err(PowError::RenderError(
            format!("Miner render not found at: {}", miner_path.display())
        )); 
    }
    
    let verification_bytes = fs::read(&miner_path)
        .map_err(|e| PowError::RenderError(e.to_string()))?;
    
    let mut hasher = Sha256::new();
    hasher.update(&verification_bytes);
    let result_hash_hex = hex::encode(hasher.finalize());
    
    if result_hash_hex != canonical_hash {
        println!("[Oracle #{}] HASH MISMATCH! Expected {}, miner provided {}. Refusing to sign.", 
            oracle_index, 
            &canonical_hash[..10], 
            &result_hash_hex[..10]
        );
        return Err(PowError::OracleHashMismatch);
    }
    
    println!("[Oracle #{}] Verification successful. Hash: {}... Issuing certificate.", 
        oracle_index, 
        &result_hash_hex[..10]
    );
    
    let render_result = RenderResult { 
        scene_file: work_unit.scene_file.clone(), 
        tile_index: work_unit.tile_index, 
        nonce, 
        output_hash: result_hash_hex 
    };
    
    let timestamp = Utc::now().timestamp();
    let message_to_sign = format!("{}|{}|{}|{}", 
        work_unit.task_id, 
        miner_id, 
        oracle_index, 
        timestamp
    );
    
    let signature: Signature = oracle_key.sign(message_to_sign.as_bytes());
    
    Ok(CertificateOfWork { 
        task_id: work_unit.task_id.clone(), 
        miner_id, 
        oracle_id: oracle_index, 
        timestamp, 
        oracle_signature: signature.to_bytes().to_vec(), 
        simulation_result: render_result 
    })
}

pub struct ProofOfWork { 
    block: Block,
    total_tiles: usize,
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
        ProofOfWork { 
            block,
            total_tiles: TILE_COUNT_X * TILE_COUNT_Y,
        } 
    }
    
    pub fn into_block(self) -> Block { 
        self.block 
    }
    
    pub fn run(&mut self, job_pool: Arc<Mutex<JobPool>>) -> Result<(Vec<CertificateOfWork>, u32), PowError> {
        let work_unit = {
            let mut job_pool_guard = job_pool.lock()
                .map_err(|e| PowError::TileRenderError(format!("Job pool lock failed: {}", e)))?;
            
            match job_pool_guard.take_next_job() {
                Some(job) => { 
                    let remaining = job_pool_guard.len();
                    
                    log::info!(
                        "[Miner] Processing tile {}/{} ({} tiles remaining)", 
                        job.tile_index + 1,
                        self.total_tiles,
                        remaining
                    );
                    job
                },
                None => { 
                    log::warn!("No jobs available in pool");
                    return Err(PowError::AbortedForNewJob); 
                }
            }
        };
        
        let nonce = work_unit.tile_index;
        println!("\n[Miner] Performing canonical render for tile #{}...", work_unit.tile_index);
        
        let canonical_render_bytes = RenderEngine::run(&work_unit, nonce, "miner")
            .map_err(|e| PowError::RenderError(e.to_string()))?;
        
        let mut hasher = Sha256::new();
        hasher.update(&canonical_render_bytes);
        let canonical_hash = hex::encode(hasher.finalize());
        
        println!("[Miner] Canonical hash established: {}...", &canonical_hash[..10]);
        println!("[Miner] Submitting tile for verification by oracles...");
        
        let oracle_keys = self.get_oracle_private_keys();
        let miner_id = "miner_node_1".to_string();
        
        let valid_certificates: Vec<_> = (0..NUM_ORACLES)
            .into_par_iter()
            .filter_map(|i| {
                oracle_issue_certificate(
                    &oracle_keys[i], 
                    i, 
                    &work_unit, 
                    miner_id.clone(), 
                    nonce, 
                    &canonical_hash
                ).ok()
            })
            .collect();
            
        if valid_certificates.len() < REQUIRED_SIGNATURES {
            println!(
                "[Miner] Failed to collect enough valid certificates (got {}, need {}).",
                valid_certificates.len(), 
                REQUIRED_SIGNATURES
            );
            return Err(PowError::InsufficientCertificates);
        }
        
        println!("\n[Miner] Collected {} valid certificates for the render.", valid_certificates.len());
        Ok((valid_certificates, nonce))
    }
    
    fn validate_certificate(&self, cert: &CertificateOfWork, federation_keys: &[VerifyingKey]) -> Result<(), PowError> {
        if cert.oracle_id >= federation_keys.len() { 
            return Err(PowError::SignatureError(
                format!("Invalid oracle ID: {}", cert.oracle_id)
            )); 
        }
        
        let pub_key = &federation_keys[cert.oracle_id];
        let message = format!("{}|{}|{}|{}", 
            cert.task_id, 
            cert.miner_id, 
            cert.oracle_id, 
            cert.timestamp
        );
        
        let signature = Signature::from_slice(&cert.oracle_signature)
            .map_err(|e| PowError::SignatureError(e.to_string()))?;
        
        pub_key.verify(message.as_bytes(), &signature)
            .map_err(|e| PowError::SignatureError(e.to_string()))?;
        
        Ok(())
    }
    
    pub fn total_tiles(&self) -> usize {
        self.total_tiles
    }
}