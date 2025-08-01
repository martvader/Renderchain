use serde::{Deserialize, Serialize};
use crate::consensus::pow::{TILE_COUNT_X, TILE_COUNT_Y};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkUnit {
    pub task_id: String,
    pub tile_index: u32,
    pub total_tiles: u32, // <-- ADD THIS FIELD
    pub scene_file: String,
    pub render_settings: String,
}

impl WorkUnit {
    pub fn generate_tile_work_units(task_id: &str, scene_file: &str) -> Vec<Self> {
        let total_tiles = (TILE_COUNT_X * TILE_COUNT_Y) as u32;
        
        // Preserve relative paths for files in project root
        let scene_path = PathBuf::from(scene_file);
        let scene_file_str = if scene_path.is_absolute() {
            scene_file.to_string()
        } else {
            // Keep relative paths as-is
            scene_file.to_string()
        };

        (0..total_tiles)
            .map(|tile_index| WorkUnit {
                task_id: task_id.to_string(),
                tile_index: tile_index,
                total_tiles: total_tiles, // <-- ADD THIS FIELD
                scene_file: scene_file_str.clone(),
                render_settings: String::new(), // Changed from String::new() for consistency
            })
            .collect()
    }
}