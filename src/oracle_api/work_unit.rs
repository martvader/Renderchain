use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkUnit {
    pub task_id: String,
    pub tile_index: u32,
    pub scene_file: String,
    pub render_settings: String,
}