use serde::{Deserialize, Serialize};
use std::sync::mpsc::Sender;

/// Progress information broadcast during cracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Progress {
    pub tried: u64,
    pub speed: f64,
    pub elapsed_ms: u128,
}

/// Broadcast a progress update via the channel.
pub fn broadcast_progress(tx: &Sender<Progress>, progress: Progress) {
    let _ = tx.send(progress);
}
