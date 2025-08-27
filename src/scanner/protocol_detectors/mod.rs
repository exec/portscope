// Protocol detection modules for various network services
// This module provides modular service detection capabilities

pub mod database_detectors;
pub mod messaging_detectors;
pub mod web_detectors;
pub mod system_detectors;
pub mod development_detectors;

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProtocolDetectionResult {
    pub service_name: String,
    pub confidence: f32,
    pub version: Option<String>,
    pub additional_info: HashMap<String, String>,
}

pub trait ProtocolDetector {
    fn name(&self) -> &str;
    fn detect(&self, response: &[u8]) -> Option<ProtocolDetectionResult>;
    fn get_probe_data(&self) -> Vec<Vec<u8>>;
}