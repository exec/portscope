use serde::{Serialize, Deserialize};
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use crate::cli::ScanType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: String,
    pub target_ip: IpAddr,
    pub scan_type: ScanType,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub ports: Vec<PortResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiHostScanResult {
    pub target_spec: String,
    pub scan_type: ScanType,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub total_hosts: usize,
    pub total_ports: usize,
    pub hosts: Vec<ScanResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub status: PortStatus,
    pub is_filtered: bool,
    pub response_time: Option<f64>,
    pub service_detected: Option<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Error,
}

impl std::fmt::Display for PortStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortStatus::Open => write!(f, "open"),
            PortStatus::Closed => write!(f, "closed"),
            PortStatus::Filtered => write!(f, "filtered"),
            PortStatus::Error => write!(f, "error"),
        }
    }
}