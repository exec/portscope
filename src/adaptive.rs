use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProfile {
    pub network_type: NetworkType,
    pub avg_response_time: f64,
    pub timeout_rate: f64,
    pub optimal_parallelism: u16,
    pub optimal_rate_limit: u64,
    pub last_updated: u64,
    pub scan_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NetworkType {
    LocalHost,
    PrivateLAN,
    PublicInternet,
    CloudProvider,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortIntelligence {
    pub port: u16,
    pub found_count: u32,
    pub success_rate: f64,
    pub avg_response_time: f64,
    pub service_confidence: f64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostIntelligence {
    pub host: String,
    pub network_profile: NetworkProfile,
    pub open_ports: Vec<u16>,
    pub os_fingerprint: Option<String>,
    pub response_pattern: ResponsePattern,
    pub firewall_detected: bool,
    pub last_scan: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePattern {
    pub rst_timing: f64,        // How fast RST responses come back
    pub syn_ack_timing: f64,    // How fast SYN-ACK responses come back
    pub timeout_pattern: f64,   // Pattern of timeouts (indicates filtering)
    pub icmp_responses: bool,   // Does host respond to ICMP
}

#[derive(Debug, Serialize, Deserialize)]
#[derive(Clone)]
pub struct AdaptiveLearning {
    pub network_profiles: HashMap<String, NetworkProfile>,
    pub port_intelligence: HashMap<u16, PortIntelligence>,
    pub host_intelligence: HashMap<String, HostIntelligence>,
    pub global_stats: GlobalStats,
    config_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalStats {
    pub total_scans: u32,
    pub total_ports_found: u32,
    pub total_hosts_scanned: u32,
    pub success_rate: f64,
    pub avg_scan_time: f64,
    pub most_common_ports: Vec<(u16, u32)>,
}

impl AdaptiveLearning {
    pub fn new() -> Self {
        let config_path = Self::get_config_path();
        
        if config_path.exists() {
            match Self::load_from_file(&config_path) {
                Ok(learning) => learning,
                Err(_) => Self::create_default(config_path),
            }
        } else {
            Self::create_default(config_path)
        }
    }
    
    fn create_default(config_path: PathBuf) -> Self {
        AdaptiveLearning {
            network_profiles: HashMap::new(),
            port_intelligence: Self::initialize_port_intelligence(),
            host_intelligence: HashMap::new(),
            global_stats: GlobalStats {
                total_scans: 0,
                total_ports_found: 0,
                total_hosts_scanned: 0,
                success_rate: 0.0,
                avg_scan_time: 0.0,
                most_common_ports: Vec::new(),
            },
            config_path,
        }
    }
    
    fn get_config_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("portscan");
        std::fs::create_dir_all(&path).ok();
        path.push("adaptive_learning.json");
        path
    }
    
    fn load_from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let mut learning: AdaptiveLearning = serde_json::from_str(&content)?;
        learning.config_path = path.clone();
        Ok(learning)
    }
    
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&self.config_path, content)?;
        Ok(())
    }
    
    fn initialize_port_intelligence() -> HashMap<u16, PortIntelligence> {
        let mut intel = HashMap::new();
        
        // Initialize common ports with baseline intelligence
        let common_ports = [
            (21, "FTP", 0.1), (22, "SSH", 0.8), (23, "Telnet", 0.05),
            (25, "SMTP", 0.3), (53, "DNS", 0.9), (80, "HTTP", 0.9),
            (110, "POP3", 0.1), (143, "IMAP", 0.2), (443, "HTTPS", 0.9),
            (993, "IMAPS", 0.1), (995, "POP3S", 0.05)
        ];
        
        for (port, _service, baseline_rate) in common_ports {
            intel.insert(port, PortIntelligence {
                port,
                found_count: 1,
                success_rate: baseline_rate,
                avg_response_time: 100.0,
                service_confidence: 0.9,
                last_seen: current_timestamp(),
            });
        }
        
        intel
    }
    
    /// Learn from a completed scan
    pub fn learn_from_scan(&mut self, scan_result: &ScanLearningData) {
        self.update_network_profile(scan_result);
        self.update_port_intelligence(scan_result);
        self.update_host_intelligence(scan_result);
        self.update_global_stats(scan_result);
        
        // Save learning data
        let _ = self.save();
    }
    
    /// Get optimized scan parameters for a target
    pub fn get_optimal_params(&self, target: IpAddr) -> OptimalScanParams {
        let network_type = classify_network(target);
        let network_key = format!("{:?}", network_type);
        
        if let Some(profile) = self.network_profiles.get(&network_key) {
            OptimalScanParams {
                timeout: (profile.avg_response_time * 3.0) as u64,
                rate_limit: profile.optimal_rate_limit,
                parallelism: profile.optimal_parallelism,
                suggested_ports: self.get_smart_port_list(&network_type),
                network_type,
            }
        } else {
            OptimalScanParams::default_for_network(network_type)
        }
    }
    
    /// Get intelligently ordered port list
    pub fn get_smart_port_list(&self, network_type: &NetworkType) -> Vec<u16> {
        let mut port_scores: Vec<(u16, f64)> = self.port_intelligence
            .iter()
            .map(|(port, intel)| {
                let recency_factor = 1.0 - ((current_timestamp() - intel.last_seen) as f64 / (86400.0 * 30.0)).min(1.0);
                let network_bonus = match network_type {
                    NetworkType::LocalHost => if *port == 22 || *port == 80 { 2.0 } else { 1.0 },
                    NetworkType::PrivateLAN => if *port == 445 || *port == 135 { 1.5 } else { 1.0 },
                    NetworkType::PublicInternet => if *port == 80 || *port == 443 { 1.5 } else { 1.0 },
                    NetworkType::CloudProvider => if *port == 22 || *port == 80 || *port == 443 { 1.5 } else { 1.0 },
                };
                
                let score = intel.success_rate * intel.service_confidence * recency_factor * network_bonus;
                (*port, score)
            })
            .collect();
        
        port_scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        port_scores.into_iter().map(|(port, _)| port).take(100).collect()
    }
    
    fn update_network_profile(&mut self, data: &ScanLearningData) {
        let network_key = format!("{:?}", data.network_type);
        let profile = self.network_profiles.entry(network_key).or_insert_with(|| {
            NetworkProfile {
                network_type: data.network_type.clone(),
                avg_response_time: data.avg_response_time,
                timeout_rate: data.timeout_rate,
                optimal_parallelism: data.parallelism_used,
                optimal_rate_limit: data.rate_limit_used,
                last_updated: current_timestamp(),
                scan_count: 0,
            }
        });
        
        // Exponential moving average for adaptive learning
        let alpha = 0.1; // Learning rate
        profile.avg_response_time = profile.avg_response_time * (1.0 - alpha) + data.avg_response_time * alpha;
        profile.timeout_rate = profile.timeout_rate * (1.0 - alpha) + data.timeout_rate * alpha;
        
        // Adjust optimal parameters based on performance
        if data.scan_performance > 0.8 {
            profile.optimal_parallelism = (profile.optimal_parallelism as f64 * 1.1).min(100.0) as u16;
            profile.optimal_rate_limit = (profile.optimal_rate_limit as f64 * 0.9).max(10.0) as u64;
        } else if data.scan_performance < 0.5 {
            profile.optimal_parallelism = (profile.optimal_parallelism as f64 * 0.9).max(1.0) as u16;
            profile.optimal_rate_limit = (profile.optimal_rate_limit as f64 * 1.2) as u64;
        }
        
        profile.scan_count += 1;
        profile.last_updated = current_timestamp();
    }
    
    fn update_port_intelligence(&mut self, data: &ScanLearningData) {
        for port_result in &data.port_results {
            let intel = self.port_intelligence.entry(port_result.port).or_insert_with(|| {
                PortIntelligence {
                    port: port_result.port,
                    found_count: 0,
                    success_rate: 0.5,
                    avg_response_time: 1000.0,
                    service_confidence: 0.5,
                    last_seen: 0,
                }
            });
            
            if port_result.is_open {
                intel.found_count += 1;
                intel.last_seen = current_timestamp();
                
                // Update success rate with exponential moving average
                let alpha = 1.0 / (intel.found_count as f64 + 1.0);
                intel.success_rate = intel.success_rate * (1.0 - alpha) + alpha;
                
                if let Some(response_time) = port_result.response_time {
                    intel.avg_response_time = intel.avg_response_time * 0.8 + response_time * 0.2;
                }
            }
        }
    }
    
    fn update_host_intelligence(&mut self, data: &ScanLearningData) {
        let host_key = data.target.to_string();
        let host_intel = self.host_intelligence.entry(host_key).or_insert_with(|| {
            HostIntelligence {
                host: data.target.to_string(),
                network_profile: NetworkProfile {
                    network_type: data.network_type.clone(),
                    avg_response_time: data.avg_response_time,
                    timeout_rate: data.timeout_rate,
                    optimal_parallelism: data.parallelism_used,
                    optimal_rate_limit: data.rate_limit_used,
                    last_updated: current_timestamp(),
                    scan_count: 1,
                },
                open_ports: Vec::new(),
                os_fingerprint: None,
                response_pattern: ResponsePattern {
                    rst_timing: 0.0,
                    syn_ack_timing: 0.0,
                    timeout_pattern: 0.0,
                    icmp_responses: false,
                },
                firewall_detected: false,
                last_scan: current_timestamp(),
            }
        });
        
        // Update open ports
        host_intel.open_ports = data.port_results
            .iter()
            .filter(|p| p.is_open)
            .map(|p| p.port)
            .collect();
        
        // Detect firewall patterns
        let filtered_count = data.port_results.iter().filter(|p| p.is_filtered).count();
        let total_count = data.port_results.len();
        host_intel.firewall_detected = (filtered_count as f64 / total_count as f64) > 0.7;
        
        host_intel.last_scan = current_timestamp();
    }
    
    fn update_global_stats(&mut self, data: &ScanLearningData) {
        self.global_stats.total_scans += 1;
        
        let open_ports = data.port_results.iter().filter(|p| p.is_open).count() as u32;
        self.global_stats.total_ports_found += open_ports;
        
        // Update most common ports
        let mut port_counts: HashMap<u16, u32> = HashMap::new();
        for port_result in &data.port_results {
            if port_result.is_open {
                *port_counts.entry(port_result.port).or_insert(0) += 1;
            }
        }
        
        // Merge with existing most common ports
        for (port, count) in port_counts {
            if let Some(existing) = self.global_stats.most_common_ports.iter_mut().find(|(p, _)| *p == port) {
                existing.1 += count;
            } else {
                self.global_stats.most_common_ports.push((port, count));
            }
        }
        
        // Keep top 50 most common ports
        self.global_stats.most_common_ports.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        self.global_stats.most_common_ports.truncate(50);
    }
}

#[derive(Debug, Clone)]
pub struct ScanLearningData {
    pub target: IpAddr,
    pub network_type: NetworkType,
    pub port_results: Vec<PortScanResult>,
    pub scan_duration: Duration,
    pub avg_response_time: f64,
    pub timeout_rate: f64,
    pub parallelism_used: u16,
    pub rate_limit_used: u64,
    pub scan_performance: f64, // 0.0 to 1.0 based on success rate and speed
}

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub port: u16,
    pub is_open: bool,
    pub is_filtered: bool,
    pub response_time: Option<f64>,
    pub service_detected: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OptimalScanParams {
    pub timeout: u64,
    pub rate_limit: u64,
    pub parallelism: u16,
    pub suggested_ports: Vec<u16>,
    pub network_type: NetworkType,
}

impl OptimalScanParams {
    fn default_for_network(network_type: NetworkType) -> Self {
        match network_type {
            NetworkType::LocalHost => OptimalScanParams {
                timeout: 200,
                rate_limit: 10,
                parallelism: 100,
                suggested_ports: vec![22, 80, 443, 8080, 3306, 5432],
                network_type,
            },
            NetworkType::PrivateLAN => OptimalScanParams {
                timeout: 500,
                rate_limit: 50,
                parallelism: 50,
                suggested_ports: vec![22, 80, 443, 445, 135, 3389],
                network_type,
            },
            NetworkType::PublicInternet => OptimalScanParams {
                timeout: 2000,
                rate_limit: 200,
                parallelism: 20,
                suggested_ports: vec![80, 443, 22, 21, 25, 53],
                network_type,
            },
            NetworkType::CloudProvider => OptimalScanParams {
                timeout: 1000,
                rate_limit: 100,
                parallelism: 30,
                suggested_ports: vec![22, 80, 443, 8080, 9000, 3000],
                network_type,
            },
        }
    }
}

pub fn classify_network(ip: IpAddr) -> NetworkType {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            
            // Localhost
            if octets[0] == 127 {
                return NetworkType::LocalHost;
            }
            
            // Private networks (RFC 1918)
            if (octets[0] == 10) ||
               (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
               (octets[0] == 192 && octets[1] == 168) {
                return NetworkType::PrivateLAN;
            }
            
            // Cloud provider ranges (simplified)
            if is_cloud_provider_ip(&octets) {
                return NetworkType::CloudProvider;
            }
            
            NetworkType::PublicInternet
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() {
                NetworkType::LocalHost
            } else if ipv6.segments()[0] == 0xfe80 || ipv6.segments()[0] & 0xfe00 == 0xfc00 {
                NetworkType::PrivateLAN
            } else {
                NetworkType::PublicInternet
            }
        }
    }
}

fn is_cloud_provider_ip(octets: &[u8; 4]) -> bool {
    // AWS ranges (simplified - this is just an example)
    (octets[0] == 3 && octets[1] <= 7) ||
    (octets[0] == 13) ||
    (octets[0] == 15) ||
    // Google Cloud (simplified)
    (octets[0] == 34 && octets[1] >= 64 && octets[1] <= 127) ||
    // Microsoft Azure (simplified)
    (octets[0] == 20) ||
    (octets[0] == 40)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_network_classification() {
        assert_eq!(classify_network("127.0.0.1".parse().unwrap()), NetworkType::LocalHost);
        assert_eq!(classify_network("192.168.1.1".parse().unwrap()), NetworkType::PrivateLAN);
        assert_eq!(classify_network("8.8.8.8".parse().unwrap()), NetworkType::PublicInternet);
    }
    
    #[test]
    fn test_adaptive_learning_creation() {
        let learning = AdaptiveLearning::new();
        assert!(!learning.port_intelligence.is_empty());
        assert_eq!(learning.global_stats.total_scans, 0);
    }
}