pub mod tcp;
pub mod udp;
pub mod discovery;
pub mod service_detection;
pub mod results;
pub mod aggressive_probing;
pub mod evasion;
// pub mod auth_fingerprinter;
// pub mod intelligent_classifier;
pub mod ml_classifier;
pub mod os_fingerprint;
pub mod response_analyzer;
pub mod protocol_detectors;
pub mod parallel_detector;
pub mod scan_cache;
pub mod adaptive_service_detector;

use anyhow::Result;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};

use crate::cli::ScanType;
use crate::utils::parse_ports;
use crate::network::parse_targets;
use crate::adaptive::{AdaptiveLearning, ScanLearningData, PortScanResult, classify_network};
pub use results::{ScanResult, PortStatus, PortResult, MultiHostScanResult, ServiceInfo};
use service_detection::ServiceDetector;
use scan_cache::GLOBAL_SCAN_CACHE;

/// Check if IP is in private/local range for optimized scanning
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // RFC 1918 private ranges
            (octets[0] == 10) ||
            (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
            (octets[0] == 192 && octets[1] == 168) ||
            // Localhost
            (octets[0] == 127) ||
            // Link-local
            (octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(ipv6) => {
            // IPv6 local ranges
            ipv6.is_loopback() || 
            ipv6.segments()[0] == 0xfe80 || // Link-local
            ipv6.segments()[0] == 0xfc00 || // Unique local
            ipv6.segments()[0] == 0xfd00    // Unique local
        }
    }
}

pub struct Scanner {
    rate_limit: u64,
    timeout: u64,
    parallel_hosts: usize,
    adaptive_learning: AdaptiveLearning,
    service_detector: ServiceDetector,
}

impl Scanner {
    pub fn new(rate_limit: u64, timeout: u64, parallel_hosts: usize) -> Self {
        Self {
            rate_limit,
            timeout,
            parallel_hosts,
            adaptive_learning: AdaptiveLearning::new(),
            service_detector: ServiceDetector::new(),
        }
    }
    
    pub async fn scan(
        &mut self,
        target: &str,
        ports: &str,
        scan_type: ScanType,
    ) -> Result<MultiHostScanResult> {
        let targets = parse_targets(target)?;
        let port_list = parse_ports(ports)?;
        
        let total_operations = targets.len() * port_list.len();
        let pb = ProgressBar::new(total_operations as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("⟦{spinner:.bright_magenta}⟧ [{elapsed_precise}] ⟨{bar:40.bright_green/bright_black}⟩ {pos}/{len} ports scanned ({eta})")?
                .progress_chars("█▉▊▋▌▍▎▏ ")
        );
        
        let start_time = chrono::Utc::now();
        
        // Create host scanning tasks for parallel execution
        let host_semaphore = Arc::new(Semaphore::new(self.parallel_hosts));
        let mut host_tasks = Vec::new();
        
        for target_ip in targets {
            let semaphore = host_semaphore.clone();
            let port_list = port_list.clone();
            let pb = pb.clone();
            let scan_type = scan_type;
            
            let task = {
                let mut scanner_clone = Scanner::new(self.rate_limit, self.timeout, self.parallel_hosts);
                scanner_clone.adaptive_learning = self.adaptive_learning.clone();
                scanner_clone.service_detector = ServiceDetector::new();
                
                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    scanner_clone.scan_single_host(target_ip, &port_list, scan_type, pb).await
                })
            };
            
            host_tasks.push(task);
        }
        
        // Wait for all host scans to complete
        let host_results: Vec<ScanResult> = join_all(host_tasks).await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        
        pb.finish_with_message("⟦SCAN COMPLETE⟧ Network discovery finished");
        let end_time = chrono::Utc::now();
        
        Ok(MultiHostScanResult {
            target_spec: target.to_string(),
            scan_type,
            start_time,
            end_time,
            total_hosts: host_results.len(),
            total_ports: port_list.len(),
            hosts: host_results,
        })
    }
    
    async fn scan_single_host(
        &mut self,
        target_ip: IpAddr,
        port_list: &[u16],
        scan_type: ScanType,
        pb: ProgressBar,
    ) -> Result<ScanResult> {
        // Get optimized parameters from adaptive learning
        let optimal_params = self.adaptive_learning.get_optimal_params(target_ip);
        let adaptive_timeout = optimal_params.timeout;
        let adaptive_rate_limit = optimal_params.rate_limit;
        let adaptive_parallelism = optimal_params.parallelism as usize;
        
        // Honor explicit user settings over adaptive learning
        // Only use adaptive parameters if user used defaults (1000ms timeout, 10ms rate_limit, 50 parallel)
        let user_set_timeout = self.timeout != 1000;
        let user_set_rate_limit = self.rate_limit != 10;  
        let user_set_parallelism = self.parallel_hosts != 50;
        
        let effective_timeout = if user_set_timeout { 
            self.timeout 
        } else if adaptive_timeout > 0 { 
            adaptive_timeout 
        } else { 
            self.timeout 
        };
        
        let effective_rate_limit = if user_set_rate_limit {
            self.rate_limit
        } else if adaptive_rate_limit > 0 { 
            adaptive_rate_limit 
        } else { 
            self.rate_limit 
        };
        
        let effective_parallelism = if user_set_parallelism {
            self.parallel_hosts
        } else if adaptive_parallelism > 0 { 
            adaptive_parallelism as usize
        } else { 
            self.parallel_hosts 
        };
        
        let semaphore = Arc::new(Semaphore::new(effective_parallelism));
        let mut tasks = vec![];
        
        let start_time = chrono::Utc::now();
        let scan_start = std::time::Instant::now();
        
        for port in port_list.iter() {
            let sem = semaphore.clone();
            let target_ip = target_ip.clone();
            let port = *port;
            let timeout = effective_timeout;
            let rate_limit = effective_rate_limit;
            let pb = pb.clone();
            
            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                
                // Check cache first
                if let Some((cached_status, cached_service)) = GLOBAL_SCAN_CACHE.get_cached_result(target_ip, port, scan_type) {
                    pb.inc(1);
                    return PortResult {
                        port,
                        status: cached_status,
                        is_filtered: cached_status == PortStatus::Filtered,
                        response_time: Some(0.0), // Cached result, instant
                        service_detected: cached_service,
                    };
                }
                
                let scan_start = std::time::Instant::now();
                let result = match scan_type {
                    ScanType::Syn => tcp::syn_scan(target_ip, port, timeout).await,
                    ScanType::Connect => {
                        // Use fast connect scan for private networks
                        if is_private_ip(target_ip) {
                            tcp::fast_connect_scan(target_ip, port, timeout).await
                        } else {
                            tcp::connect_scan(target_ip, port, timeout).await
                        }
                    },
                    ScanType::Udp => udp::udp_scan(target_ip, port, timeout).await,
                    ScanType::Fin => tcp::fin_scan(target_ip, port, timeout).await,
                    ScanType::Xmas => tcp::xmas_scan(target_ip, port, timeout).await,
                    ScanType::Null => tcp::null_scan(target_ip, port, timeout).await,
                };
                let scan_duration = scan_start.elapsed().as_millis() as f64;
                
                pb.inc(1);
                
                if rate_limit > 0 {
                    sleep(Duration::from_millis(rate_limit)).await;
                }
                
                PortResult { 
                    port, 
                    status: result,
                    is_filtered: result == PortStatus::Filtered,
                    response_time: Some(scan_duration),
                    service_detected: None, // Will be filled in later for open ports
                }
            });
            
            tasks.push(task);
        }
        
        let mut port_results = join_all(tasks).await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        
        // Perform service detection on open ports and cache results
        for port_result in &mut port_results {
            if port_result.status == PortStatus::Open && port_result.service_detected.is_none() {
                // Only detect if not already cached
                port_result.service_detected = self.service_detector
                    .detect_service(target_ip, port_result.port)
                    .await;
            }
            
            // Cache the result for future scans
            GLOBAL_SCAN_CACHE.cache_result(
                target_ip,
                port_result.port,
                port_result.status,
                port_result.service_detected.clone(),
                scan_type,
            );
        }
        
        let end_time = chrono::Utc::now();
        let scan_duration = scan_start.elapsed();
        
        // Collect learning data for adaptive optimization
        let mut learning_port_results = Vec::new();
        let mut total_response_time = 0.0;
        let mut response_count = 0;
        let mut timeout_count = 0;
        
        for port_result in &port_results {
            let is_open = matches!(port_result.status, PortStatus::Open);
            let is_filtered = matches!(port_result.status, PortStatus::Filtered);
            
            // Use actual response times from scanning
            let response_time = port_result.response_time;
            if let Some(rt) = response_time {
                total_response_time += rt;
                response_count += 1;
            } else {
                timeout_count += 1;
            }
            
            learning_port_results.push(PortScanResult {
                port: port_result.port,
                is_open,
                is_filtered,
                response_time,
                service_detected: port_result.service_detected.as_ref().map(|s| s.name.clone()),
            });
        }
        
        let avg_response_time = if response_count > 0 { 
            total_response_time / response_count as f64 
        } else { 
            effective_timeout as f64 
        };
        
        let timeout_rate = timeout_count as f64 / port_results.len() as f64;
        let scan_performance = 1.0 - timeout_rate; // Simple performance metric
        
        let learning_data = ScanLearningData {
            target: target_ip,
            network_type: classify_network(target_ip),
            port_results: learning_port_results,
            scan_duration,
            avg_response_time,
            timeout_rate,
            parallelism_used: effective_parallelism as u16,
            rate_limit_used: effective_rate_limit,
            scan_performance,
        };
        
        // Learn from the scan results
        self.adaptive_learning.learn_from_scan(&learning_data);
        
        Ok(ScanResult {
            target: target_ip.to_string(),
            target_ip,
            scan_type,
            start_time,
            end_time,
            ports: port_results,
        })
    }
}