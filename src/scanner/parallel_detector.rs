// Parallel protocol detection engine for improved scanning performance
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use futures::future::join_all;

use crate::scanner::results::ServiceInfo;
use crate::scanner::protocol_detectors::{ProtocolDetector, ProtocolDetectionResult};
use crate::scanner::protocol_detectors::database_detectors::*;

#[allow(dead_code)]
pub struct ParallelProtocolDetector {
    detectors: Vec<Box<dyn ProtocolDetector + Send + Sync>>,
    max_concurrent_probes: usize,
    probe_timeout: Duration,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub detector_name: String,
    pub result: Option<ProtocolDetectionResult>,
    pub response_data: Vec<u8>,
    pub probe_duration: Duration,
}

#[allow(dead_code)]
impl ParallelProtocolDetector {
    pub fn new() -> Self {
        let mut detectors: Vec<Box<dyn ProtocolDetector + Send + Sync>> = Vec::new();
        
        // Add available protocol detectors
        detectors.push(Box::new(PostgreSQLDetector));
        detectors.push(Box::new(MongoDBDetector));
        detectors.push(Box::new(RedisDetector));
        
        Self {
            detectors,
            max_concurrent_probes: 10, // Limit concurrent network operations
            probe_timeout: Duration::from_millis(3000), // 3 second timeout per probe
        }
    }
    
    /// Detect service protocol in parallel using multiple detectors
    pub async fn detect_service_parallel(&self, target: IpAddr, port: u16) -> Option<ServiceInfo> {
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent_probes));
        let mut probe_tasks = Vec::new();
        
        // Create probe tasks for each detector
        for detector in &self.detectors {
            let sem = semaphore.clone();
            let detector_name = detector.name().to_string();
            let probe_data_list = detector.get_probe_data();
            
            // If detector has probe data, use it; otherwise use empty probe
            let probe_data = if probe_data_list.is_empty() {
                vec![Vec::new()]
            } else {
                probe_data_list
            };
            
            for probe in probe_data {
                let sem_clone = sem.clone();
                let probe_clone = probe.clone();
                let detector_name_clone = detector_name.clone();
                
                let task = tokio::spawn(async move {
                    let _permit = sem_clone.acquire().await.unwrap();
                    Self::execute_probe(target, port, detector_name_clone, probe_clone, Duration::from_millis(3000)).await
                });
                
                probe_tasks.push(task);
            }
        }
        
        // Execute all probes in parallel
        let probe_results = join_all(probe_tasks).await;
        
        // Collect successful results
        let mut results = Vec::new();
        for result in probe_results {
            if let Ok(probe_result) = result {
                if let Some(detection_result) = &probe_result.result {
                    results.push((detection_result.clone(), probe_result.probe_duration));
                }
            }
        }
        
        // Find the best result (highest confidence)
        if let Some((best_result, _duration)) = results.into_iter()
            .max_by(|a, b| a.0.confidence.partial_cmp(&b.0.confidence).unwrap_or(std::cmp::Ordering::Equal)) {
            
            Some(ServiceInfo {
                name: best_result.service_name,
                version: best_result.version,
                confidence: best_result.confidence,
            })
        } else {
            None
        }
    }
    
    /// Execute a single probe against a target
    async fn execute_probe(
        target: IpAddr, 
        port: u16, 
        detector_name: String, 
        probe_data: Vec<u8>,
        timeout_duration: Duration
    ) -> ProbeResult {
        let start_time = std::time::Instant::now();
        let addr = SocketAddr::new(target, port);
        
        let response_data = match timeout(timeout_duration, async {
            let mut stream = TcpStream::connect(addr).await?;
            
            if !probe_data.is_empty() {
                stream.write_all(&probe_data).await?;
            }
            
            let mut buffer = vec![0u8; 4096];
            let bytes_read = stream.read(&mut buffer).await?;
            buffer.truncate(bytes_read);
            
            Ok::<Vec<u8>, std::io::Error>(buffer)
        }).await {
            Ok(Ok(data)) => data,
            _ => Vec::new(),
        };
        
        let probe_duration = start_time.elapsed();
        
        // Try to detect protocol from response
        let result = if !response_data.is_empty() {
            Self::analyze_response(&detector_name, &response_data)
        } else {
            None
        };
        
        ProbeResult {
            detector_name,
            result,
            response_data,
            probe_duration,
        }
    }
    
    /// Analyze response data using the appropriate detector
    fn analyze_response(detector_name: &str, response_data: &[u8]) -> Option<ProtocolDetectionResult> {
        match detector_name {
            "PostgreSQL" => PostgreSQLDetector.detect(response_data),
            "MongoDB" => MongoDBDetector.detect(response_data),
            "Redis" => RedisDetector.detect(response_data),
            _ => None,
        }
    }
    
    /// Get statistics about detection performance
    pub fn get_detector_stats(&self) -> HashMap<String, u32> {
        let mut stats = HashMap::new();
        for detector in &self.detectors {
            stats.insert(detector.name().to_string(), 0);
        }
        stats
    }
    
    /// Add a custom detector to the parallel detector
    pub fn add_detector(&mut self, detector: Box<dyn ProtocolDetector + Send + Sync>) {
        self.detectors.push(detector);
    }
    
    /// Configure parallel detection parameters
    pub fn configure(&mut self, max_concurrent: usize, timeout_ms: u64) {
        self.max_concurrent_probes = max_concurrent;
        self.probe_timeout = Duration::from_millis(timeout_ms);
    }
}