use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::scanner::results::ServiceInfo;
use crate::scanner::parallel_detector::ParallelProtocolDetector;
use crate::scanner::adaptive_service_detector::AdaptiveServiceDetector;

pub struct ServiceDetector {
    service_probes: HashMap<u16, Vec<ServiceProbe>>,
    parallel_detector: ParallelProtocolDetector,
    adaptive_detector: AdaptiveServiceDetector,
}

#[derive(Clone)]
struct ServiceProbe {
    name: String,
    probe_data: Vec<u8>,
    expected_response: Vec<u8>,
    version_regex: Option<String>,
}

impl ServiceDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            service_probes: HashMap::new(),
            parallel_detector: ParallelProtocolDetector::new(),
            adaptive_detector: AdaptiveServiceDetector::new(),
        };
        detector.load_default_probes();
        detector
    }
    
    fn load_default_probes(&mut self) {
        // HTTP detection
        self.add_probe(80, ServiceProbe {
            name: "HTTP".to_string(),
            probe_data: b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: PortScope\r\n\r\n".to_vec(),
            expected_response: b"HTTP/".to_vec(),
            version_regex: Some(r"Server: ([^\r\n]+)".to_string()),
        });
        
        self.add_probe(8080, ServiceProbe {
            name: "HTTP".to_string(),
            probe_data: b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: PortScope\r\n\r\n".to_vec(),
            expected_response: b"HTTP/".to_vec(),
            version_regex: Some(r"Server: ([^\r\n]+)".to_string()),
        });
        
        // HTTPS detection
        self.add_probe(443, ServiceProbe {
            name: "HTTPS".to_string(),
            probe_data: b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: PortScope\r\n\r\n".to_vec(),
            expected_response: b"HTTP/".to_vec(),
            version_regex: Some(r"Server: ([^\r\n]+)".to_string()),
        });
        
        // SSH detection
        self.add_probe(22, ServiceProbe {
            name: "SSH".to_string(),
            probe_data: b"SSH-2.0-PortScope\r\n".to_vec(),
            expected_response: b"SSH-".to_vec(),
            version_regex: Some(r"SSH-([0-9.]+[^\r\n]*)".to_string()),
        });
        
        // FTP detection
        self.add_probe(21, ServiceProbe {
            name: "FTP".to_string(),
            probe_data: b"USER anonymous\r\n".to_vec(),
            expected_response: b"220".to_vec(),
            version_regex: Some(r"220[- ]([^\r\n]+)".to_string()),
        });
        
        // SMTP detection
        self.add_probe(25, ServiceProbe {
            name: "SMTP".to_string(),
            probe_data: b"HELO mlscan\r\n".to_vec(),
            expected_response: b"220".to_vec(),
            version_regex: Some(r"220[- ]([^\r\n]+)".to_string()),
        });
        
        // DNS detection
        self.add_probe(53, ServiceProbe {
            name: "DNS".to_string(),
            probe_data: vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            expected_response: vec![0x12, 0x34],
            version_regex: None,
        });
        
        // MySQL detection
        self.add_probe(3306, ServiceProbe {
            name: "MySQL".to_string(),
            probe_data: vec![],
            expected_response: b"\x0a".to_vec(), // MySQL greeting packet starts with protocol version
            version_regex: Some(r"([0-9]+\.[0-9]+\.[0-9]+[^\x00]*)".to_string()),
        });
        
        // PostgreSQL detection
        self.add_probe(5432, ServiceProbe {
            name: "PostgreSQL".to_string(),
            probe_data: vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f],
            expected_response: b"SCRAM-SHA-256".to_vec(),
            version_regex: None,
        });
        
        // Redis detection
        self.add_probe(6379, ServiceProbe {
            name: "Redis".to_string(),
            probe_data: b"*1\r\n$4\r\nINFO\r\n".to_vec(),
            expected_response: b"redis_version:".to_vec(),
            version_regex: Some(r"redis_version:([^\r\n]+)".to_string()),
        });
    }
    
    fn add_probe(&mut self, port: u16, probe: ServiceProbe) {
        self.service_probes.entry(port).or_insert_with(Vec::new).push(probe);
    }
    
    pub async fn detect_service(&self, target: IpAddr, port: u16) -> Option<ServiceInfo> {
        // First, try traditional probe-based detection for known ports (faster)
        if let Some(port_probes) = self.service_probes.get(&port) {
            for probe in port_probes {
                if let Some(service_info) = self.try_probe(target, port, probe).await {
                    return Some(service_info);
                }
            }
        }
        
        // Then try parallel protocol detection for faster results
        if let Some(service_info) = self.parallel_detector.detect_service_parallel(target, port).await {
            return Some(service_info);
        }
        
        // For unknown ports or failed detection, use adaptive service detection
        if let Some(service_info) = self.adaptive_detector.detect_service_adaptive(target, port).await {
            return Some(service_info);
        }
        
        // Final fallback to generic service detection patterns
        self.generic_service_detection(target, port).await
    }
    
    async fn try_probe(&self, target: IpAddr, port: u16, probe: &ServiceProbe) -> Option<ServiceInfo> {
        let socket_addr = SocketAddr::new(target, port);
        
        // Try to connect and send probe
        let response = match timeout(Duration::from_millis(3000), async {
            let mut stream = tokio::net::TcpStream::connect(socket_addr).await?;
            
            if !probe.probe_data.is_empty() {
                stream.write_all(&probe.probe_data).await?;
            }
            
            let mut buffer = vec![0u8; 1024];
            let bytes_read = stream.read(&mut buffer).await?;
            buffer.truncate(bytes_read);
            
            Ok::<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>(buffer)
        }).await {
            Ok(Ok(response)) => response,
            _ => return None,
        };
        
        // Check if response matches expected pattern
        if response.windows(probe.expected_response.len())
            .any(|window| window == probe.expected_response) {
            
            let version = if let Some(ref regex_pattern) = probe.version_regex {
                self.extract_version(&response, regex_pattern)
            } else {
                None
            };
            
            return Some(ServiceInfo {
                name: probe.name.clone(),
                version,
                confidence: 0.9, // High confidence for probe-based detection
            });
        }
        
        None
    }
    
    async fn generic_service_detection(&self, target: IpAddr, port: u16) -> Option<ServiceInfo> {
        // For unknown ports, try to connect and analyze banner
        let socket_addr = SocketAddr::new(target, port);
        
        let response = match timeout(Duration::from_millis(2000), async {
            let mut stream = tokio::net::TcpStream::connect(socket_addr).await?;
            let mut buffer = vec![0u8; 512];
            let bytes_read = stream.read(&mut buffer).await?;
            buffer.truncate(bytes_read);
            Ok::<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>(buffer)
        }).await {
            Ok(Ok(response)) => response,
            _ => return None,
        };
        
        // Analyze response for common patterns
        let response_str = String::from_utf8_lossy(&response);
        
        if response_str.contains("HTTP/") {
            Some(ServiceInfo {
                name: "HTTP".to_string(),
                version: self.extract_version(&response, r"Server: ([^\r\n]+)"),
                confidence: 0.7,
            })
        } else if response_str.contains("SSH-") {
            Some(ServiceInfo {
                name: "SSH".to_string(),
                version: self.extract_version(&response, r"SSH-([0-9.]+[^\r\n]*)"),
                confidence: 0.8,
            })
        } else if response_str.starts_with("220") {
            Some(ServiceInfo {
                name: "SMTP/FTP".to_string(),
                version: self.extract_version(&response, r"220[- ]([^\r\n]+)"),
                confidence: 0.6,
            })
        } else if !response.is_empty() {
            Some(ServiceInfo {
                name: "Unknown".to_string(),
                version: None,
                confidence: 0.3,
            })
        } else {
            None
        }
    }
    
    fn extract_version(&self, response: &[u8], pattern: &str) -> Option<String> {
        let response_str = String::from_utf8_lossy(response);
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(captures) = re.captures(&response_str) {
                return captures.get(1).map(|m| m.as_str().to_string());
            }
        }
        None
    }
}