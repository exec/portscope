// Adaptive Service Detector - Port-agnostic service identification
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use futures::future::join_all;

use crate::scanner::results::ServiceInfo;

#[derive(Debug, Clone)]
pub struct ServiceProbe {
    pub name: String,
    pub probe_data: Vec<u8>,
    pub expected_patterns: Vec<Vec<u8>>,
    pub confidence_if_match: f32,
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub probe_name: String,
    pub response: Vec<u8>,
    pub matched: bool,
    pub confidence: f32,
    pub service_name: String,
}

pub struct AdaptiveServiceDetector {
    probes: Vec<ServiceProbe>,
    service_signatures: HashMap<String, Vec<ServiceSignature>>,
}

#[derive(Debug, Clone)]
struct ServiceSignature {
    pattern: Vec<u8>,
    service_name: String,
    confidence: f32,
    offset: usize, // Where in response to look for pattern
}

impl AdaptiveServiceDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            probes: Vec::new(),
            service_signatures: HashMap::new(),
        };
        detector.load_probes();
        detector.load_signatures();
        detector
    }
    
    fn load_probes(&mut self) {
        // HTTP probes
        self.probes.push(ServiceProbe {
            name: "HTTP-GET".to_string(),
            probe_data: b"GET / HTTP/1.1\r\nHost: test\r\nUser-Agent: MLScan\r\n\r\n".to_vec(),
            expected_patterns: vec![
                b"HTTP/".to_vec(),
                b"Content-Type".to_vec(),
                b"Server:".to_vec(),
            ],
            confidence_if_match: 0.9,
        });
        
        // HTTPS/TLS probe
        self.probes.push(ServiceProbe {
            name: "TLS-ClientHello".to_string(),
            probe_data: self.create_tls_client_hello(),
            expected_patterns: vec![
                vec![0x16, 0x03], // TLS handshake
                vec![0x15, 0x03], // TLS alert
            ],
            confidence_if_match: 0.95,
        });
        
        // SSH probe
        self.probes.push(ServiceProbe {
            name: "SSH-Version".to_string(),
            probe_data: Vec::new(), // SSH sends banner first
            expected_patterns: vec![
                b"SSH-".to_vec(),
                b"OpenSSH".to_vec(),
            ],
            confidence_if_match: 0.95,
        });
        
        // FTP probe
        self.probes.push(ServiceProbe {
            name: "FTP-Banner".to_string(),
            probe_data: Vec::new(), // FTP sends banner first
            expected_patterns: vec![
                b"220".to_vec(),
                b"FTP".to_vec(),
                b"FileZilla".to_vec(),
                b"vsftpd".to_vec(),
            ],
            confidence_if_match: 0.9,
        });
        
        // SMTP probe
        self.probes.push(ServiceProbe {
            name: "SMTP-EHLO".to_string(),
            probe_data: b"EHLO test.local\r\n".to_vec(),
            expected_patterns: vec![
                b"250".to_vec(),
                b"SMTP".to_vec(),
                b"ESMTP".to_vec(),
            ],
            confidence_if_match: 0.9,
        });
        
        // DNS probe (TCP)
        self.probes.push(ServiceProbe {
            name: "DNS-Query".to_string(),
            probe_data: self.create_dns_query(),
            expected_patterns: vec![
                vec![0x12, 0x34], // Our transaction ID
                vec![0x81, 0x80], // DNS response flags
            ],
            confidence_if_match: 0.85,
        });
        
        // Database probes
        self.probes.push(ServiceProbe {
            name: "MySQL-Handshake".to_string(),
            probe_data: Vec::new(), // MySQL sends handshake first
            expected_patterns: vec![
                vec![0x0a], // Protocol version 10
                b"mysql_native_password".to_vec(),
            ],
            confidence_if_match: 0.9,
        });
        
        self.probes.push(ServiceProbe {
            name: "PostgreSQL-StartupMessage".to_string(),
            probe_data: vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f], // SSL request
            expected_patterns: vec![
                b"S".to_vec(), // SSL supported
                b"N".to_vec(), // SSL not supported
            ],
            confidence_if_match: 0.85,
        });
        
        self.probes.push(ServiceProbe {
            name: "Redis-PING".to_string(),
            probe_data: b"*1\r\n$4\r\nPING\r\n".to_vec(),
            expected_patterns: vec![
                b"+PONG".to_vec(),
                b"-NOAUTH".to_vec(),
                b"-ERR".to_vec(),
            ],
            confidence_if_match: 0.9,
        });
        
        // Generic protocol probes
        self.probes.push(ServiceProbe {
            name: "Banner-Grab".to_string(),
            probe_data: Vec::new(),
            expected_patterns: vec![], // We'll analyze any response
            confidence_if_match: 0.3, // Low confidence for generic probe
        });
    }
    
    fn load_signatures(&mut self) {
        // HTTP signatures
        let http_sigs = vec![
            ServiceSignature {
                pattern: b"Apache".to_vec(),
                service_name: "Apache HTTP Server".to_string(),
                confidence: 0.9,
                offset: 0,
            },
            ServiceSignature {
                pattern: b"nginx".to_vec(),
                service_name: "nginx".to_string(),
                confidence: 0.9,
                offset: 0,
            },
            ServiceSignature {
                pattern: b"IIS".to_vec(),
                service_name: "Microsoft IIS".to_string(),
                confidence: 0.9,
                offset: 0,
            },
            ServiceSignature {
                pattern: b"lighttpd".to_vec(),
                service_name: "lighttpd".to_string(),
                confidence: 0.9,
                offset: 0,
            },
        ];
        self.service_signatures.insert("HTTP".to_string(), http_sigs);
        
        // SSH signatures
        let ssh_sigs = vec![
            ServiceSignature {
                pattern: b"OpenSSH".to_vec(),
                service_name: "OpenSSH".to_string(),
                confidence: 0.95,
                offset: 0,
            },
            ServiceSignature {
                pattern: b"dropbear".to_vec(),
                service_name: "Dropbear SSH".to_string(),
                confidence: 0.95,
                offset: 0,
            },
        ];
        self.service_signatures.insert("SSH".to_string(), ssh_sigs);
    }
    
    /// Port-agnostic service detection - tries all probes regardless of port
    pub async fn detect_service_adaptive(&self, target: IpAddr, port: u16) -> Option<ServiceInfo> {
        let mut probe_tasks = Vec::new();
        
        // Execute all probes in parallel
        for probe in &self.probes {
            let probe_clone = probe.clone();
            let task = tokio::spawn(async move {
                Self::execute_probe(target, port, probe_clone).await
            });
            probe_tasks.push(task);
        }
        
        // Wait for all probes to complete
        let probe_results = join_all(probe_tasks).await;
        let mut results: Vec<ProbeResult> = probe_results
            .into_iter()
            .filter_map(|result| result.ok())
            .collect();
        
        // Sort by confidence (highest first)
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        
        // Return the best result if we have one
        if let Some(best_result) = results.first() {
            if best_result.confidence > 0.5 {
                return Some(ServiceInfo {
                    name: best_result.service_name.clone(),
                    version: self.extract_version(&best_result.response, &best_result.service_name),
                    confidence: best_result.confidence,
                });
            }
        }
        
        None
    }
    
    async fn execute_probe(target: IpAddr, port: u16, probe: ServiceProbe) -> ProbeResult {
        let addr = SocketAddr::new(target, port);
        
        // Try to connect and execute probe
        let response = match timeout(Duration::from_millis(2000), async {
            let mut stream = TcpStream::connect(addr).await?;
            
            if !probe.probe_data.is_empty() {
                stream.write_all(&probe.probe_data).await?;
                tokio::time::sleep(Duration::from_millis(200)).await;
            } else {
                // For banner grabs, wait for server to send data
                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
            
            let mut buffer = vec![0u8; 4096];
            let bytes_read = stream.read(&mut buffer).await?;
            buffer.truncate(bytes_read);
            
            Ok::<Vec<u8>, std::io::Error>(buffer)
        }).await {
            Ok(Ok(data)) => data,
            _ => Vec::new(),
        };
        
        // Analyze response
        let (matched, confidence, service_name) = Self::analyze_response(&probe, &response);
        
        ProbeResult {
            probe_name: probe.name,
            response,
            matched,
            confidence,
            service_name,
        }
    }
    
    fn analyze_response(probe: &ServiceProbe, response: &[u8]) -> (bool, f32, String) {
        if response.is_empty() {
            return (false, 0.0, "Unknown".to_string());
        }
        
        let text = String::from_utf8_lossy(response).to_lowercase();
        
        // Check for expected patterns
        for pattern in &probe.expected_patterns {
            if Self::contains_pattern(response, pattern) {
                let service_name = Self::identify_specific_service(&probe.name, response, &text);
                return (true, probe.confidence_if_match, service_name);
            }
        }
        
        // For generic probes, try to identify service from response
        if probe.name == "Banner-Grab" && !response.is_empty() {
            let service_name = Self::identify_from_banner(response, &text);
            if !service_name.is_empty() {
                return (true, 0.7, service_name);
            }
        }
        
        (false, 0.0, "Unknown".to_string())
    }
    
    fn identify_specific_service(probe_name: &str, response: &[u8], text: &str) -> String {
        match probe_name {
            "HTTP-GET" => {
                if text.contains("apache") {
                    "Apache HTTP Server".to_string()
                } else if text.contains("nginx") {
                    "nginx".to_string()
                } else if text.contains("iis") {
                    "Microsoft IIS".to_string()
                } else {
                    "HTTP Server".to_string()
                }
            }
            "TLS-ClientHello" => "TLS/SSL Server".to_string(),
            "SSH-Version" => {
                if text.contains("openssh") {
                    "OpenSSH".to_string()
                } else if text.contains("dropbear") {
                    "Dropbear SSH".to_string()
                } else {
                    "SSH Server".to_string()
                }
            }
            "FTP-Banner" => {
                if text.contains("filezilla") {
                    "FileZilla FTP".to_string()
                } else if text.contains("vsftpd") {
                    "vsftpd".to_string()
                } else {
                    "FTP Server".to_string()
                }
            }
            "SMTP-EHLO" => "SMTP Server".to_string(),
            "DNS-Query" => "DNS Server".to_string(),
            "MySQL-Handshake" => "MySQL Database".to_string(),
            "PostgreSQL-StartupMessage" => "PostgreSQL Database".to_string(),
            "Redis-PING" => "Redis Database".to_string(),
            _ => "Unknown Service".to_string(),
        }
    }
    
    fn identify_from_banner(response: &[u8], text: &str) -> String {
        if text.starts_with("ssh-") {
            "SSH Server".to_string()
        } else if text.starts_with("220") && text.contains("ftp") {
            "FTP Server".to_string()
        } else if text.starts_with("220") && text.contains("smtp") {
            "SMTP Server".to_string()
        } else if text.contains("http") && (text.contains("server:") || text.contains("content-type")) {
            "HTTP Server".to_string()
        } else {
            String::new()
        }
    }
    
    fn contains_pattern(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return false;
        }
        
        haystack.windows(needle.len()).any(|window| window == needle)
    }
    
    fn extract_version(&self, response: &[u8], service_name: &str) -> Option<String> {
        let text = String::from_utf8_lossy(response);
        
        match service_name {
            s if s.contains("OpenSSH") => {
                if let Some(start) = text.find("OpenSSH_") {
                    if let Some(end) = text[start..].find(' ') {
                        return Some(text[start + 8..start + end].to_string());
                    }
                }
            }
            s if s.contains("Apache") => {
                if let Some(start) = text.find("Apache/") {
                    if let Some(end) = text[start..].find(' ') {
                        return Some(text[start + 7..start + end].to_string());
                    }
                }
            }
            s if s.contains("nginx") => {
                if let Some(start) = text.find("nginx/") {
                    if let Some(end) = text[start..].find(' ') {
                        return Some(text[start + 6..start + end].to_string());
                    }
                }
            }
            _ => {}
        }
        
        None
    }
    
    fn create_tls_client_hello(&self) -> Vec<u8> {
        vec![
            0x16, 0x03, 0x01, 0x00, 0x2c,  // TLS Record Header
            0x01, 0x00, 0x00, 0x28,        // Handshake Header
            0x03, 0x03,                    // TLS 1.2
            // Random (32 bytes of zeros for simplicity)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,                          // Session ID length
            0x00, 0x02,                    // Cipher suites length
            0x00, 0x35,                    // TLS_RSA_WITH_AES_256_CBC_SHA
            0x01, 0x00                     // Compression methods
        ]
    }
    
    fn create_dns_query(&self) -> Vec<u8> {
        vec![
            0x12, 0x34,             // Transaction ID
            0x01, 0x00,             // Flags (standard query)
            0x00, 0x01,             // Questions: 1
            0x00, 0x00,             // Answer RRs: 0
            0x00, 0x00,             // Authority RRs: 0
            0x00, 0x00,             // Additional RRs: 0
            // Query: google.com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // "google"
            0x03, 0x63, 0x6f, 0x6d,                     // "com"
            0x00,                   // End of name
            0x00, 0x01,             // Type: A
            0x00, 0x01              // Class: IN
        ]
    }
}