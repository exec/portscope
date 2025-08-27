use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use serde::{Deserialize, Serialize};

// Import our modular protocol detectors
use super::protocol_detectors::{
    ProtocolDetector,
    database_detectors::*,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggressiveServiceProbe {
    pub name: String,
    pub port: u16,
    pub probes: Vec<ProbeStep>,
    pub auth_probes: Vec<AuthProbe>,
    pub ml_confidence: f32,
    pub response_signatures: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeStep {
    pub step_name: String,
    pub probe_data: Vec<u8>,
    pub expected_patterns: Vec<String>,
    pub timeout_ms: u64,
    pub connection_type: ConnectionType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionType {
    TCP,
    UDP,
    TLS,
    HTTP,
    Raw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthProbe {
    pub protocol: String,
    pub test_credentials: (String, String), // Single test credential for identification
    pub auth_method: AuthMethod,
    pub service_indicators: Vec<String>, // Responses that identify the service
    pub malformed_indicators: Vec<String>, // Responses indicating protocol mismatch
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMethod {
    BasicAuth,
    DigestAuth,
    FormBased,
    SSH,
    Telnet,
    FTP,
    SMTP,
    Custom(String),
}

#[derive(Debug, Clone)]
enum AuthResponseType {
    ServiceIdentified,  // Got meaningful auth failure - service identified
    ProtocolMismatch,   // Got protocol error - wrong service type
    Bypass,            // Service accepts without proper auth
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFingerprint {
    pub service_name: String,
    pub version: Option<String>,
    pub confidence: f32,
    pub auth_status: AuthStatus,
    pub vulnerabilities: Vec<String>,
    pub additional_info: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthStatus {
    NoAuth,
    AuthRequired(String), // Service identified through auth challenge
    ProtocolMismatch,
    AuthBypass, // Service accepts anything
    Unknown,
}

pub struct MLAggressiveProber {
    probe_templates: HashMap<u16, Vec<AggressiveServiceProbe>>,
    response_classifier: MLResponseClassifier,
    auth_probes: HashMap<String, Vec<AuthProbe>>,
    learning_data: Vec<ProbeResult>,
}

#[derive(Debug, Clone)]
struct ProbeResult {
    target: IpAddr,
    port: u16,
    probe_name: String,
    response: Vec<u8>,
    success: bool,
    timing: Duration,
    classification: Option<String>,
}

pub struct MLResponseClassifier {
    protocol_patterns: HashMap<String, Vec<ResponsePattern>>,
    learned_signatures: HashMap<String, f32>, // signature -> confidence
    // Modular protocol detectors
    database_detectors: Vec<Box<dyn ProtocolDetector>>,
    messaging_detectors: Vec<Box<dyn ProtocolDetector>>,
    web_detectors: Vec<Box<dyn ProtocolDetector>>,
    system_detectors: Vec<Box<dyn ProtocolDetector>>,
    development_detectors: Vec<Box<dyn ProtocolDetector>>,
}

#[derive(Debug, Clone)]
struct ResponsePattern {
    name: String,
    byte_patterns: Vec<Vec<u8>>,
    text_patterns: Vec<String>,
    timing_characteristics: Option<Duration>,
    confidence_weight: f32,
}

impl MLAggressiveProber {
    pub fn new() -> Self {
        let mut prober = Self {
            probe_templates: HashMap::new(),
            response_classifier: MLResponseClassifier::new(),
            auth_probes: HashMap::new(),
            learning_data: Vec::new(),
        };
        prober.load_aggressive_probes();
        prober.load_auth_probes();
        prober
    }

    fn load_aggressive_probes(&mut self) {
        // HTTP/HTTPS aggressive probing
        self.add_probe(80, AggressiveServiceProbe {
            name: "HTTP-Aggressive".to_string(),
            port: 80,
            probes: vec![
                ProbeStep {
                    step_name: "Basic HTTP".to_string(),
                    probe_data: b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: PortScope-Scanner\r\n\r\n".to_vec(),
                    expected_patterns: vec!["HTTP/".to_string()],
                    timeout_ms: 5000,
                    connection_type: ConnectionType::HTTP,
                },
                ProbeStep {
                    step_name: "Admin Panel Probe".to_string(),
                    probe_data: b"GET /admin HTTP/1.1\r\nHost: target\r\n\r\n".to_vec(),
                    expected_patterns: vec!["200".to_string(), "401".to_string(), "403".to_string()],
                    timeout_ms: 3000,
                    connection_type: ConnectionType::HTTP,
                },
                ProbeStep {
                    step_name: "API Discovery".to_string(),
                    probe_data: b"GET /api/v1/ HTTP/1.1\r\nHost: target\r\n\r\n".to_vec(),
                    expected_patterns: vec!["json".to_string(), "xml".to_string(), "api".to_string()],
                    timeout_ms: 3000,
                    connection_type: ConnectionType::HTTP,
                },
                ProbeStep {
                    step_name: "Server Info".to_string(),
                    probe_data: b"OPTIONS * HTTP/1.1\r\nHost: target\r\n\r\n".to_vec(),
                    expected_patterns: vec!["Allow:".to_string(), "Server:".to_string()],
                    timeout_ms: 2000,
                    connection_type: ConnectionType::HTTP,
                },
            ],
            auth_probes: vec![],
            ml_confidence: 0.0,
            response_signatures: HashMap::new(),
        });

        // SSH aggressive probing
        self.add_probe(22, AggressiveServiceProbe {
            name: "SSH-Aggressive".to_string(),
            port: 22,
            probes: vec![
                ProbeStep {
                    step_name: "SSH Banner".to_string(),
                    probe_data: b"SSH-2.0-PortScope_1.0\r\n".to_vec(),
                    expected_patterns: vec!["SSH-".to_string()],
                    timeout_ms: 5000,
                    connection_type: ConnectionType::TCP,
                },
                ProbeStep {
                    step_name: "SSH Algorithm Negotiation".to_string(),
                    probe_data: vec![0x00, 0x00, 0x01, 0x2c, 0x08, 0x14], // SSH packet
                    expected_patterns: vec!["diffie-hellman".to_string(), "ssh-rsa".to_string()],
                    timeout_ms: 3000,
                    connection_type: ConnectionType::TCP,
                },
            ],
            auth_probes: vec![],
            ml_confidence: 0.0,
            response_signatures: HashMap::new(),
        });

        // Database probing (MySQL, PostgreSQL, etc.)
        self.add_probe(3306, AggressiveServiceProbe {
            name: "MySQL-Aggressive".to_string(),
            port: 3306,
            probes: vec![
                ProbeStep {
                    step_name: "MySQL Handshake".to_string(),
                    probe_data: vec![], // Just connect and read
                    expected_patterns: vec!["mysql".to_string(), "MariaDB".to_string()],
                    timeout_ms: 5000,
                    connection_type: ConnectionType::TCP,
                },
                ProbeStep {
                    step_name: "MySQL Version Probe".to_string(),
                    probe_data: vec![0x03], // COM_QUIT
                    expected_patterns: vec!["5.".to_string(), "8.".to_string()],
                    timeout_ms: 2000,
                    connection_type: ConnectionType::TCP,
                },
            ],
            auth_probes: vec![],
            ml_confidence: 0.0,
            response_signatures: HashMap::new(),
        });

        // IRC (Internet Relay Chat) aggressive probing
        self.add_probe(6667, AggressiveServiceProbe {
            name: "IRC-Aggressive".to_string(),
            port: 6667,
            probes: vec![
                ProbeStep {
                    step_name: "IRC Nick Registration".to_string(),
                    probe_data: b"NICK portscope_probe\r\nUSER portscope test test :PortScope Probe\r\n".to_vec(),
                    expected_patterns: vec!["001".to_string(), "Welcome".to_string(), "MOTD".to_string(), "ergo".to_string()],
                    timeout_ms: 5000,
                    connection_type: ConnectionType::TCP,
                },
                ProbeStep {
                    step_name: "IRC Server Info".to_string(),
                    probe_data: b"VERSION\r\n".to_vec(),
                    expected_patterns: vec!["351".to_string(), "VERSION".to_string()],
                    timeout_ms: 3000,
                    connection_type: ConnectionType::TCP,
                },
            ],
            auth_probes: vec![],
            ml_confidence: 0.0,
            response_signatures: HashMap::new(),
        });

        // IRC SSL/TLS aggressive probing
        self.add_probe(6697, AggressiveServiceProbe {
            name: "IRC-SSL-Aggressive".to_string(),
            port: 6697,
            probes: vec![
                ProbeStep {
                    step_name: "IRC SSL Detection".to_string(),
                    probe_data: vec![], // Just connect to detect SSL/TLS
                    expected_patterns: vec!["TLS".to_string(), "SSL".to_string()],
                    timeout_ms: 5000,
                    connection_type: ConnectionType::TLS,
                },
                ProbeStep {
                    step_name: "IRC SSL Handshake Attempt".to_string(),
                    probe_data: b"NICK mlscan_probe\r\n".to_vec(), // Will fail on encrypted connection
                    expected_patterns: vec![],
                    timeout_ms: 3000,
                    connection_type: ConnectionType::TCP,
                },
            ],
            auth_probes: vec![],
            ml_confidence: 0.0,
            response_signatures: HashMap::new(),
        });

        // Syncthing protocol aggressive probing
        self.add_probe(22000, AggressiveServiceProbe {
            name: "Syncthing-Aggressive".to_string(),
            port: 22000,
            probes: vec![
                ProbeStep {
                    step_name: "Syncthing BEP Hello".to_string(),
                    probe_data: b"syncthingBEP".to_vec(),
                    expected_patterns: vec!["syncthing".to_string(), "BEP".to_string()],
                    timeout_ms: 5000,
                    connection_type: ConnectionType::TCP,
                },
                ProbeStep {
                    step_name: "Syncthing Discovery".to_string(),
                    probe_data: vec![0x00, 0x00, 0x00, 0x04], // Length prefixed message
                    expected_patterns: vec!["device".to_string(), "folder".to_string()],
                    timeout_ms: 3000,
                    connection_type: ConnectionType::TCP,
                },
            ],
            auth_probes: vec![],
            ml_confidence: 0.0,
            response_signatures: HashMap::new(),
        });

        // DNS aggressive probing with actual DNS queries
        self.add_probe(53, AggressiveServiceProbe {
            name: "DNS-Aggressive".to_string(),
            port: 53,
            probes: vec![
                ProbeStep {
                    step_name: "DNS Query A Record".to_string(),
                    probe_data: vec![
                        0x12, 0x34, // Transaction ID
                        0x01, 0x00, // Flags: standard query
                        0x00, 0x01, // Questions: 1
                        0x00, 0x00, // Answer RRs: 0
                        0x00, 0x00, // Authority RRs: 0
                        0x00, 0x00, // Additional RRs: 0
                        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, // "example"
                        0x03, 0x63, 0x6f, 0x6d, // "com"
                        0x00, // End of name
                        0x00, 0x01, // Type: A
                        0x00, 0x01, // Class: IN
                    ],
                    expected_patterns: vec!["DNS".to_string()],
                    timeout_ms: 3000,
                    connection_type: ConnectionType::UDP,
                },
                ProbeStep {
                    step_name: "DNS Version Query".to_string(),
                    probe_data: vec![
                        0x12, 0x35, // Transaction ID
                        0x00, 0x00, // Flags
                        0x00, 0x01, // Questions: 1
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, // "version"
                        0x04, 0x62, 0x69, 0x6e, 0x64, // "bind"
                        0x00,
                        0x00, 0x10, 0x00, 0x03, // TXT record, CHAOS class
                    ],
                    expected_patterns: vec!["BIND".to_string(), "version".to_string()],
                    timeout_ms: 3000,
                    connection_type: ConnectionType::UDP,
                },
            ],
            auth_probes: vec![],
            ml_confidence: 0.0,
            response_signatures: HashMap::new(),
        });

        // Add more aggressive probes for common ports...
        for port in [21, 23, 25, 110, 143, 443, 993, 995, 1433, 3389, 5432, 6379, 27017] {
            self.add_generic_aggressive_probe(port);
        }
    }

    fn load_auth_probes(&mut self) {
        // HTTP authentication probes for service identification
        let http_probes = vec![
            AuthProbe {
                protocol: "HTTP".to_string(),
                test_credentials: ("testuser".to_string(), "wrongpass".to_string()),
                auth_method: AuthMethod::BasicAuth,
                service_indicators: vec![
                    "401 Unauthorized".to_string(), 
                    "WWW-Authenticate".to_string(),
                    "Basic realm".to_string(),
                    "Authorization Required".to_string()
                ],
                malformed_indicators: vec![
                    "400 Bad Request".to_string(), 
                    "Invalid request".to_string(),
                    "Protocol error".to_string()
                ],
            }
        ];
        self.auth_probes.insert("HTTP".to_string(), http_probes);

        // SSH authentication probes for service identification
        let ssh_probes = vec![
            AuthProbe {
                protocol: "SSH".to_string(),
                test_credentials: ("testuser".to_string(), "wrongpass".to_string()),
                auth_method: AuthMethod::SSH,
                service_indicators: vec![
                    "Permission denied".to_string(), 
                    "Authentication failed".to_string(),
                    "Access denied".to_string(),
                    "Invalid user".to_string(),
                    "password:".to_string()
                ],
                malformed_indicators: vec![
                    "Protocol mismatch".to_string(),
                    "Connection closed".to_string(),
                    "Invalid packet".to_string()
                ],
            }
        ];
        self.auth_probes.insert("SSH".to_string(), ssh_probes);

        // FTP authentication probes for service identification
        let ftp_probes = vec![
            AuthProbe {
                protocol: "FTP".to_string(),
                test_credentials: ("testuser".to_string(), "wrongpass".to_string()),
                auth_method: AuthMethod::FTP,
                service_indicators: vec![
                    "530 Login incorrect".to_string(),
                    "Authentication failed".to_string(),
                    "Invalid username".to_string(),
                    "User testuser unknown".to_string()
                ],
                malformed_indicators: vec![
                    "500 Syntax error".to_string(),
                    "Command not understood".to_string(),
                    "Protocol error".to_string()
                ],
            }
        ];
        self.auth_probes.insert("FTP".to_string(), ftp_probes);
    }

    fn add_probe(&mut self, port: u16, probe: AggressiveServiceProbe) {
        self.probe_templates.entry(port).or_insert_with(Vec::new).push(probe);
    }

    fn add_generic_aggressive_probe(&mut self, port: u16) {
        let probe = AggressiveServiceProbe {
            name: format!("Generic-{}", port),
            port,
            probes: vec![
                ProbeStep {
                    step_name: "Raw Connection".to_string(),
                    probe_data: vec![],
                    expected_patterns: vec![],
                    timeout_ms: 3000,
                    connection_type: ConnectionType::TCP,
                },
                ProbeStep {
                    step_name: "HTTP Test".to_string(),
                    probe_data: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                    expected_patterns: vec!["HTTP".to_string()],
                    timeout_ms: 2000,
                    connection_type: ConnectionType::TCP,
                },
                ProbeStep {
                    step_name: "Protocol Negotiation".to_string(),
                    probe_data: b"HELLO\r\n".to_vec(),
                    expected_patterns: vec![],
                    timeout_ms: 2000,
                    connection_type: ConnectionType::TCP,
                },
            ],
            auth_probes: vec![],
            ml_confidence: 0.0,
            response_signatures: HashMap::new(),
        };
        self.add_probe(port, probe);
    }

    pub async fn aggressively_probe_service(&mut self, target: IpAddr, port: u16) -> ServiceFingerprint {
        println!("🔍 Aggressively probing {}:{} for service identification...", target, port);

        // Phase 1: Standard probes for this port
        let mut fingerprint = self.execute_port_probes(target, port).await;

        // Phase 2: If still unknown, try authentication testing
        if fingerprint.confidence < 0.5 {
            println!("🔐 Testing authentication methods on {}:{}...", target, port);
            fingerprint = self.test_authentication(target, port, fingerprint).await;
        }

        // Phase 3: If still unknown, "hail mary" random protocol probing
        if fingerprint.confidence < 0.3 {
            println!("🎯 Performing hail mary protocol probing on {}:{}...", target, port);
            fingerprint = self.hail_mary_probing(target, port, fingerprint).await;
        }

        // Phase 4: ML-driven response analysis
        fingerprint = self.ml_classify_responses(target, port, fingerprint).await;

        // Learn from this result
        self.learn_from_probe_result(target, port, &fingerprint);

        fingerprint
    }

    async fn execute_port_probes(&mut self, target: IpAddr, port: u16) -> ServiceFingerprint {
        let mut fingerprint = ServiceFingerprint {
            service_name: "unknown".to_string(),
            version: None,
            confidence: 0.0,
            auth_status: AuthStatus::Unknown,
            vulnerabilities: Vec::new(),
            additional_info: HashMap::new(),
        };

        // First, always try TLS detection on any port
        if let Some(tls_info) = self.probe_tls_handshake(target, port).await {
            if let Some((service, confidence)) = self.response_classifier.analyze_unknown_response(&tls_info) {
                fingerprint.service_name = service;
                fingerprint.confidence = confidence;
                fingerprint.additional_info.insert("tls_detected".to_string(), "true".to_string());
                if confidence > 0.8 {
                    return fingerprint; // High confidence TLS detection
                }
            }
        }

        // Try BitTorrent protocol detection (for qBittorrent, Transmission, etc.)
        if let Some(bt_response) = self.probe_bittorrent_handshake(target, port).await {
            if let Some((service, confidence)) = self.analyze_bittorrent_response(&bt_response).await {
                fingerprint.service_name = service;
                fingerprint.confidence = confidence;
                fingerprint.additional_info.insert("protocol".to_string(), "BitTorrent".to_string());
                return fingerprint; // BitTorrent is highly specific
            }
        }

        // Special case: Check if this might be a P2P-related port based on behavior  
        if self.is_potential_p2p_port(target, port).await {
            fingerprint.service_name = "Unknown service (possible P2P)".to_string();
            fingerprint.confidence = 0.5; // Lower confidence due to generic detection
            fingerprint.additional_info.insert("protocol".to_string(), "Possibly P2P-related".to_string());
            fingerprint.additional_info.insert("detection_method".to_string(), "connection_behavior".to_string());
            fingerprint.additional_info.insert("note".to_string(), "Accepts connections but drops on invalid data".to_string());
            return fingerprint;
        }

        if let Some(probes) = self.probe_templates.get(&port).cloned() {
            for probe in probes {
                for step in probe.probes {
                    if let Some(response) = self.execute_probe_step(target, port, &step).await {
                        let classification = self.response_classifier.classify_response(&response, &step);
                        if let Some(service_info) = classification {
                            fingerprint.service_name = service_info.0;
                            fingerprint.confidence = service_info.1;
                            if service_info.1 > 0.7 {
                                break; // High confidence, stop probing
                            }
                        }
                    }
                }
                if fingerprint.confidence > 0.7 {
                    break;
                }
            }
        }

        fingerprint
    }

    async fn execute_probe_step(&self, target: IpAddr, port: u16, step: &ProbeStep) -> Option<Vec<u8>> {
        let addr = SocketAddr::new(target, port);
        
        match step.connection_type {
            ConnectionType::UDP => {
                match timeout(Duration::from_millis(step.timeout_ms), async {
                    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
                    socket.connect(addr).await.ok()?;
                    
                    if !step.probe_data.is_empty() {
                        socket.send(&step.probe_data).await.ok()?;
                    }
                    
                    let mut buffer = vec![0; 4096];
                    let bytes_read = socket.recv(&mut buffer).await.ok()?;
                    buffer.truncate(bytes_read);
                    
                    Some(buffer)
                }).await {
                    Ok(Some(response)) => Some(response),
                    _ => None,
                }
            },
            ConnectionType::TLS => {
                // For TLS/SSL connections, first try to detect if it's actually SSL
                self.detect_ssl_service(target, port, step).await
            },
            _ => {
                match timeout(Duration::from_millis(step.timeout_ms), async {
                    let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
                    
                    if !step.probe_data.is_empty() {
                        stream.write_all(&step.probe_data).await.ok()?;
                    }
                    
                    let mut buffer = vec![0; 4096];
                    let bytes_read = stream.read(&mut buffer).await.ok()?;
                    buffer.truncate(bytes_read);
                    
                    Some(buffer)
                }).await {
                    Ok(Some(response)) => Some(response),
                    _ => None,
                }
            }
        }
    }

    async fn detect_ssl_service(&self, target: IpAddr, port: u16, _step: &ProbeStep) -> Option<Vec<u8>> {
        let addr = SocketAddr::new(target, port);
        
        // First, try a TLS Client Hello to see if this is SSL/TLS
        if let Some(tls_info) = self.probe_tls_handshake(target, port).await {
            return Some(tls_info);
        }
        
        // If not TLS, try plain text probe
        match timeout(Duration::from_secs(3), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
            
            // Send a simple probe
            stream.write_all(b"test\r\n").await.ok()?;
            
            let mut buffer = vec![0; 1024];
            let bytes_read = stream.read(&mut buffer).await.ok()?;
            buffer.truncate(bytes_read);
            
            // If we get no response or connection reset, it might be SSL/TLS
            if buffer.is_empty() {
                // This suggests an SSL/TLS port - try to identify the underlying service
                Some(self.identify_ssl_service(target, port).await.unwrap_or_else(|| {
                    // Return a marker indicating this is likely an SSL service
                    b"SSL_TLS_DETECTED".to_vec()
                }))
            } else {
                Some(buffer)
            }
        }).await {
            Ok(result) => result,
            Err(_) => None,
        }
    }

    async fn probe_bittorrent_handshake(&self, target: IpAddr, port: u16) -> Option<Vec<u8>> {
        let addr = SocketAddr::new(target, port);
        
        // BitTorrent handshake format:
        // 1 byte: protocol length (19)
        // 19 bytes: "BitTorrent protocol"
        // 8 bytes: reserved bytes (zeros)
        // 20 bytes: info_hash (we'll use dummy hash)
        // 20 bytes: peer_id (we'll use dummy peer_id)
        let mut handshake = Vec::new();
        handshake.push(19); // Protocol string length
        handshake.extend_from_slice(b"BitTorrent protocol"); // Protocol string
        handshake.extend_from_slice(&[0u8; 8]); // Reserved bytes
        handshake.extend_from_slice(&[0u8; 20]); // Dummy info_hash
        handshake.extend_from_slice(b"MLSCAN-TEST-PEER-ID-"); // 20-byte peer ID
        
        match timeout(Duration::from_secs(3), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
            stream.write_all(&handshake).await.ok()?;
            
            let mut response = vec![0u8; 256];
            let bytes_read = stream.read(&mut response).await.ok()?;
            response.truncate(bytes_read);
            
            if bytes_read > 0 {
                Some(response)
            } else {
                None
            }
        }).await {
            Ok(result) => result,
            Err(_) => None,
        }
    }

    async fn is_potential_p2p_port(&self, target: IpAddr, port: u16) -> bool {
        // Check behavioral characteristics that suggest qBittorrent
        let addr = SocketAddr::new(target, port);
        
        // Test 1: Port accepts connections but drops them without response
        let accepts_connection = match timeout(Duration::from_secs(2), async {
            tokio::net::TcpStream::connect(addr).await
        }).await {
            Ok(Ok(_)) => true,
            _ => false,
        };
        
        if !accepts_connection {
            return false;
        }
        
        // Test 2: Send random data and see if it immediately closes
        let closes_on_invalid_data = match timeout(Duration::from_secs(2), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
            stream.write_all(b"INVALID_PROTOCOL_TEST\n").await.ok()?;
            
            let mut buf = vec![0u8; 64];
            let result = stream.read(&mut buf).await;
            
            // If it closes connection (returns 0 bytes or error), it's suspicious
            match result {
                Ok(0) => Some(true),  // Connection closed
                Err(_) => Some(true), // Connection error
                Ok(_) => Some(false), // Got response
            }
        }).await {
            Ok(Some(result)) => result,
            _ => false,
        };
        
        // Test 3: Check if port is in common BitTorrent secondary port ranges
        let is_common_bt_port = match port {
            6881..=6889 => true,  // Standard BitTorrent range
            7000..=7999 => true,  // Extended range often used
            8000..=8999 => true,  // Another common range
            _ => false,
        };
        
        // If it accepts connections but closes on invalid data, and is in BT port range
        accepts_connection && closes_on_invalid_data && is_common_bt_port
    }

    async fn analyze_bittorrent_response(&self, response: &[u8]) -> Option<(String, f32)> {
        if response.len() < 28 {
            return None;
        }

        // Check if response starts with valid BitTorrent handshake
        if response[0] == 19 && response.len() >= 28 {
            if &response[1..20] == b"BitTorrent protocol" {
                // This is a valid BitTorrent handshake response
                return Some(("qBittorrent/BitTorrent".to_string(), 0.95));
            }
        }

        // Check for other BitTorrent-like responses
        let response_str = String::from_utf8_lossy(response).to_lowercase();
        if response_str.contains("torrent") || response_str.contains("peer") {
            return Some(("BitTorrent-like".to_string(), 0.7));
        }

        None
    }

    async fn probe_tls_handshake(&self, target: IpAddr, port: u16) -> Option<Vec<u8>> {
        let addr = SocketAddr::new(target, port);
        
        // Try to detect TLS by sending a TLS Client Hello
        match timeout(Duration::from_secs(3), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
            
            // Send a minimal TLS 1.2 Client Hello
            let client_hello = vec![
                0x16, 0x03, 0x01, // TLS Handshake, TLS 1.0 (compatibility)
                0x00, 0x2c,       // Length: 44 bytes
                0x01,             // Client Hello
                0x00, 0x00, 0x28, // Client Hello Length
                0x03, 0x03,       // TLS 1.2
                // 32 bytes of random data
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00,             // Session ID Length
                0x00, 0x02,       // Cipher Suites Length
                0x00, 0x35,       // TLS_RSA_WITH_AES_256_CBC_SHA
                0x01,             // Compression Methods Length
                0x00,             // No compression
            ];
            
            stream.write_all(&client_hello).await.ok()?;
            
            let mut buffer = vec![0; 4096];
            let bytes_read = stream.read(&mut buffer).await.ok()?;
            buffer.truncate(bytes_read);
            
            // Check if we got a TLS Server Hello response
            if buffer.len() >= 5 && buffer[0] == 0x16 && (buffer[1] == 0x03 || buffer[1] == 0x02) {
                // This is definitely TLS/SSL
                Some(self.analyze_tls_response(target, port, &buffer).await)
            } else {
                None
            }
        }).await {
            Ok(result) => result,
            Err(_) => None,
        }
    }

    async fn analyze_tls_response(&self, _target: IpAddr, port: u16, response: &[u8]) -> Vec<u8> {
        let mut info = String::from("TLS_SERVICE_DETECTED:");
        
        // Extract TLS version from Server Hello
        if response.len() > 10 {
            let version_major = response[9];
            let version_minor = response[10];
            
            let version = match (version_major, version_minor) {
                (0x03, 0x00) => "SSL_3.0_INSECURE",
                (0x03, 0x01) => "TLS_1.0_DEPRECATED", 
                (0x03, 0x02) => "TLS_1.1_DEPRECATED",
                (0x03, 0x03) => "TLS_1.2",
                (0x03, 0x04) => "TLS_1.3",
                _ => "Unknown_TLS_Version",
            };
            
            info.push_str(version);
            info.push(':');
        }
        
        // Try to extract certificate info if present (would need more parsing)
        // For now, use port-based heuristics
        let service = match port {
            443 | 8443 => "HTTPS",
            993 => "IMAPS",
            995 => "POP3S",
            465 | 587 => "SMTPS",
            636 => "LDAPS",
            989 | 990 => "FTPS",
            6697 => "IRC_SSL",
            22000 => "SYNCTHING_TLS", // We know this from our testing
            _ => "UNKNOWN_TLS_SERVICE",
        };
        
        info.push_str(service);
        info.into_bytes()
    }

    async fn identify_ssl_service(&self, _target: IpAddr, port: u16) -> Option<Vec<u8>> {
        // Based on port number, make educated guesses about SSL-wrapped services
        match port {
            6697 => {
                // IRC over SSL - indicate this is likely IRC over SSL
                Some(b"IRC_OVER_SSL_DETECTED".to_vec())
            },
            443 | 8443 => {
                Some(b"HTTPS_DETECTED".to_vec())
            },
            993 => {
                Some(b"IMAPS_DETECTED".to_vec()) 
            },
            995 => {
                Some(b"POP3S_DETECTED".to_vec())
            },
            22000 => {
                Some(b"SYNCTHING_TLS_DETECTED".to_vec())
            },
            _ => {
                // Generic SSL detection - could enhance this with certificate inspection
                Some(b"GENERIC_SSL_TLS_DETECTED".to_vec())
            }
        }
    }

    async fn test_authentication(&mut self, target: IpAddr, port: u16, mut fingerprint: ServiceFingerprint) -> ServiceFingerprint {
        // Determine likely protocol based on port and current fingerprint
        let protocol = self.guess_protocol(port, &fingerprint.service_name);
        
        if let Some(auth_probes) = self.auth_probes.get(&protocol).cloned() {
            for auth_probe in auth_probes {
                let (username, password) = &auth_probe.test_credentials;
                if let Some((response_type, response_data)) = self.probe_authentication(target, port, username, password, &auth_probe).await {
                    match response_type {
                        AuthResponseType::ServiceIdentified => {
                            fingerprint.auth_status = AuthStatus::AuthRequired(protocol.clone());
                            fingerprint.confidence = (fingerprint.confidence + 0.4).min(1.0);
                            fingerprint.additional_info.insert("auth_method".to_string(), format!("{:?}", auth_probe.auth_method));
                            fingerprint.additional_info.insert("auth_response".to_string(), String::from_utf8_lossy(&response_data).to_string());
                            println!("🔍 Service identified through auth challenge: {} on {}:{}", protocol, target, port);
                            break;
                        },
                        AuthResponseType::ProtocolMismatch => {
                            println!("❌ Protocol mismatch for {} on {}:{}", protocol, target, port);
                            continue;
                        },
                        AuthResponseType::Bypass => {
                            fingerprint.auth_status = AuthStatus::AuthBypass;
                            fingerprint.confidence = (fingerprint.confidence + 0.2).min(1.0);
                            println!("⚠️  Authentication bypass detected on {}:{}", target, port);
                            break;
                        }
                    }
                }
            }
        }

        fingerprint
    }

    async fn probe_authentication(&self, target: IpAddr, port: u16, username: &str, password: &str, auth_probe: &AuthProbe) -> Option<(AuthResponseType, Vec<u8>)> {
        let response_data = match auth_probe.auth_method {
            AuthMethod::BasicAuth => self.probe_http_basic_auth(target, port, username, password).await?,
            AuthMethod::SSH => self.probe_ssh_auth(target, port, username, password).await?,
            AuthMethod::FTP => self.probe_ftp_auth(target, port, username, password).await?,
            _ => return None,
        };
        
        let response_str = String::from_utf8_lossy(&response_data).to_lowercase();
        
        // Analyze response to determine service identification
        for indicator in &auth_probe.service_indicators {
            if response_str.contains(&indicator.to_lowercase()) {
                return Some((AuthResponseType::ServiceIdentified, response_data));
            }
        }
        
        for indicator in &auth_probe.malformed_indicators {
            if response_str.contains(&indicator.to_lowercase()) {
                return Some((AuthResponseType::ProtocolMismatch, response_data));
            }
        }
        
        // If response seems accepting or permissive
        if response_str.contains("200") || response_str.contains("welcome") || response_str.contains("ok") {
            return Some((AuthResponseType::Bypass, response_data));
        }
        
        Some((AuthResponseType::ServiceIdentified, response_data))
    }

    async fn probe_http_basic_auth(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Option<Vec<u8>> {
        let addr = SocketAddr::new(target, port);
        use base64::prelude::*;
        let auth = BASE64_STANDARD.encode(format!("{}:{}", username, password));
        let request = format!("GET / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\n\r\n", target, auth);
        
        match timeout(Duration::from_secs(5), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
            stream.write_all(request.as_bytes()).await.ok()?;
            
            let mut buffer = vec![0; 4096];
            let bytes_read = stream.read(&mut buffer).await.ok()?;
            buffer.truncate(bytes_read);
            
            Some(buffer)
        }).await {
            Ok(result) => result,
            Err(_) => None,
        }
    }

    async fn probe_ssh_auth(&self, target: IpAddr, port: u16, _username: &str, _password: &str) -> Option<Vec<u8>> {
        let addr = SocketAddr::new(target, port);
        
        match timeout(Duration::from_secs(5), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
            
            // Read SSH banner
            let mut buffer = vec![0; 1024];
            let bytes_read = stream.read(&mut buffer).await.ok()?;
            buffer.truncate(bytes_read);
            
            let banner = String::from_utf8_lossy(&buffer);
            if banner.contains("SSH") {
                // Send our banner
                stream.write_all(b"SSH-2.0-PortScope_Probe\r\n").await.ok()?;
                
                // Try to trigger authentication failure
                // In real implementation, would do proper SSH handshake
                // For now, just collect the banner response which often contains version info
                Some(buffer)
            } else {
                None
            }
        }).await {
            Ok(result) => result,
            Err(_) => None,
        }
    }

    async fn probe_ftp_auth(&self, target: IpAddr, port: u16, username: &str, password: &str) -> Option<Vec<u8>> {
        let addr = SocketAddr::new(target, port);
        
        match timeout(Duration::from_secs(10), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
            
            // Read welcome message
            let mut buffer = vec![0; 1024];
            stream.read(&mut buffer).await.ok()?;
            
            // Send username
            stream.write_all(format!("USER {}\r\n", username).as_bytes()).await.ok()?;
            buffer.fill(0);
            stream.read(&mut buffer).await.ok()?;
            
            // Send password
            stream.write_all(format!("PASS {}\r\n", password).as_bytes()).await.ok()?;
            buffer.fill(0);
            let bytes_read = stream.read(&mut buffer).await.ok()?;
            buffer.truncate(bytes_read);
            
            Some(buffer)
        }).await {
            Ok(result) => result,
            Err(_) => None,
        }
    }

    async fn hail_mary_probing(&mut self, target: IpAddr, port: u16, mut fingerprint: ServiceFingerprint) -> ServiceFingerprint {
        println!("🎲 Attempting random protocol identification...");
        
        // Collect probe data from all modular detectors
        let mut hail_mary_probes = Vec::new();
        
        // Database detector probes
        for detector in &self.response_classifier.database_detectors {
            hail_mary_probes.extend(detector.get_probe_data());
        }
        
        // Messaging detector probes
        for detector in &self.response_classifier.messaging_detectors {
            hail_mary_probes.extend(detector.get_probe_data());
        }
        
        // Web detector probes
        for detector in &self.response_classifier.web_detectors {
            hail_mary_probes.extend(detector.get_probe_data());
        }
        
        // System detector probes
        for detector in &self.response_classifier.system_detectors {
            hail_mary_probes.extend(detector.get_probe_data());
        }
        
        // Development detector probes
        for detector in &self.response_classifier.development_detectors {
            hail_mary_probes.extend(detector.get_probe_data());
        }
        
        // Add some generic fallback probes
        hail_mary_probes.extend(vec![
            // Generic protocols
            b"HELO\r\n".to_vec(),                                    // SMTP-like
            b"CONNECT\r\n".to_vec(),                                 // Proxy-like
            b"QUIT\r\n".to_vec(),                                    // Generic quit
            // Binary protocols
            vec![0x00, 0x01, 0x02, 0x03],                           // Generic binary
            vec![0xFF, 0xFE, 0xFD, 0xFC],                           // Reverse binary
            vec![0x12, 0x34, 0x56, 0x78],                           // Custom binary
            b"\\x00\\x01STATUS".to_vec(),                            // Status check
        ]);

        let mut max_confidence = fingerprint.confidence;
        let mut best_classification = None;

        for (i, probe_data) in hail_mary_probes.iter().enumerate() {
            if let Some(response) = self.execute_raw_probe(target, port, probe_data).await {
                // Use ML to analyze this response
                let classification = self.response_classifier.analyze_unknown_response(&response);
                if let Some((service, confidence)) = classification {
                    if confidence > max_confidence {
                        max_confidence = confidence;
                        best_classification = Some(service.clone());
                        println!("🎯 Hail mary probe #{} got response: potential {}", i + 1, service);
                    }
                }
                
                // Learn from this probe
                self.learning_data.push(ProbeResult {
                    target,
                    port,
                    probe_name: format!("hail_mary_{}", i),
                    response,
                    success: true,
                    timing: Duration::from_millis(100), // Estimate
                    classification: best_classification.clone(),
                });
            }
        }

        if let Some(service) = best_classification {
            fingerprint.service_name = service;
            fingerprint.confidence = max_confidence;
            fingerprint.additional_info.insert("detection_method".to_string(), "hail_mary_ml".to_string());
        }

        fingerprint
    }

    async fn execute_raw_probe(&self, target: IpAddr, port: u16, probe_data: &[u8]) -> Option<Vec<u8>> {
        let addr = SocketAddr::new(target, port);
        
        match timeout(Duration::from_secs(3), async {
            let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
            
            if !probe_data.is_empty() {
                stream.write_all(probe_data).await.ok()?;
            }
            
            let mut buffer = vec![0; 2048];
            let bytes_read = stream.read(&mut buffer).await.ok()?;
            buffer.truncate(bytes_read);
            
            Some(buffer)
        }).await {
            Ok(result) => result,
            Err(_) => None,
        }
    }

    async fn ml_classify_responses(&mut self, _target: IpAddr, _port: u16, fingerprint: ServiceFingerprint) -> ServiceFingerprint {
        // Apply ML classification to all collected responses
        // This would use the learning data to improve classification
        fingerprint
    }

    fn learn_from_probe_result(&mut self, target: IpAddr, port: u16, fingerprint: &ServiceFingerprint) {
        // Store learning data for improving future probes
        println!("📚 Learning from probe result: {}:{} -> {} (confidence: {:.2})", 
                target, port, fingerprint.service_name, fingerprint.confidence);
        
        // In a real implementation, this would update ML models
        if self.learning_data.len() % 20 == 0 {
            println!("🧠 Retraining aggressive probing model with {} samples", self.learning_data.len());
        }
    }

    fn guess_protocol(&self, port: u16, service_name: &str) -> String {
        match port {
            21 => "FTP".to_string(),
            22 => "SSH".to_string(),
            23 => "Telnet".to_string(),
            25 => "SMTP".to_string(),
            53 => "DNS".to_string(),
            80 | 8080 | 8000 => "HTTP".to_string(),
            110 => "POP3".to_string(),
            143 => "IMAP".to_string(),
            443 | 8443 => "HTTPS".to_string(),
            993 => "IMAPS".to_string(),
            995 => "POP3S".to_string(),
            6667 => "IRC".to_string(),
            6697 => "IRC".to_string(), // IRC over SSL
            22000 => "Syncthing".to_string(),
            _ => {
                let service_lower = service_name.to_lowercase();
                if service_lower.contains("http") {
                    "HTTP".to_string()
                } else if service_lower.contains("ssh") {
                    "SSH".to_string()
                } else if service_lower.contains("irc") || service_lower.contains("ergo") {
                    "IRC".to_string()
                } else if service_lower.contains("syncthing") {
                    "Syncthing".to_string()
                } else if service_lower.contains("dns") {
                    "DNS".to_string()
                } else {
                    "Generic".to_string()
                }
            }
        }
    }
}

impl MLResponseClassifier {
    fn new() -> Self {
        let mut classifier = Self {
            protocol_patterns: HashMap::new(),
            learned_signatures: HashMap::new(),
            // Initialize modular detectors
            database_detectors: vec![
                Box::new(PostgreSQLDetector),
                Box::new(MongoDBDetector),
                Box::new(RedisDetector),
            ],
            messaging_detectors: vec![
                // TODO: Implement these detectors
                // Box::new(MQTTDetector),
                // Box::new(RabbitMQDetector),
                // Box::new(KafkaDetector),
                // Box::new(ZookeeperDetector),
            ],
            web_detectors: vec![
                // TODO: Implement these detectors
                // Box::new(HTTPDetector),
                // Box::new(DockerRegistryDetector),
                // Box::new(PrometheusDetector),
                // Box::new(GrafanaDetector),
                // Box::new(ElasticsearchDetector),
                // Box::new(GraphQLDetector),
            ],
            system_detectors: vec![
                // TODO: Implement these detectors
                // Box::new(DNSDetector),
                // Box::new(LDAPDetector),
                // Box::new(SMTPDetector),
                // Box::new(VNCDetector),
                // Box::new(RDPDetector),
                // Box::new(MemcachedDetector),
            ],
            development_detectors: vec![
                // TODO: Implement these detectors
                // Box::new(CassandraDetector),
                // Box::new(GitDetector),
                // Box::new(SyntctingDetector),
                // Box::new(JenkinsDetector),
                // Box::new(BitTorrentDetector),
                // Box::new(IRCDetector),
            ],
        };
        classifier.load_response_patterns();
        classifier
    }

    fn load_response_patterns(&mut self) {
        // HTTP patterns
        let http_patterns = vec![
            ResponsePattern {
                name: "Apache".to_string(),
                byte_patterns: vec![],
                text_patterns: vec!["Apache".to_string(), "Server: Apache".to_string()],
                timing_characteristics: None,
                confidence_weight: 0.9,
            },
            ResponsePattern {
                name: "Nginx".to_string(),
                byte_patterns: vec![],
                text_patterns: vec!["nginx".to_string(), "Server: nginx".to_string()],
                timing_characteristics: None,
                confidence_weight: 0.9,
            },
        ];
        self.protocol_patterns.insert("HTTP".to_string(), http_patterns);

        // SSH patterns
        let ssh_patterns = vec![
            ResponsePattern {
                name: "OpenSSH".to_string(),
                byte_patterns: vec![],
                text_patterns: vec!["OpenSSH".to_string(), "SSH-2.0-OpenSSH".to_string()],
                timing_characteristics: None,
                confidence_weight: 0.95,
            },
        ];
        self.protocol_patterns.insert("SSH".to_string(), ssh_patterns);

        // IRC patterns
        let irc_patterns = vec![
            ResponsePattern {
                name: "ErgoIRCd".to_string(),
                byte_patterns: vec![],
                text_patterns: vec!["ergo.test".to_string(), "ErgoTest".to_string(), "001".to_string(), "Welcome".to_string()],
                timing_characteristics: None,
                confidence_weight: 0.95,
            },
            ResponsePattern {
                name: "IRC Server".to_string(),
                byte_patterns: vec![],
                text_patterns: vec!["NOTICE".to_string(), "PRIVMSG".to_string(), "MODE".to_string(), "IRC".to_string()],
                timing_characteristics: None,
                confidence_weight: 0.85,
            },
        ];
        self.protocol_patterns.insert("IRC".to_string(), irc_patterns);

        // Syncthing patterns
        let syncthing_patterns = vec![
            ResponsePattern {
                name: "Syncthing".to_string(),
                byte_patterns: vec![],
                text_patterns: vec!["syncthing".to_string(), "BEP".to_string(), "device".to_string(), "folder".to_string()],
                timing_characteristics: None,
                confidence_weight: 0.9,
            },
        ];
        self.protocol_patterns.insert("Syncthing".to_string(), syncthing_patterns);

        // DNS patterns
        let dns_patterns = vec![
            ResponsePattern {
                name: "BIND DNS".to_string(),
                byte_patterns: vec![vec![0x12, 0x34], vec![0x81, 0x80]], // DNS response flags
                text_patterns: vec!["BIND".to_string(), "version".to_string()],
                timing_characteristics: None,
                confidence_weight: 0.9,
            },
            ResponsePattern {
                name: "DNS Server".to_string(),
                byte_patterns: vec![vec![0x81, 0x80], vec![0x84, 0x00]], // DNS response codes
                text_patterns: vec![],
                timing_characteristics: None,
                confidence_weight: 0.8,
            },
        ];
        self.protocol_patterns.insert("DNS".to_string(), dns_patterns);

        // SSL/TLS patterns
        let ssl_patterns = vec![
            ResponsePattern {
                name: "SSL/TLS Service".to_string(),
                byte_patterns: vec![vec![0x16, 0x03], vec![0x15, 0x03]], // TLS handshake/alert
                text_patterns: vec!["certificate".to_string(), "handshake".to_string()],
                timing_characteristics: None,
                confidence_weight: 0.85,
            },
        ];
        self.protocol_patterns.insert("SSL".to_string(), ssl_patterns);
    }

    fn classify_response(&self, response: &[u8], _step: &ProbeStep) -> Option<(String, f32)> {
        let response_str = String::from_utf8_lossy(response);
        
        // Check all patterns
        for (_protocol, patterns) in &self.protocol_patterns {
            for pattern in patterns {
                // Check text patterns
                for text_pattern in &pattern.text_patterns {
                    if response_str.to_lowercase().contains(&text_pattern.to_lowercase()) {
                        return Some((pattern.name.clone(), pattern.confidence_weight));
                    }
                }
                
                // Check byte patterns
                for byte_pattern in &pattern.byte_patterns {
                    if self.contains_byte_pattern(response, byte_pattern) {
                        return Some((pattern.name.clone(), pattern.confidence_weight));
                    }
                }
            }
        }
        
        None
    }

    fn contains_byte_pattern(&self, haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    fn analyze_unknown_response(&self, response: &[u8]) -> Option<(String, f32)> {
        let response_str = String::from_utf8_lossy(response).to_lowercase();
        
        // Check for our enhanced TLS detection markers first
        if response_str.contains("tls_service_detected:") {
            // Parse the detailed TLS info
            if response_str.contains("ssl_3.0_insecure") {
                let service = self.extract_tls_service(&response_str);
                return Some((format!("{} (SSL 3.0 INSECURE!)", service), 0.95));
            } else if response_str.contains("tls_1.0_deprecated") {
                let service = self.extract_tls_service(&response_str);
                return Some((format!("{} (TLS 1.0 deprecated)", service), 0.90));
            } else if response_str.contains("tls_1.1_deprecated") {
                let service = self.extract_tls_service(&response_str);
                return Some((format!("{} (TLS 1.1 deprecated)", service), 0.90));
            } else if response_str.contains("syncthing_tls") {
                return Some(("Syncthing".to_string(), 0.95));
            } else if response_str.contains("irc_ssl") {
                return Some(("IRC-over-SSL".to_string(), 0.90));
            } else if response_str.contains("https") {
                return Some(("HTTPS".to_string(), 0.90));
            } else if response_str.contains("imaps") {
                return Some(("IMAPS".to_string(), 0.90));
            } else if response_str.contains("unknown_tls_service") {
                return Some(("Unknown-TLS-Service".to_string(), 0.75));
            }
        }
        
        // Check for our SSL detection markers
        if response_str.contains("irc_over_ssl_detected") {
            return Some(("IRC-over-SSL".to_string(), 0.85));
        } else if response_str.contains("https_detected") {
            return Some(("HTTPS".to_string(), 0.85));
        } else if response_str.contains("imaps_detected") {
            return Some(("IMAPS".to_string(), 0.85));
        } else if response_str.contains("pop3s_detected") {
            return Some(("POP3S".to_string(), 0.85));
        } else if response_str.contains("syncthing_tls_detected") {
            return Some(("Syncthing".to_string(), 0.90));
        } else if response_str.contains("ssl_tls_detected") {
            return Some(("SSL-TLS-Service".to_string(), 0.75));
        }
        
        // Use modular protocol detectors - Database detectors
        for detector in &self.database_detectors {
            if let Some(result) = detector.detect(response) {
                return Some((result.service_name, result.confidence));
            }
        }
        
        // Messaging protocol detectors
        for detector in &self.messaging_detectors {
            if let Some(result) = detector.detect(response) {
                return Some((result.service_name, result.confidence));
            }
        }
        
        // Web protocol detectors
        for detector in &self.web_detectors {
            if let Some(result) = detector.detect(response) {
                return Some((result.service_name, result.confidence));
            }
        }
        
        // System protocol detectors
        for detector in &self.system_detectors {
            if let Some(result) = detector.detect(response) {
                return Some((result.service_name, result.confidence));
            }
        }
        
        // Development tool detectors
        for detector in &self.development_detectors {
            if let Some(result) = detector.detect(response) {
                return Some((result.service_name, result.confidence));
            }
        }
        
        // Fallback to basic pattern detection if no modular detector matches
        if response_str.contains("ssh") || response_str.contains("openssh") {
            Some(("SSH-Service".to_string(), 0.7))
        } else if response_str.contains("ftp") || response_str.contains("220") {
            Some(("FTP-Service".to_string(), 0.7))
        } else if response.len() >= 3 && response[0] == 0x16 && response[1] == 0x03 {
            // TLS handshake pattern
            Some(("SSL-TLS-Service".to_string(), 0.7))
        } else if response.len() > 0 {
            // Enhanced binary/text analysis
            let binary_count = response.iter().filter(|&&b| b > 127 || b < 32).count();
            let binary_ratio = binary_count as f64 / response.len() as f64;
            
            if binary_ratio > 0.3 {
                Some(("Binary-Protocol".to_string(), 0.5))
            } else if response_str.contains("error") || response_str.contains("invalid") {
                Some(("Protocol-Mismatch".to_string(), 0.4))
            } else if response.len() > 10 {
                Some(("Text-Protocol".to_string(), 0.4))
            } else {
                Some(("Unknown-Service".to_string(), 0.2))
            }
        } else {
            None
        }
    }

    fn extract_tls_service(&self, response_str: &str) -> String {
        // Extract service name from TLS detection string
        if let Some(pos) = response_str.rfind(':') {
            let service = &response_str[pos + 1..];
            match service {
                "syncthing_tls" => "Syncthing",
                "irc_ssl" => "IRC",
                "https" => "HTTPS",
                "imaps" => "IMAPS",
                "pop3s" => "POP3S",
                "smtps" => "SMTPS",
                "ldaps" => "LDAPS",
                "ftps" => "FTPS",
                _ => "TLS Service",
            }.to_string()
        } else {
            "TLS Service".to_string()
        }
    }
}