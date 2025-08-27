// Development tool protocol detectors (Git, Docker, CI/CD, etc.)

use super::{ProtocolDetector, ProtocolDetectionResult};
use std::collections::HashMap;

pub struct CassandraDetector;

impl ProtocolDetector for CassandraDetector {
    fn name(&self) -> &str {
        "Cassandra"
    }

    fn detect(&self, response: &[u8]) -> Option<ProtocolDetectionResult> {
        let response_str = String::from_utf8_lossy(response).to_lowercase();
        
        // Cassandra CQL protocol detection
        if response.len() >= 8 {
            // Check for Cassandra native protocol frame
            let version = response[0];
            let flags = response[1];
            if version >= 0x03 && version <= 0x05 && flags == 0x00 {
                Some(ProtocolDetectionResult {
                    service_name: "Cassandra-Database".to_string(),
                    confidence: 0.88,
                    version: None,
                    additional_info: HashMap::from([
                        ("protocol".to_string(), "Cassandra CQL protocol".to_string()),
                    ]),
                })
            } else if response_str.contains("cassandra") || response_str.contains("cql") {
                Some(ProtocolDetectionResult {
                    service_name: "Cassandra-Database".to_string(),
                    confidence: 0.80,
                    version: None,
                    additional_info: HashMap::from([
                        ("protocol".to_string(), "Cassandra database".to_string()),
                    ]),
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    fn get_probe_data(&self) -> Vec<Vec<u8>> {
        vec![
            // Cassandra OPTIONS request
            vec![
                0x04,        // Version (v4)
                0x00,        // Flags
                0x00, 0x01,  // Stream ID
                0x05,        // Opcode (OPTIONS)
                0x00, 0x00, 0x00, 0x00,  // Length
            ],
        ]
    }
}

pub struct GitDetector;

impl ProtocolDetector for GitDetector {
    fn name(&self) -> &str {
        "Git"
    }

    fn detect(&self, response: &[u8]) -> Option<ProtocolDetectionResult> {
        let response_str = String::from_utf8_lossy(response).to_lowercase();
        
        // Git protocol detection
        if response_str.starts_with("001e# service=git-") ||
           response_str.contains("git-upload-pack") ||
           response_str.contains("git-receive-pack") {
            Some(ProtocolDetectionResult {
                service_name: "Git-Server".to_string(),
                confidence: 0.95,
                version: None,
                additional_info: HashMap::from([
                    ("protocol".to_string(), "Git smart protocol".to_string()),
                ]),
            })
        } else if response_str.contains("git") {
            Some(ProtocolDetectionResult {
                service_name: "Git-Server".to_string(),
                confidence: 0.75,
                version: None,
                additional_info: HashMap::from([
                    ("protocol".to_string(), "Git service".to_string()),
                ]),
            })
        } else {
            None
        }
    }

    fn get_probe_data(&self) -> Vec<Vec<u8>> {
        vec![
            b"0032git-upload-pack /repo.git\0host=localhost\0".to_vec(),
        ]
    }
}

pub struct SyntctingDetector;

impl ProtocolDetector for SyntctingDetector {
    fn name(&self) -> &str {
        "Syncthing"
    }

    fn detect(&self, response: &[u8]) -> Option<ProtocolDetectionResult> {
        let response_str = String::from_utf8_lossy(response).to_lowercase();
        
        // Syncthing protocol detection
        if response.len() >= 4 {
            // Check for Syncthing BEP (Block Exchange Protocol) magic
            if response[0..4] == [0x2E, 0xA3, 0x45, 0x23] {
                Some(ProtocolDetectionResult {
                    service_name: "Syncthing-Sync".to_string(),
                    confidence: 0.95,
                    version: None,
                    additional_info: HashMap::from([
                        ("protocol".to_string(), "Syncthing BEP protocol".to_string()),
                    ]),
                })
            } else if response_str.contains("syncthing") || response_str.contains("bep/") {
                Some(ProtocolDetectionResult {
                    service_name: "Syncthing-Sync".to_string(),
                    confidence: 0.85,
                    version: None,
                    additional_info: HashMap::from([
                        ("protocol".to_string(), "Syncthing service".to_string()),
                    ]),
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    fn get_probe_data(&self) -> Vec<Vec<u8>> {
        vec![
            // Syncthing BEP magic number
            vec![0x2E, 0xA3, 0x45, 0x23],
        ]
    }
}

pub struct JenkinsDetector;

impl ProtocolDetector for JenkinsDetector {
    fn name(&self) -> &str {
        "Jenkins"
    }

    fn detect(&self, response: &[u8]) -> Option<ProtocolDetectionResult> {
        let response_str = String::from_utf8_lossy(response).to_lowercase();
        
        // Jenkins CI/CD detection
        if response_str.contains("jenkins") || 
           response_str.contains("x-jenkins") ||
           response_str.contains("hudson") {
            Some(ProtocolDetectionResult {
                service_name: "Jenkins-CI".to_string(),
                confidence: 0.90,
                version: None,
                additional_info: HashMap::from([
                    ("protocol".to_string(), "Jenkins CI/CD server".to_string()),
                ]),
            })
        } else {
            None
        }
    }

    fn get_probe_data(&self) -> Vec<Vec<u8>> {
        vec![
            b"GET /api/json HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        ]
    }
}

pub struct BitTorrentDetector;

impl ProtocolDetector for BitTorrentDetector {
    fn name(&self) -> &str {
        "BitTorrent"
    }

    fn detect(&self, response: &[u8]) -> Option<ProtocolDetectionResult> {
        let response_str = String::from_utf8_lossy(response).to_lowercase();
        
        // BitTorrent protocol detection
        if response.len() >= 20 && response[0] == 19 && 
           &response[1..20] == b"BitTorrent protocol" {
            Some(ProtocolDetectionResult {
                service_name: "BitTorrent-P2P".to_string(),
                confidence: 0.95,
                version: None,
                additional_info: HashMap::from([
                    ("protocol".to_string(), "BitTorrent peer protocol".to_string()),
                ]),
            })
        } else if response_str.contains("bittorrent") || response_str.contains("torrent") ||
                  response_str.contains("qbittorrent") {
            Some(ProtocolDetectionResult {
                service_name: "BitTorrent-P2P".to_string(),
                confidence: 0.85,
                version: None,
                additional_info: HashMap::from([
                    ("protocol".to_string(), "BitTorrent service".to_string()),
                ]),
            })
        } else {
            None
        }
    }

    fn get_probe_data(&self) -> Vec<Vec<u8>> {
        vec![
            // BitTorrent handshake
            vec![
                19, // Protocol name length
                98, 105, 116, 84, 111, 114, 114, 101, 110, 116, 32, 112, 114, 111, 116, 111, 99, 111, 108, // "BitTorrent protocol"
                0, 0, 0, 0, 0, 0, 0, 0, // Reserved bytes
                // Info hash (20 bytes of zeros for probe)
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                // Peer ID (20 bytes)
                45, 77, 76, 83, 67, 65, 78, 45, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            ],
        ]
    }
}

pub struct IRCDetector;

impl ProtocolDetector for IRCDetector {
    fn name(&self) -> &str {
        "IRC"
    }

    fn detect(&self, response: &[u8]) -> Option<ProtocolDetectionResult> {
        let response_str = String::from_utf8_lossy(response).to_lowercase();
        
        // IRC protocol detection
        if response_str.starts_with(":") && (response_str.contains("001") || response_str.contains("notice")) ||
           response_str.contains("irc") || response_str.contains("ircd") {
            Some(ProtocolDetectionResult {
                service_name: "IRC-Chat".to_string(),
                confidence: 0.88,
                version: None,
                additional_info: HashMap::from([
                    ("protocol".to_string(), "IRC chat server".to_string()),
                ]),
            })
        } else {
            None
        }
    }

    fn get_probe_data(&self) -> Vec<Vec<u8>> {
        vec![
            b"NICK mlscan\r\n".to_vec(),
            b"USER mlscan 0 * :mlscan\r\n".to_vec(),
        ]
    }
}