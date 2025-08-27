use std::collections::HashMap;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSFingerprint {
    pub detected_os: String,
    pub confidence: f32,
    pub tcp_features: TcpFeatures,
    pub timing_features: TimingFeatures,
    pub behavioral_features: BehavioralFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFeatures {
    pub window_size: u16,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamp: bool,
    pub ttl: u8,
    pub df_bit: bool,
    pub tcp_options_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingFeatures {
    pub syn_ack_delay: f64,
    pub rst_timing: f64,
    pub retransmission_pattern: Vec<f64>,
    pub port_scan_detection_delay: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralFeatures {
    pub closed_port_response: String, // RST, ICMP unreachable, drop
    pub open_port_pattern: String,
    pub fragmentation_handling: String,
    pub icmp_responses: Vec<String>,
}

pub struct MLOSDetector {
    // Simple ML model using weighted features
    os_signatures: HashMap<String, OSSignatureWeights>,
    learning_data: Vec<(OSFingerprint, String)>, // Training data
}

#[derive(Debug, Clone)]
struct OSSignatureWeights {
    tcp_window_weight: f32,
    ttl_weight: f32,
    timing_weight: f32,
    behavioral_weight: f32,
    confidence_threshold: f32,
}

impl MLOSDetector {
    pub fn new() -> Self {
        let mut detector = Self {
            os_signatures: HashMap::new(),
            learning_data: Vec::new(),
        };
        detector.load_ml_signatures();
        detector
    }

    fn load_ml_signatures(&mut self) {
        // Linux signatures
        self.os_signatures.insert("Linux".to_string(), OSSignatureWeights {
            tcp_window_weight: 0.3,
            ttl_weight: 0.25,
            timing_weight: 0.25,
            behavioral_weight: 0.2,
            confidence_threshold: 0.7,
        });

        // Windows signatures
        self.os_signatures.insert("Windows".to_string(), OSSignatureWeights {
            tcp_window_weight: 0.35,
            ttl_weight: 0.3,
            timing_weight: 0.2,
            behavioral_weight: 0.15,
            confidence_threshold: 0.75,
        });

        // macOS signatures
        self.os_signatures.insert("macOS".to_string(), OSSignatureWeights {
            tcp_window_weight: 0.25,
            ttl_weight: 0.25,
            timing_weight: 0.3,
            behavioral_weight: 0.2,
            confidence_threshold: 0.72,
        });

        // FreeBSD signatures
        self.os_signatures.insert("FreeBSD".to_string(), OSSignatureWeights {
            tcp_window_weight: 0.3,
            ttl_weight: 0.3,
            timing_weight: 0.25,
            behavioral_weight: 0.15,
            confidence_threshold: 0.7,
        });
    }

    pub async fn fingerprint_os(&mut self, target: IpAddr, open_ports: &[u16]) -> Option<OSFingerprint> {
        let tcp_features = self.extract_tcp_features(target, open_ports).await?;
        let timing_features = self.extract_timing_features(target, open_ports).await?;
        let behavioral_features = self.extract_behavioral_features(target).await?;

        let fingerprint = OSFingerprint {
            detected_os: "Unknown".to_string(),
            confidence: 0.0,
            tcp_features,
            timing_features,
            behavioral_features,
        };

        // Apply ML classification
        let classified = self.classify_with_ml(&fingerprint);
        Some(classified)
    }

    async fn extract_tcp_features(&self, target: IpAddr, open_ports: &[u16]) -> Option<TcpFeatures> {
        if open_ports.is_empty() {
            return None;
        }

        // Use first open port for TCP feature extraction
        let _port = open_ports[0];
        
        // In a real implementation, this would capture actual TCP packets
        // For now, simulate based on target characteristics
        Some(TcpFeatures {
            window_size: self.estimate_window_size(target),
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            timestamp: true,
            ttl: self.estimate_ttl(target),
            df_bit: true,
            tcp_options_signature: self.generate_tcp_options_signature(target),
        })
    }

    async fn extract_timing_features(&self, target: IpAddr, _open_ports: &[u16]) -> Option<TimingFeatures> {
        // Simulate timing measurements - in real implementation would measure actual network timing
        let base_delay = if target.is_loopback() { 0.1 } else { 10.0 };
        
        Some(TimingFeatures {
            syn_ack_delay: base_delay + (rand::random::<f64>() * 5.0),
            rst_timing: base_delay * 0.8,
            retransmission_pattern: vec![1.0, 3.0, 6.0], // Typical Linux pattern
            port_scan_detection_delay: base_delay * 2.0,
        })
    }

    async fn extract_behavioral_features(&self, _target: IpAddr) -> Option<BehavioralFeatures> {
        Some(BehavioralFeatures {
            closed_port_response: "RST".to_string(),
            open_port_pattern: "SYN-ACK".to_string(),
            fragmentation_handling: "NORMAL".to_string(),
            icmp_responses: vec!["UNREACHABLE".to_string()],
        })
    }

    fn classify_with_ml(&self, fingerprint: &OSFingerprint) -> OSFingerprint {
        let mut best_os = "Unknown".to_string();
        let mut best_confidence = 0.0;

        for (os_name, weights) in &self.os_signatures {
            let confidence = self.calculate_ml_confidence(fingerprint, weights, os_name);
            
            if confidence > best_confidence && confidence > weights.confidence_threshold {
                best_confidence = confidence;
                best_os = os_name.clone();
            }
        }

        let mut result = fingerprint.clone();
        result.detected_os = best_os;
        result.confidence = best_confidence;
        result
    }

    fn calculate_ml_confidence(&self, fingerprint: &OSFingerprint, weights: &OSSignatureWeights, os_name: &str) -> f32 {
        let mut score = 0.0;

        // TCP window size analysis
        let window_score = match os_name {
            "Linux" => if fingerprint.tcp_features.window_size >= 5840 { 0.9 } else { 0.3 },
            "Windows" => if fingerprint.tcp_features.window_size == 65535 || fingerprint.tcp_features.window_size == 8192 { 0.95 } else { 0.2 },
            "macOS" => if fingerprint.tcp_features.window_size == 65535 { 0.8 } else { 0.4 },
            _ => 0.5,
        };
        score += window_score * weights.tcp_window_weight;

        // TTL analysis
        let ttl_score = match os_name {
            "Linux" => if fingerprint.tcp_features.ttl == 64 { 0.95 } else { 0.1 },
            "Windows" => if fingerprint.tcp_features.ttl == 128 { 0.95 } else { 0.1 },
            "macOS" => if fingerprint.tcp_features.ttl == 64 { 0.8 } else { 0.2 },
            _ => 0.5,
        };
        score += ttl_score * weights.ttl_weight;

        // Timing analysis
        let timing_score = match os_name {
            "Linux" => if fingerprint.timing_features.syn_ack_delay < 5.0 { 0.8 } else { 0.4 },
            "Windows" => if fingerprint.timing_features.syn_ack_delay > 3.0 { 0.7 } else { 0.3 },
            _ => 0.6,
        };
        score += timing_score * weights.timing_weight;

        // Behavioral analysis
        let behavioral_score = match os_name {
            "Linux" => if fingerprint.behavioral_features.closed_port_response == "RST" { 0.9 } else { 0.2 },
            "Windows" => if fingerprint.behavioral_features.closed_port_response == "RST" { 0.8 } else { 0.3 },
            _ => 0.5,
        };
        score += behavioral_score * weights.behavioral_weight;

        score.min(1.0).max(0.0)
    }

    fn estimate_window_size(&self, target: IpAddr) -> u16 {
        // Simulate OS detection based on IP patterns
        if target.is_loopback() {
            65535 // Common localhost behavior
        } else {
            match target.to_string().chars().last().unwrap_or('0') {
                '0'..='3' => 5840,  // Linux-like 
                '4'..='7' => 65535, // Windows-like
                _ => 8192,          // Other
            }
        }
    }

    fn estimate_ttl(&self, target: IpAddr) -> u8 {
        if target.is_loopback() {
            64
        } else {
            match target.to_string().chars().last().unwrap_or('0') {
                '0'..='4' => 64,  // Linux/Unix
                '5'..='8' => 128, // Windows  
                _ => 255,         // Network device
            }
        }
    }

    fn generate_tcp_options_signature(&self, target: IpAddr) -> String {
        // Generate a signature based on typical TCP options ordering
        if target.is_loopback() {
            "MSS,SACK,WS,TS".to_string()
        } else {
            "MSS,NOP,WS,NOP,NOP,TS,SACK,EOL".to_string()
        }
    }

    pub fn learn_from_result(&mut self, fingerprint: OSFingerprint, actual_os: String) {
        // Store learning data for future ML model improvements
        self.learning_data.push((fingerprint, actual_os));
        
        // In a full implementation, this would retrain the model periodically
        if self.learning_data.len() % 100 == 0 {
            self.retrain_model();
        }
    }

    fn retrain_model(&mut self) {
        // Simplified model retraining - in practice would use proper ML algorithms
        println!("Retraining OS detection model with {} samples", self.learning_data.len());
        
        // Calculate accuracies first to avoid borrow checker issues
        let mut accuracy_updates = Vec::new();
        for os_name in self.os_signatures.keys() {
            let accuracy = self.calculate_historical_accuracy(os_name);
            accuracy_updates.push((os_name.clone(), accuracy));
        }
        
        // Update confidence thresholds based on historical accuracy
        for (os_name, accuracy) in accuracy_updates {
            if let Some(weights) = self.os_signatures.get_mut(&os_name) {
                weights.confidence_threshold = (0.5 + accuracy * 0.3).min(0.9);
            }
        }
    }

    fn calculate_historical_accuracy(&self, os_name: &str) -> f32 {
        let relevant_samples: Vec<_> = self.learning_data.iter()
            .filter(|(fp, actual)| fp.detected_os == *os_name || actual == os_name)
            .collect();
            
        if relevant_samples.is_empty() {
            return 0.5;
        }
        
        let correct_predictions = relevant_samples.iter()
            .filter(|(fp, actual)| &fp.detected_os == actual)
            .count();
            
        correct_predictions as f32 / relevant_samples.len() as f32
    }
}