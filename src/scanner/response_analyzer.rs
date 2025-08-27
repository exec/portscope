use crate::scanner::ml_classifier::{ServiceFeatures, TrainingExample};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::IpAddr;
use statrs::statistics::Statistics;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct NetworkResponse {
    pub data: Vec<u8>,
    pub response_time: Duration,
    pub connection_successful: bool,
    pub connection_reset: bool,
    pub timeout_occurred: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProbeSession {
    pub target: IpAddr,
    pub port: u16,
    pub responses: Vec<NetworkResponse>,
    pub start_time: SystemTime,
    pub total_duration: Duration,
}

pub struct ResponseAnalyzer {
    // Compiled regex patterns for efficiency
    http_pattern: Regex,
    version_pattern: Regex,
    json_pattern: Regex,
    xml_pattern: Regex,
    html_pattern: Regex,
    base64_pattern: Regex,
    greeting_pattern: Regex,
    auth_patterns: HashMap<String, Regex>,
    
    // Known service signatures
    service_signatures: HashMap<String, Vec<String>>,
    
    // Statistical analysis
    response_time_history: HashMap<(IpAddr, u16), Vec<f64>>,
}

impl ResponseAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            http_pattern: Regex::new(r"(?i)HTTP/[0-9]\.[0-9]").unwrap(),
            version_pattern: Regex::new(r"[vV]?[0-9]+\.[0-9]+(\.[0-9]+)?").unwrap(),
            json_pattern: Regex::new(r#"^\s*[\{\[].*[\}\]]\s*$"#).unwrap(),
            xml_pattern: Regex::new(r"(?i)<\?xml|<[a-z][^>]*>").unwrap(),
            html_pattern: Regex::new(r"(?i)<html|<head|<body|<!doctype").unwrap(),
            base64_pattern: Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap(),
            greeting_pattern: Regex::new(r"(?i)^(220|200|welcome|hello|ready|connected)").unwrap(),
            auth_patterns: HashMap::new(),
            service_signatures: HashMap::new(),
            response_time_history: HashMap::new(),
        };
        
        analyzer.initialize_patterns();
        analyzer.load_service_signatures();
        analyzer
    }
    
    fn initialize_patterns(&mut self) {
        // Authentication challenge patterns
        self.auth_patterns.insert(
            "http_auth".to_string(),
            Regex::new(r"(?i)(401|unauthorized|www-authenticate|basic realm)").unwrap()
        );
        self.auth_patterns.insert(
            "ssh_auth".to_string(),
            Regex::new(r"(?i)(password:|permission denied|authentication failed|invalid user)").unwrap()
        );
        self.auth_patterns.insert(
            "ftp_auth".to_string(),
            Regex::new(r"(?i)(530|login incorrect|user.*unknown|password required)").unwrap()
        );
        self.auth_patterns.insert(
            "invalid_request".to_string(),
            Regex::new(r"(?i)(400|bad request|invalid|malformed|syntax error|protocol error)").unwrap()
        );
    }
    
    fn load_service_signatures(&mut self) {
        // HTTP signatures
        self.service_signatures.insert("HTTP".to_string(), vec![
            "HTTP/".to_string(),
            "Server:".to_string(),
            "Content-Type:".to_string(),
            "Set-Cookie:".to_string(),
        ]);
        
        // SSH signatures
        self.service_signatures.insert("SSH".to_string(), vec![
            "SSH-".to_string(),
            "OpenSSH".to_string(),
            "diffie-hellman".to_string(),
            "ssh-rsa".to_string(),
        ]);
        
        // FTP signatures
        self.service_signatures.insert("FTP".to_string(), vec![
            "220".to_string(),
            "FTP".to_string(),
            "FileZilla".to_string(),
            "vsftpd".to_string(),
        ]);
        
        // Database signatures
        self.service_signatures.insert("MySQL".to_string(), vec![
            "mysql_native_password".to_string(),
            "MariaDB".to_string(),
            "Got packets out of order".to_string(),
        ]);
        
        self.service_signatures.insert("PostgreSQL".to_string(), vec![
            "FATAL".to_string(),
            "database".to_string(),
            "PostgreSQL".to_string(),
        ]);
        
        // Web server signatures
        self.service_signatures.insert("Apache".to_string(), vec![
            "Apache".to_string(),
            "Server: Apache".to_string(),
        ]);
        
        self.service_signatures.insert("Nginx".to_string(), vec![
            "nginx".to_string(),
            "Server: nginx".to_string(),
        ]);
        
        // SMTP signatures
        self.service_signatures.insert("SMTP".to_string(), vec![
            "SMTP".to_string(),
            "EHLO".to_string(),
            "MAIL FROM".to_string(),
            "Postfix".to_string(),
        ]);
    }
    
    pub fn analyze_probe_session(&mut self, session: &ProbeSession) -> ServiceFeatures {
        let mut features = ServiceFeatures::default();
        
        if session.responses.is_empty() {
            return features;
        }
        
        // Analyze individual responses
        let mut total_length = 0;
        let mut total_time = 0.0;
        let mut response_times = Vec::new();
        let mut has_successful_connection = false;
        let mut has_connection_reset = false;
        let mut has_timeout = false;
        let mut combined_response = Vec::new();
        
        for response in &session.responses {
            total_length += response.data.len();
            let time_ms = response.response_time.as_millis() as f64;
            total_time += time_ms;
            response_times.push(time_ms);
            
            if response.connection_successful {
                has_successful_connection = true;
            }
            if response.connection_reset {
                has_connection_reset = true;
            }
            if response.timeout_occurred {
                has_timeout = true;
            }
            
            combined_response.extend(&response.data);
        }
        
        // Basic response characteristics
        features.response_length = total_length as f64;
        features.response_time_ms = total_time / session.responses.len() as f64;
        features.multiple_packets = if session.responses.len() > 1 { 1.0 } else { 0.0 };
        
        // Connection behavior
        features.connection_accepted = if has_successful_connection { 1.0 } else { 0.0 };
        features.connection_reset = if has_connection_reset { 1.0 } else { 0.0 };
        features.timeout_occurred = if has_timeout { 1.0 } else { 0.0 };
        
        // Timing analysis
        if !response_times.is_empty() {
            let mean_time = response_times.iter().mean();
            features.quick_response = if mean_time < 100.0 { 1.0 } else { 0.0 };
            features.medium_response = if mean_time >= 100.0 && mean_time <= 1000.0 { 1.0 } else { 0.0 };
            features.slow_response = if mean_time > 1000.0 { 1.0 } else { 0.0 };
            
            if response_times.len() > 1 {
                features.response_variance = response_times.iter().population_variance();
            }
        }
        
        // Store response time history for ML learning
        let key = (session.target, session.port);
        self.response_time_history.entry(key)
            .or_insert_with(Vec::new)
            .extend(response_times);
        
        // Content analysis
        if !combined_response.is_empty() {
            features = self.analyze_response_content(features, &combined_response);
        }
        
        features
    }
    
    fn analyze_response_content(&self, mut features: ServiceFeatures, data: &[u8]) -> ServiceFeatures {
        // Convert to string for text analysis (handle non-UTF8 gracefully)
        let text = String::from_utf8_lossy(data);
        
        // Binary data detection
        features.has_binary_data = if self.is_binary_data(data) { 1.0 } else { 0.0 };
        
        // Entropy calculation
        features.entropy = self.calculate_entropy(data);
        
        // Protocol-specific patterns
        features.has_http_headers = if self.http_pattern.is_match(&text) { 1.0 } else { 0.0 };
        features.has_ascii_banner = if self.is_ascii_banner(&text) { 1.0 } else { 0.0 };
        features.starts_with_greeting = if self.greeting_pattern.is_match(&text) { 1.0 } else { 0.0 };
        features.contains_version_string = if self.version_pattern.is_match(&text) { 1.0 } else { 0.0 };
        
        // Content type detection
        features.contains_json = if self.json_pattern.is_match(&text) { 1.0 } else { 0.0 };
        features.contains_xml = if self.xml_pattern.is_match(&text) { 1.0 } else { 0.0 };
        features.contains_html = if self.html_pattern.is_match(&text) { 1.0 } else { 0.0 };
        features.contains_base64 = if self.base64_pattern.is_match(&text) { 1.0 } else { 0.0 };
        
        // Authentication analysis
        features.auth_challenge = if self.has_auth_challenge(&text) { 1.0 } else { 0.0 };
        features.requires_login = if self.requires_authentication(&text) { 1.0 } else { 0.0 };
        features.permission_denied = if self.is_permission_denied(&text) { 1.0 } else { 0.0 };
        features.invalid_request = if self.is_invalid_request(&text) { 1.0 } else { 0.0 };
        
        features
    }
    
    fn is_binary_data(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        
        let non_printable_count = data.iter()
            .filter(|&&b| b < 32 && b != 9 && b != 10 && b != 13) // Not tab, LF, CR
            .count();
            
        // Consider binary if more than 10% non-printable characters
        (non_printable_count as f64 / data.len() as f64) > 0.1
    }
    
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    fn is_ascii_banner(&self, text: &str) -> bool {
        // Check if text looks like a service banner
        let lines: Vec<&str> = text.lines().collect();
        if lines.is_empty() {
            return false;
        }
        
        let first_line = lines[0];
        
        // Common banner patterns
        first_line.len() > 10 && 
        first_line.len() < 200 &&
        first_line.chars().all(|c| c.is_ascii() && (c.is_alphanumeric() || " .-_/()[]".contains(c)))
    }
    
    fn has_auth_challenge(&self, text: &str) -> bool {
        self.auth_patterns.get("http_auth").unwrap().is_match(text) ||
        self.auth_patterns.get("ssh_auth").unwrap().is_match(text) ||
        self.auth_patterns.get("ftp_auth").unwrap().is_match(text)
    }
    
    fn requires_authentication(&self, text: &str) -> bool {
        text.to_lowercase().contains("login") ||
        text.to_lowercase().contains("password") ||
        text.to_lowercase().contains("authenticate") ||
        text.contains("401") ||
        text.contains("403")
    }
    
    fn is_permission_denied(&self, text: &str) -> bool {
        text.to_lowercase().contains("permission denied") ||
        text.to_lowercase().contains("access denied") ||
        text.to_lowercase().contains("unauthorized") ||
        text.contains("403") ||
        text.contains("401")
    }
    
    fn is_invalid_request(&self, text: &str) -> bool {
        self.auth_patterns.get("invalid_request").unwrap().is_match(text)
    }
    
    pub fn create_training_example(
        &self, 
        session: &ProbeSession, 
        known_service: &str
    ) -> TrainingExample {
        let features = self.analyze_probe_session_immutable(session);
        
        TrainingExample {
            features,
            service_label: known_service.to_string(),
            target: session.target,
            port: session.port,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
    
    // Immutable version for creating training examples
    fn analyze_probe_session_immutable(&self, session: &ProbeSession) -> ServiceFeatures {
        let mut temp_analyzer = ResponseAnalyzer::new();
        temp_analyzer.analyze_probe_session(session)
    }
    
    pub fn detect_service_from_signatures(&self, text: &str) -> Option<(String, f64)> {
        let mut best_match = None;
        let mut best_score = 0.0;
        
        for (service, signatures) in &self.service_signatures {
            let mut matches = 0;
            let text_lower = text.to_lowercase();
            
            for signature in signatures {
                if text_lower.contains(&signature.to_lowercase()) {
                    matches += 1;
                }
            }
            
            if matches > 0 {
                let score = matches as f64 / signatures.len() as f64;
                if score > best_score {
                    best_score = score;
                    best_match = Some(service.clone());
                }
            }
        }
        
        if best_score > 0.0 {
            Some((best_match.unwrap(), best_score))
        } else {
            None
        }
    }
    
    pub fn get_response_time_stats(&self, target: IpAddr, port: u16) -> Option<(f64, f64, f64)> {
        let key = (target, port);
        if let Some(times) = self.response_time_history.get(&key) {
            if !times.is_empty() {
                let mean = times.iter().mean();
                let std_dev = times.iter().population_std_dev();
                let variance = times.iter().population_variance();
                return Some((mean, std_dev, variance));
            }
        }
        None
    }
    
    pub fn clear_history_for_target(&mut self, target: IpAddr, port: u16) {
        let key = (target, port);
        self.response_time_history.remove(&key);
    }
}