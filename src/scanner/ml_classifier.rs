use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFeatures {
    pub response_length: f64,
    pub response_time_ms: f64,
    pub has_binary_data: f64,
    pub entropy: f64,
    pub has_http_headers: f64,
    pub has_ascii_banner: f64,
    pub starts_with_greeting: f64,
    pub contains_version_string: f64,
    pub connection_accepted: f64,
    pub connection_reset: f64,
    pub timeout_occurred: f64,
    pub multiple_packets: f64,
    pub contains_json: f64,
    pub contains_xml: f64,
    pub contains_html: f64,
    pub contains_base64: f64,
    pub auth_challenge: f64,
    pub requires_login: f64,
    pub permission_denied: f64,
    pub invalid_request: f64,
    pub quick_response: f64,
    pub medium_response: f64,
    pub slow_response: f64,
    pub response_variance: f64,
}

impl Default for ServiceFeatures {
    fn default() -> Self {
        ServiceFeatures {
            response_length: 0.0,
            response_time_ms: 0.0,
            has_binary_data: 0.0,
            entropy: 0.0,
            has_http_headers: 0.0,
            has_ascii_banner: 0.0,
            starts_with_greeting: 0.0,
            contains_version_string: 0.0,
            connection_accepted: 0.0,
            connection_reset: 0.0,
            timeout_occurred: 0.0,
            multiple_packets: 0.0,
            contains_json: 0.0,
            contains_xml: 0.0,
            contains_html: 0.0,
            contains_base64: 0.0,
            auth_challenge: 0.0,
            requires_login: 0.0,
            permission_denied: 0.0,
            invalid_request: 0.0,
            quick_response: 0.0,
            medium_response: 0.0,
            slow_response: 0.0,
            response_variance: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    pub features: ServiceFeatures,
    pub service_label: String,
    pub target: IpAddr,
    pub port: u16,
    pub timestamp: u64,
}