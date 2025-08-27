// Simplified but sophisticated ML-driven service classification
// Implements key ML concepts without complex library dependencies

use std::collections::HashMap;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use statrs::statistics::Statistics;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceFeatures {
    // Response characteristics (0.0 to 1.0 normalized)
    pub response_length_score: f64,      // Length relative to typical responses
    pub response_time_score: f64,        // Speed score (faster = higher)
    pub binary_content_ratio: f64,       // Ratio of binary content
    pub entropy_score: f64,              // Data entropy (randomness)
    
    // Protocol indicators (0.0 or 1.0)
    pub http_indicators: f64,
    pub ssh_indicators: f64,
    pub ftp_indicators: f64,
    pub smtp_indicators: f64,
    pub database_indicators: f64,
    
    // Authentication patterns (0.0 to 1.0)
    pub auth_challenge_strength: f64,
    pub error_specificity: f64,          // How specific error messages are
    pub timing_consistency: f64,         // How consistent response times are
    
    // Behavioral patterns (0.0 to 1.0)
    pub connection_stability: f64,
    pub multi_round_protocol: f64,       // Requires multiple exchanges
    pub state_awareness: f64,            // Remembers connection state
}

#[derive(Debug, Clone)]
pub struct ServiceClassification {
    pub service_name: String,
    pub confidence: f64,
    pub reasoning: Vec<String>,
    pub alternative_classifications: Vec<(String, f64)>,
}

#[derive(Debug, Clone)]
pub struct TrainingExample {
    pub features: ServiceFeatures,
    pub true_service: String,
    pub context: ServiceContext,
}

#[derive(Debug, Clone)]
pub struct ServiceContext {
    pub target: IpAddr,
    pub port: u16,
    pub probe_responses: Vec<String>,
    pub timing_data: Vec<f64>,
}

pub struct IntelligentClassifier {
    // Learned patterns from training data
    training_examples: Vec<TrainingExample>,
    
    // Feature importance weights (learned from data)
    feature_weights: HashMap<String, f64>,
    
    // Service pattern templates
    service_templates: HashMap<String, ServiceFeatures>,
    
    // Statistical models
    response_time_models: HashMap<String, (f64, f64)>, // (mean, std_dev) per service
    
    // Decision thresholds
    high_confidence_threshold: f64,
    medium_confidence_threshold: f64,
}

impl Default for ServiceFeatures {
    fn default() -> Self {
        ServiceFeatures {
            response_length_score: 0.0,
            response_time_score: 0.0,
            binary_content_ratio: 0.0,
            entropy_score: 0.0,
            http_indicators: 0.0,
            ssh_indicators: 0.0,
            ftp_indicators: 0.0,
            smtp_indicators: 0.0,
            database_indicators: 0.0,
            auth_challenge_strength: 0.0,
            error_specificity: 0.0,
            timing_consistency: 0.0,
            connection_stability: 0.0,
            multi_round_protocol: 0.0,
            state_awareness: 0.0,
        }
    }
}

impl ServiceFeatures {
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            self.response_length_score,
            self.response_time_score,
            self.binary_content_ratio,
            self.entropy_score,
            self.http_indicators,
            self.ssh_indicators,
            self.ftp_indicators,
            self.smtp_indicators,
            self.database_indicators,
            self.auth_challenge_strength,
            self.error_specificity,
            self.timing_consistency,
            self.connection_stability,
            self.multi_round_protocol,
            self.state_awareness,
        ]
    }
    
    pub fn feature_names() -> Vec<&'static str> {
        vec![
            "response_length_score",
            "response_time_score", 
            "binary_content_ratio",
            "entropy_score",
            "http_indicators",
            "ssh_indicators",
            "ftp_indicators",
            "smtp_indicators",
            "database_indicators",
            "auth_challenge_strength",
            "error_specificity",
            "timing_consistency",
            "connection_stability",
            "multi_round_protocol",
            "state_awareness",
        ]
    }
}

impl IntelligentClassifier {
    pub fn new() -> Self {
        let mut classifier = Self {
            training_examples: Vec::new(),
            feature_weights: HashMap::new(),
            service_templates: HashMap::new(),
            response_time_models: HashMap::new(),
            high_confidence_threshold: 0.8,
            medium_confidence_threshold: 0.5,
        };
        
        classifier.initialize_service_templates();
        classifier.initialize_feature_weights();
        classifier
    }
    
    fn initialize_service_templates(&mut self) {
        // HTTP template
        self.service_templates.insert("HTTP".to_string(), ServiceFeatures {
            response_length_score: 0.7,
            response_time_score: 0.8,
            binary_content_ratio: 0.1,
            entropy_score: 0.6,
            http_indicators: 1.0,
            ssh_indicators: 0.0,
            ftp_indicators: 0.0,
            smtp_indicators: 0.0,
            database_indicators: 0.0,
            auth_challenge_strength: 0.6,
            error_specificity: 0.8,
            timing_consistency: 0.7,
            connection_stability: 0.9,
            multi_round_protocol: 0.3,
            state_awareness: 0.5,
        });
        
        // SSH template
        self.service_templates.insert("SSH".to_string(), ServiceFeatures {
            response_length_score: 0.4,
            response_time_score: 0.6,
            binary_content_ratio: 0.8,
            entropy_score: 0.9,
            http_indicators: 0.0,
            ssh_indicators: 1.0,
            ftp_indicators: 0.0,
            smtp_indicators: 0.0,
            database_indicators: 0.0,
            auth_challenge_strength: 0.9,
            error_specificity: 0.7,
            timing_consistency: 0.8,
            connection_stability: 0.8,
            multi_round_protocol: 0.9,
            state_awareness: 0.9,
        });
        
        // FTP template
        self.service_templates.insert("FTP".to_string(), ServiceFeatures {
            response_length_score: 0.3,
            response_time_score: 0.7,
            binary_content_ratio: 0.2,
            entropy_score: 0.3,
            http_indicators: 0.0,
            ssh_indicators: 0.0,
            ftp_indicators: 1.0,
            smtp_indicators: 0.0,
            database_indicators: 0.0,
            auth_challenge_strength: 0.7,
            error_specificity: 0.9,
            timing_consistency: 0.6,
            connection_stability: 0.7,
            multi_round_protocol: 0.8,
            state_awareness: 0.6,
        });
        
        // Add more service templates...
        self.add_database_templates();
        self.add_web_service_templates();
    }
    
    fn add_database_templates(&mut self) {
        // MySQL template
        self.service_templates.insert("MySQL".to_string(), ServiceFeatures {
            response_length_score: 0.5,
            response_time_score: 0.6,
            binary_content_ratio: 0.7,
            entropy_score: 0.6,
            http_indicators: 0.0,
            ssh_indicators: 0.0,
            ftp_indicators: 0.0,
            smtp_indicators: 0.0,
            database_indicators: 1.0,
            auth_challenge_strength: 0.8,
            error_specificity: 0.6,
            timing_consistency: 0.5,
            connection_stability: 0.6,
            multi_round_protocol: 0.4,
            state_awareness: 0.7,
        });
    }
    
    fn add_web_service_templates(&mut self) {
        // HTTPS template
        self.service_templates.insert("HTTPS".to_string(), ServiceFeatures {
            response_length_score: 0.6,
            response_time_score: 0.7,
            binary_content_ratio: 0.9,
            entropy_score: 0.8,
            http_indicators: 0.8,
            ssh_indicators: 0.0,
            ftp_indicators: 0.0,
            smtp_indicators: 0.0,
            database_indicators: 0.0,
            auth_challenge_strength: 0.5,
            error_specificity: 0.7,
            timing_consistency: 0.6,
            connection_stability: 0.8,
            multi_round_protocol: 0.6,
            state_awareness: 0.4,
        });
    }
    
    fn initialize_feature_weights(&mut self) {
        // Initialize with reasonable defaults, will be updated through learning
        let features = ServiceFeatures::feature_names();
        for feature in features {
            self.feature_weights.insert(feature.to_string(), 1.0);
        }
        
        // Higher weights for more discriminative features
        self.feature_weights.insert("http_indicators".to_string(), 2.0);
        self.feature_weights.insert("ssh_indicators".to_string(), 2.0);
        self.feature_weights.insert("ftp_indicators".to_string(), 2.0);
        self.feature_weights.insert("database_indicators".to_string(), 2.0);
        self.feature_weights.insert("auth_challenge_strength".to_string(), 1.5);
        self.feature_weights.insert("error_specificity".to_string(), 1.3);
    }
    
    pub fn classify_service(&self, features: &ServiceFeatures) -> ServiceClassification {
        let mut service_scores = HashMap::new();
        let mut reasoning = Vec::new();
        
        // Calculate similarity scores to each service template
        for (service_name, template) in &self.service_templates {
            let similarity = self.calculate_weighted_similarity(features, template);
            service_scores.insert(service_name.clone(), similarity);
            
            if similarity > 0.5 {
                let key_features = self.identify_key_matching_features(features, template);
                reasoning.push(format!("{}: {:.2} similarity ({})", 
                    service_name, similarity, key_features.join(", ")));
            }
        }
        
        // Find best match
        let best_match = service_scores.iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
            .map(|(service, score)| (service.clone(), *score));
        
        let (service_name, confidence) = best_match
            .unwrap_or_else(|| ("Unknown".to_string(), 0.0));
        
        // Generate alternative classifications
        let mut alternatives: Vec<(String, f64)> = service_scores.into_iter()
            .filter(|(name, score)| name != &service_name && *score > 0.3)
            .collect();
        alternatives.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        alternatives.truncate(3);
        
        // Enhance reasoning with confidence explanation
        if confidence > self.high_confidence_threshold {
            reasoning.insert(0, "High confidence classification".to_string());
        } else if confidence > self.medium_confidence_threshold {
            reasoning.insert(0, "Medium confidence classification".to_string());
        } else {
            reasoning.insert(0, "Low confidence classification".to_string());
        }
        
        ServiceClassification {
            service_name,
            confidence,
            reasoning,
            alternative_classifications: alternatives,
        }
    }
    
    fn calculate_weighted_similarity(&self, features: &ServiceFeatures, template: &ServiceFeatures) -> f64 {
        let feature_vector = features.to_vector();
        let template_vector = template.to_vector();
        let feature_names = ServiceFeatures::feature_names();
        
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;
        
        for (i, (&feature_val, &template_val)) in feature_vector.iter()
            .zip(template_vector.iter()).enumerate() {
            
            if let Some(feature_name) = feature_names.get(i) {
                let weight = self.feature_weights.get(*feature_name).unwrap_or(&1.0);
                
                // Calculate similarity for this feature (1.0 = perfect match, 0.0 = complete mismatch)
                let similarity = 1.0 - (feature_val - template_val).abs();
                
                weighted_sum += similarity * weight;
                total_weight += weight;
            }
        }
        
        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
    }
    
    fn identify_key_matching_features(&self, features: &ServiceFeatures, template: &ServiceFeatures) -> Vec<String> {
        let feature_vector = features.to_vector();
        let template_vector = template.to_vector();
        let feature_names = ServiceFeatures::feature_names();
        
        let mut matches = Vec::new();
        
        for (i, (&feature_val, &template_val)) in feature_vector.iter()
            .zip(template_vector.iter()).enumerate() {
            
            if let Some(feature_name) = feature_names.get(i) {
                let similarity = 1.0 - (feature_val - template_val).abs();
                
                // Consider it a key match if similarity > 0.8 and both values > 0.5
                if similarity > 0.8 && feature_val > 0.5 && template_val > 0.5 {
                    matches.push(feature_name.to_string());
                }
            }
        }
        
        matches
    }
    
    pub fn add_training_example(&mut self, example: TrainingExample) {
        self.training_examples.push(example);
        
        // Retrain/update models periodically
        if self.training_examples.len() % 20 == 0 {
            println!("🧠 Updating ML models with {} training examples", self.training_examples.len());
            self.update_models();
        }
    }
    
    fn update_models(&mut self) {
        self.update_feature_weights();
        self.update_service_templates();
        self.update_response_time_models();
    }
    
    fn update_feature_weights(&mut self) {
        // Simple feature importance calculation based on training data
        let mut feature_importance = HashMap::new();
        
        for feature_name in ServiceFeatures::feature_names() {
            let importance = self.calculate_feature_importance(feature_name);
            feature_importance.insert(feature_name.to_string(), importance);
        }
        
        // Update weights based on calculated importance
        for (feature, importance) in feature_importance {
            let current_weight = self.feature_weights.get(&feature).unwrap_or(&1.0);
            let new_weight = (current_weight * 0.8) + (importance * 0.2); // Smoothed update
            self.feature_weights.insert(feature, new_weight);
        }
        
        println!("📊 Updated feature weights based on training data");
    }
    
    fn calculate_feature_importance(&self, feature_name: &str) -> f64 {
        // Calculate how well this feature discriminates between services
        let feature_index = ServiceFeatures::feature_names().iter()
            .position(|&name| name == feature_name)
            .unwrap_or(0);
        
        let mut service_means = HashMap::new();
        
        // Calculate mean feature value for each service
        for example in &self.training_examples {
            let feature_value = example.features.to_vector()[feature_index];
            service_means.entry(example.true_service.clone())
                .or_insert_with(Vec::new)
                .push(feature_value);
        }
        
        // Calculate variance between service means (higher = more discriminative)
        let means: Vec<f64> = service_means.values()
            .map(|values| values.iter().mean())
            .collect();
        
        if means.len() > 1 {
            means.iter().population_variance().sqrt()
        } else {
            1.0 // Default importance
        }
    }
    
    fn update_service_templates(&mut self) {
        // Update templates based on successful classifications
        let mut service_examples: HashMap<String, Vec<&ServiceFeatures>> = HashMap::new();
        
        for example in &self.training_examples {
            service_examples.entry(example.true_service.clone())
                .or_default()
                .push(&example.features);
        }
        
        // Update each service template with learned patterns
        for (service, examples) in service_examples {
            if examples.len() >= 3 { // Need minimum examples
                let updated_template = self.compute_template_from_examples(&examples);
                self.service_templates.insert(service, updated_template);
            }
        }
    }
    
    fn compute_template_from_examples(&self, examples: &[&ServiceFeatures]) -> ServiceFeatures {
        let feature_count = ServiceFeatures::feature_names().len();
        let mut feature_sums = vec![0.0; feature_count];
        
        // Average feature values across examples
        for example in examples {
            let vector = example.to_vector();
            for (i, &value) in vector.iter().enumerate() {
                if i < feature_sums.len() {
                    feature_sums[i] += value;
                }
            }
        }
        
        // Create template with averaged values
        let example_count = examples.len() as f64;
        ServiceFeatures {
            response_length_score: feature_sums[0] / example_count,
            response_time_score: feature_sums[1] / example_count,
            binary_content_ratio: feature_sums[2] / example_count,
            entropy_score: feature_sums[3] / example_count,
            http_indicators: feature_sums[4] / example_count,
            ssh_indicators: feature_sums[5] / example_count,
            ftp_indicators: feature_sums[6] / example_count,
            smtp_indicators: feature_sums[7] / example_count,
            database_indicators: feature_sums[8] / example_count,
            auth_challenge_strength: feature_sums[9] / example_count,
            error_specificity: feature_sums[10] / example_count,
            timing_consistency: feature_sums[11] / example_count,
            connection_stability: feature_sums[12] / example_count,
            multi_round_protocol: feature_sums[13] / example_count,
            state_awareness: feature_sums[14] / example_count,
        }
    }
    
    fn update_response_time_models(&mut self) {
        // Build statistical models of response times per service
        let mut service_times: HashMap<String, Vec<f64>> = HashMap::new();
        
        for example in &self.training_examples {
            let times = &example.context.timing_data;
            service_times.entry(example.true_service.clone())
                .or_default()
                .extend(times);
        }
        
        for (service, times) in service_times {
            if !times.is_empty() {
                let mean = times.iter().mean();
                let std_dev = times.iter().population_std_dev();
                self.response_time_models.insert(service, (mean, std_dev));
            }
        }
    }
    
    pub fn get_model_stats(&self) -> HashMap<String, serde_json::Value> {
        let mut stats = HashMap::new();
        
        stats.insert("training_examples".to_string(), 
            serde_json::Value::Number(self.training_examples.len().into()));
        
        stats.insert("service_templates".to_string(), 
            serde_json::Value::Number(self.service_templates.len().into()));
        
        stats.insert("response_time_models".to_string(), 
            serde_json::Value::Number(self.response_time_models.len().into()));
        
        // Add feature weight summary
        let mut feature_weights = serde_json::Map::new();
        for (feature, weight) in &self.feature_weights {
            feature_weights.insert(feature.clone(), 
                serde_json::Value::Number(serde_json::Number::from_f64(*weight).unwrap_or_else(|| serde_json::Number::from(0))));
        }
        stats.insert("feature_weights".to_string(), 
            serde_json::Value::Object(feature_weights));
        
        stats
    }
    
    pub fn predict_response_time(&self, service: &str) -> Option<(f64, f64)> {
        self.response_time_models.get(service).copied()
    }
    
    pub fn is_ready(&self) -> bool {
        !self.service_templates.is_empty() && self.training_examples.len() >= 5
    }
}