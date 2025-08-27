// Scan result caching system for improved performance
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

use crate::scanner::results::{PortStatus, ServiceInfo};
use crate::cli::ScanType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPortResult {
    pub status: PortStatus,
    pub service: Option<ServiceInfo>,
    pub timestamp: u64,
    pub scan_type: ScanType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedHostResult {
    pub target: IpAddr,
    pub ports: HashMap<u16, CachedPortResult>,
    pub last_full_scan: u64,
}

pub struct ScanCache {
    cache: Arc<RwLock<HashMap<String, CachedHostResult>>>,
    cache_ttl_seconds: u64,
    max_entries: usize,
}

impl ScanCache {
    pub fn new(ttl_seconds: u64, max_entries: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl_seconds: ttl_seconds,
            max_entries,
        }
    }
    
    /// Check if we have cached results for a target/port combination
    pub fn get_cached_result(&self, target: IpAddr, port: u16, scan_type: ScanType) -> Option<(PortStatus, Option<ServiceInfo>)> {
        let cache = self.cache.read().ok()?;
        let host_key = target.to_string();
        
        if let Some(host_result) = cache.get(&host_key) {
            if let Some(port_result) = host_result.ports.get(&port) {
                // Check if result is still valid
                if self.is_result_valid(&port_result) && port_result.scan_type == scan_type {
                    return Some((port_result.status, port_result.service.clone()));
                }
            }
        }
        
        None
    }
    
    /// Cache a scan result
    pub fn cache_result(&self, target: IpAddr, port: u16, status: PortStatus, service: Option<ServiceInfo>, scan_type: ScanType) {
        let mut cache = match self.cache.write() {
            Ok(cache) => cache,
            Err(_) => return,
        };
        
        let host_key = target.to_string();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let port_result = CachedPortResult {
            status,
            service,
            timestamp: current_time,
            scan_type,
        };
        
        // Get or create host entry
        let host_result = cache.entry(host_key).or_insert_with(|| CachedHostResult {
            target,
            ports: HashMap::new(),
            last_full_scan: current_time,
        });
        
        // Cache the port result
        host_result.ports.insert(port, port_result);
        
        // Cleanup old entries if we're at capacity
        if cache.len() > self.max_entries {
            self.cleanup_old_entries(&mut cache);
        }
    }
    
    /// Check if we have recent full scan results for a target
    pub fn has_recent_full_scan(&self, target: IpAddr, max_age_seconds: u64) -> bool {
        let cache = match self.cache.read() {
            Ok(cache) => cache,
            Err(_) => return false,
        };
        
        let host_key = target.to_string();
        if let Some(host_result) = cache.get(&host_key) {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
                
            return current_time - host_result.last_full_scan < max_age_seconds;
        }
        
        false
    }
    
    /// Get cached port count for a target (useful for intelligence)
    pub fn get_cached_open_ports(&self, target: IpAddr) -> Vec<u16> {
        let cache = match self.cache.read() {
            Ok(cache) => cache,
            Err(_) => return Vec::new(),
        };
        
        let host_key = target.to_string();
        if let Some(host_result) = cache.get(&host_key) {
            return host_result
                .ports
                .iter()
                .filter_map(|(&port, result)| {
                    if result.status == PortStatus::Open && self.is_result_valid(result) {
                        Some(port)
                    } else {
                        None
                    }
                })
                .collect();
        }
        
        Vec::new()
    }
    
    /// Clear cache for a specific target
    pub fn clear_target(&self, target: IpAddr) {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(&target.to_string());
        }
    }
    
    /// Clear entire cache
    pub fn clear_all(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
    
    /// Get cache statistics
    pub fn get_stats(&self) -> CacheStats {
        let cache = match self.cache.read() {
            Ok(cache) => cache,
            Err(_) => return CacheStats::default(),
        };
        
        let mut total_ports = 0;
        let mut valid_results = 0;
        let mut expired_results = 0;
        
        for host_result in cache.values() {
            total_ports += host_result.ports.len();
            for port_result in host_result.ports.values() {
                if self.is_result_valid(port_result) {
                    valid_results += 1;
                } else {
                    expired_results += 1;
                }
            }
        }
        
        CacheStats {
            total_hosts: cache.len(),
            total_ports,
            valid_results,
            expired_results,
        }
    }
    
    fn is_result_valid(&self, result: &CachedPortResult) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        current_time - result.timestamp < self.cache_ttl_seconds
    }
    
    fn cleanup_old_entries(&self, cache: &mut HashMap<String, CachedHostResult>) {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Remove hosts that haven't been scanned in a long time
        cache.retain(|_, host_result| {
            current_time - host_result.last_full_scan < self.cache_ttl_seconds * 2
        });
        
        // If still too many entries, remove oldest
        if cache.len() > self.max_entries {
            let mut hosts_by_age: Vec<_> = cache
                .iter()
                .map(|(key, host)| (key.clone(), host.last_full_scan))
                .collect();
                
            hosts_by_age.sort_by(|a, b| a.1.cmp(&b.1));
            
            let to_remove = cache.len() - self.max_entries;
            for (host_key, _) in hosts_by_age.into_iter().take(to_remove) {
                cache.remove(&host_key);
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct CacheStats {
    pub total_hosts: usize,
    pub total_ports: usize,
    pub valid_results: usize,
    pub expired_results: usize,
}

impl CacheStats {
    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_ports == 0 {
            0.0
        } else {
            self.valid_results as f64 / self.total_ports as f64
        }
    }
}

/// Global cache instance for sharing across scan sessions
lazy_static::lazy_static! {
    pub static ref GLOBAL_SCAN_CACHE: ScanCache = ScanCache::new(
        3600, // 1 hour TTL
        1000  // Max 1000 host entries
    );
}