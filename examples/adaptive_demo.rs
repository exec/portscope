use portscan::adaptive::*;
use std::net::IpAddr;
use std::time::Duration;

#[tokio::main]
async fn main() {
    println!("🧠 PortScan-RS Adaptive Learning Demo");
    println!("=====================================\n");

    // Initialize our adaptive learning system
    let mut learning = AdaptiveLearning::new();
    
    // Simulate some scan results to demonstrate learning
    simulate_scan_learning(&mut learning).await;
    
    // Show how it optimizes parameters for different networks
    demonstrate_network_optimization(&learning).await;
    
    // Show smart port ordering
    demonstrate_smart_port_selection(&learning).await;
}

async fn simulate_scan_learning(learning: &mut AdaptiveLearning) {
    println!("📊 Simulating scan learning...\n");
    
    // Simulate LAN scan results
    let lan_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let lan_data = ScanLearningData {
        target: lan_ip,
        network_type: NetworkType::PrivateLAN,
        port_results: vec![
            PortScanResult {
                port: 22,
                is_open: true,
                is_filtered: false,
                response_time: Some(50.0),
                service_detected: Some("SSH".to_string()),
            },
            PortScanResult {
                port: 80,
                is_open: true,
                is_filtered: false,
                response_time: Some(30.0),
                service_detected: Some("HTTP".to_string()),
            },
            PortScanResult {
                port: 443,
                is_open: false,
                is_filtered: false,
                response_time: Some(25.0),
                service_detected: None,
            },
        ],
        scan_duration: Duration::from_millis(200),
        avg_response_time: 35.0,
        timeout_rate: 0.1,
        parallelism_used: 50,
        rate_limit_used: 50,
        scan_performance: 0.9,
    };
    
    learning.learn_from_scan(&lan_data);
    println!("✅ Learned from LAN scan (192.168.1.100)");
    
    // Simulate Internet scan results
    let internet_ip: IpAddr = "8.8.8.8".parse().unwrap();
    let internet_data = ScanLearningData {
        target: internet_ip,
        network_type: NetworkType::PublicInternet,
        port_results: vec![
            PortScanResult {
                port: 53,
                is_open: true,
                is_filtered: false,
                response_time: Some(150.0),
                service_detected: Some("DNS".to_string()),
            },
            PortScanResult {
                port: 443,
                is_open: true,
                is_filtered: false,
                response_time: Some(200.0),
                service_detected: Some("HTTPS".to_string()),
            },
            PortScanResult {
                port: 80,
                is_open: false,
                is_filtered: true,
                response_time: None,
                service_detected: None,
            },
        ],
        scan_duration: Duration::from_millis(2000),
        avg_response_time: 175.0,
        timeout_rate: 0.3,
        parallelism_used: 20,
        rate_limit_used: 200,
        scan_performance: 0.7,
    };
    
    learning.learn_from_scan(&internet_data);
    println!("✅ Learned from Internet scan (8.8.8.8)");
    
    println!("📈 Learning data saved to ~/.config/portscan/adaptive_learning.json\n");
}

async fn demonstrate_network_optimization(learning: &AdaptiveLearning) {
    println!("🎯 Network-Specific Optimizations:");
    println!("==================================\n");
    
    // Test different network types
    let test_ips = [
        ("127.0.0.1", "Localhost"),
        ("192.168.1.1", "Private LAN"),
        ("8.8.8.8", "Public Internet"),
        ("34.64.0.1", "Cloud Provider"),
    ];
    
    for (ip_str, description) in test_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        let params = learning.get_optimal_params(ip);
        
        println!("🔍 {} ({}):", description, ip_str);
        println!("   Network Type: {:?}", params.network_type);
        println!("   Optimal Timeout: {}ms", params.timeout);
        println!("   Rate Limit: {}ms", params.rate_limit);
        println!("   Parallelism: {} threads", params.parallelism);
        println!("   Top Ports: {:?}", &params.suggested_ports[..6.min(params.suggested_ports.len())]);
        println!();
    }
}

async fn demonstrate_smart_port_selection(learning: &AdaptiveLearning) {
    println!("🧠 Smart Port Selection:");
    println!("========================\n");
    
    let lan_ports = learning.get_smart_port_list(&NetworkType::PrivateLAN);
    let internet_ports = learning.get_smart_port_list(&NetworkType::PublicInternet);
    
    println!("🏠 LAN optimized port order:");
    println!("   {:?}", &lan_ports[..10.min(lan_ports.len())]);
    println!();
    
    println!("🌐 Internet optimized port order:");
    println!("   {:?}", &internet_ports[..10.min(internet_ports.len())]);
    println!();
    
    println!("💡 Port intelligence sample:");
    if let Some((port, intel)) = learning.port_intelligence.iter().next() {
        println!("   Port {}: Success rate {:.1}%, Avg response {:.0}ms",
                 port, intel.success_rate * 100.0, intel.avg_response_time);
    }
    
    println!("\n🎊 Adaptive Learning Demo Complete!");
    println!("Our system is already smarter than RustScan's 'basic maths' approach! 🔥");
}