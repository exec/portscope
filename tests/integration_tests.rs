use portscan::utils::parse_ports;
use portscan::scanner::{Scanner, PortStatus};
use portscan::cli::ScanType;
use std::net::IpAddr;

#[test]
fn test_parse_single_port() {
    let ports = parse_ports("80").unwrap();
    assert_eq!(ports, vec![80]);
}

#[test]
fn test_parse_port_range() {
    let ports = parse_ports("80-82").unwrap();
    assert_eq!(ports, vec![80, 81, 82]);
}

#[test]
fn test_parse_multiple_ports() {
    let ports = parse_ports("80,443,8080").unwrap();
    assert_eq!(ports, vec![80, 443, 8080]);
}

#[test]
fn test_parse_mixed() {
    let ports = parse_ports("80,443,8000-8002").unwrap();
    assert_eq!(ports, vec![80, 443, 8000, 8001, 8002]);
}

#[test]
fn test_parse_top100() {
    let ports = parse_ports("top100").unwrap();
    assert_eq!(ports.len(), 100);
}

#[test]
fn test_parse_invalid_range() {
    let result = parse_ports("100-50");
    assert!(result.is_err());
}

#[test]
fn test_parse_invalid_port() {
    let result = parse_ports("abc");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_localhost_scan() {
    let scanner = Scanner::new(10, 1000, 5);
    
    let result = scanner.scan(
        "127.0.0.1",
        "22",
        ScanType::Connect,
    ).await;
    
    assert!(result.is_ok());
    let scan_result = result.unwrap();
    assert_eq!(scan_result.target, "127.0.0.1");
    assert_eq!(scan_result.ports.len(), 1);
    assert_eq!(scan_result.ports[0].port, 22);
}

#[tokio::test]
async fn test_closed_port_scan() {
    let scanner = Scanner::new(10, 100, 5);
    
    let result = scanner.scan(
        "127.0.0.1",
        "9999",
        ScanType::Connect,
    ).await;
    
    assert!(result.is_ok());
    let scan_result = result.unwrap();
    assert_eq!(scan_result.ports.len(), 1);
    assert_eq!(scan_result.ports[0].port, 9999);
    assert!(matches!(scan_result.ports[0].status, PortStatus::Closed | PortStatus::Filtered));
}

#[test]
fn test_port_status_display() {
    assert_eq!(format!("{}", PortStatus::Open), "open");
    assert_eq!(format!("{}", PortStatus::Closed), "closed");
    assert_eq!(format!("{}", PortStatus::Filtered), "filtered");
    assert_eq!(format!("{}", PortStatus::Error), "error");
}