use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "portscope")]
#[command(author = "PortScope")]
#[command(version = "0.1.0")]
#[command(about = "Advanced network port scanner with intelligent service detection", long_about = None)]
pub struct Cli {
    #[arg(help = "Target IP, hostname, IP range (IP1-IP2), or CIDR (192.168.1.0/24). Can be specified multiple times.")]
    pub target: Vec<String>,
    
    #[arg(short, long, help = "Ports to scan: -p22,80,443 or -p1-1000 or -p- for all ports. Defaults to 1-1000.")]
    pub ports: Option<Vec<String>>,
    
    #[arg(short = 's', value_enum, help = "Scan technique (default: SYN scan)")]
    pub scan_type: Option<ScanType>,
    
    #[arg(long, help = "Send packets no faster than <rate> per second (default: ML optimized)")]
    pub rate_limit: Option<u64>,
    
    #[arg(long, help = "Give up on target after this long (default: ML adaptive)")]
    pub timeout: Option<u64>,
    
    #[arg(long, help = "Probe parallelization: numprobes. Higher is faster but less accurate (default: ML optimized)")]
    pub parallel_hosts: Option<usize>,
    
    #[arg(short = 'o', long, value_enum, default_value = "human", help = "Output format")]
    pub output_format: OutputFormat,
    
    #[arg(short = 'f', long, help = "Output file path")]
    pub output_file: Option<PathBuf>,
    
    #[arg(long, help = "Disable colored output")]
    pub no_color: bool,
    
    #[arg(short, long, help = "Enable verbose output")]
    pub verbose: bool,

    #[arg(short = 'P', help = "Skip host discovery (assume all hosts up)")]
    pub skip_ping: bool,
    
    #[arg(short = 'O', help = "Enable OS detection")]
    pub os_detection: bool,
    
    #[arg(short = 'A', help = "Enable OS detection, version detection, script scanning, and traceroute")]
    pub aggressive: bool,
    
    #[arg(short = 'T', value_name = "TIMING", help = "Set timing template (0-5) for speed/stealth")]
    pub timing: Option<u8>,
}

#[derive(Debug, Clone, Copy, ValueEnum, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum ScanType {
    #[value(name = "syn", help = "TCP SYN scan (requires root)")]
    Syn,
    #[value(name = "connect", help = "TCP connect scan")]
    Connect,
    #[value(name = "udp", help = "UDP scan")]
    Udp,
    #[value(name = "fin", help = "TCP FIN scan")]
    Fin,
    #[value(name = "xmas", help = "TCP Xmas scan")]
    Xmas,
    #[value(name = "null", help = "TCP NULL scan")]
    Null,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Syn => write!(f, "SYN"),
            ScanType::Connect => write!(f, "CONNECT"),
            ScanType::Udp => write!(f, "UDP"),
            ScanType::Fin => write!(f, "FIN"),
            ScanType::Xmas => write!(f, "XMAS"),
            ScanType::Null => write!(f, "NULL"),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum OutputFormat {
    #[value(name = "human", help = "Human-readable output")]
    Human,
    #[value(name = "json", help = "JSON output")]
    Json,
    #[value(name = "xml", help = "XML output (Nmap compatible)")]
    Xml,
    #[value(name = "csv", help = "CSV output")]
    Csv,
}