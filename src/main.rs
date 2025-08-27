mod cli;
mod scanner;
mod output;
mod utils;
mod network;
mod adaptive;

use anyhow::Result;
use clap::Parser;
use colored::*;
use tracing_subscriber;

use crate::cli::Cli;
use crate::scanner::Scanner;
use crate::output::OutputWriter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    tracing_subscriber::fmt::init();
    
    // No legal BS, just pure scanning action! 🔥
    
    let mut scanner = Scanner::new(
        cli.rate_limit.unwrap_or(10), // 10ms rate limit for responsiveness
        cli.timeout.unwrap_or(3000),  // 3 second timeout default
        cli.parallel_hosts.unwrap_or(50), // 50 parallel connections
    );
    
    let output_writer = OutputWriter::new(cli.output_format, cli.output_file)?;
    
    // Check if target is provided
    if cli.target.is_empty() {
        eprintln!("{}", "Error: No target specified.".red());
        eprintln!("Example: portscope 192.168.1.1");
        eprintln!("Run 'portscope --help' for more information.");
        std::process::exit(1);
    }
    
    let target_spec = cli.target.join(",");
    let ports_spec = match cli.ports {
        Some(ports) => {
            if ports.len() == 1 && ports[0] == "-" {
                "1-65535".to_string() // -p- means all ports
            } else {
                ports.join(",")
            }
        },
        None => "1-1000".to_string(), // Default: scan common ports
    };
    let results = scanner.scan(
        &target_spec,
        &ports_spec,
        cli.scan_type.unwrap_or(crate::cli::ScanType::Syn),
    ).await?;
    
    output_writer.write(results)?;
    
    Ok(())
}
