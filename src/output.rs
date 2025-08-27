use std::fs::File;
use std::io::{self, Write, BufWriter};
use std::path::PathBuf;
use anyhow::Result;
use colored::*;

use crate::cli::OutputFormat;
use crate::scanner::results::{MultiHostScanResult, PortStatus};

pub struct OutputWriter {
    format: OutputFormat,
    file: Option<PathBuf>,
}

impl OutputWriter {
    pub fn new(format: OutputFormat, file: Option<PathBuf>) -> Result<Self> {
        Ok(Self { format, file })
    }
    
    pub fn write(&self, result: MultiHostScanResult) -> Result<()> {
        let output = match self.format {
            OutputFormat::Human => self.format_human(result)?,
            OutputFormat::Json => self.format_json(result)?,
            OutputFormat::Xml => self.format_xml(result)?,
            OutputFormat::Csv => self.format_csv(result)?,
        };
        
        match &self.file {
            Some(path) => {
                let file = File::create(path)?;
                let mut writer = BufWriter::new(file);
                writer.write_all(output.as_bytes())?;
                writer.flush()?;
            }
            None => {
                print!("{}", output);
                io::stdout().flush()?;
            }
        }
        
        Ok(())
    }
    
    fn format_human(&self, result: MultiHostScanResult) -> Result<String> {
        let mut output = String::new();
        
        // Clean header
        output.push_str(&format!("\n{}\n\n", 
            "NETWORK SCAN COMPLETE".truecolor(0, 255, 65).bold()));
        
        // Clean scan info
        output.push_str(&format!("{} {} {} {} {}\n", 
            "⟦".truecolor(64, 64, 64),
            result.target_spec.truecolor(255, 255, 255).bold(),
            "•".truecolor(0, 255, 65),
            result.scan_type.to_string().truecolor(255, 140, 0).bold(),
            "⟧".truecolor(64, 64, 64)));
        output.push_str(&format!("{} {} {} {} {} {}\n\n", 
            "⟦".truecolor(64, 64, 64),
            format!("{}ms", (result.end_time - result.start_time).num_milliseconds()).truecolor(0, 212, 255).bold(),
            "•".truecolor(0, 255, 65),
            format!("{} hosts", result.total_hosts).truecolor(191, 64, 191).bold(),
            "•".truecolor(0, 255, 65),
            format!("{} ports", result.total_ports).truecolor(191, 64, 191).bold()));
        
        let mut hosts_with_open_ports = 0;
        let mut total_open_ports = 0;
        
        for host in &result.hosts {
            let open_ports: Vec<_> = host.ports.iter()
                .filter(|p| p.status == PortStatus::Open)
                .collect();
            let filtered_ports: Vec<_> = host.ports.iter()
                .filter(|p| p.status == PortStatus::Filtered)
                .collect();
            
            if !open_ports.is_empty() {
                hosts_with_open_ports += 1;
                total_open_ports += open_ports.len();
                
                // Clean host header
                output.push_str(&format!("{} {} {} {} {}\n", 
                    "▶".truecolor(0, 255, 65).bold(),
                    host.target_ip.to_string().truecolor(255, 255, 255).bold(),
                    "•".truecolor(64, 64, 64),
                    format!("{} open ports", open_ports.len()).truecolor(0, 212, 255).bold(),
                    if !filtered_ports.is_empty() { 
                        format!("• {} filtered", filtered_ports.len()).truecolor(255, 140, 0) 
                    } else { 
                        "".truecolor(255, 255, 255)
                    }));
                
                for port in &open_ports {
                    let service = if let Some(ref service_info) = port.service_detected {
                        if let Some(ref version) = service_info.version {
                            format!("{} {}", service_info.name, version)
                        } else {
                            service_info.name.clone()
                        }
                    } else {
                        get_service_name(port.port).to_string()
                    };
                    
                    // Add response time if available
                    let service_display = if let Some(response_time) = port.response_time {
                        format!("{} ({:.1}ms)", service, response_time)
                    } else {
                        service
                    };
                    
                    output.push_str(&format!("  {} {} {} {}\n",
                        port.port.to_string().truecolor(255, 255, 255).bold(),
                        "●".truecolor(0, 255, 65),
                        "open".truecolor(0, 255, 65),
                        service_display.truecolor(128, 128, 128)));
                }
                
                output.push_str("\n");
            }
        }
        
        // Clean summary
        if hosts_with_open_ports == 0 {
            output.push_str(&format!("{} {}\n", 
                "⚠".truecolor(255, 140, 0).bold(),
                "No open ports detected - all targets secured".truecolor(128, 128, 128)));
        } else {
            output.push_str(&format!("{} {} {} {} {} {}\n", 
                "⚡".truecolor(0, 255, 65).bold(),
                "Scan complete:".truecolor(0, 255, 65).bold(),
                format!("{} active hosts", hosts_with_open_ports).truecolor(255, 255, 255).bold(),
                "•".truecolor(64, 64, 64),
                format!("{} open ports", total_open_ports).truecolor(255, 255, 255).bold(),
                "found".truecolor(0, 255, 65).bold()));
        }
        
        output.push_str(&format!("\n{}\n", 
            "▓▒░ SCAN OPERATION COMPLETE ░▒▓".truecolor(191, 64, 191).bold()));
        
        Ok(output)
    }
    
    fn format_json(&self, result: MultiHostScanResult) -> Result<String> {
        Ok(serde_json::to_string_pretty(&result)?)
    }
    
    fn format_xml(&self, result: MultiHostScanResult) -> Result<String> {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<nmaprun>\n");
        xml.push_str(&format!("  <scaninfo type=\"{:?}\" />\n", result.scan_type));
        
        for host in &result.hosts {
            xml.push_str(&format!("  <host><address addr=\"{}\" addrtype=\"ipv4\"/>\n", host.target_ip));
            xml.push_str("    <ports>\n");
            
            for port in &host.ports {
                xml.push_str(&format!(
                    "      <port protocol=\"tcp\" portid=\"{}\">\n",
                    port.port
                ));
                xml.push_str(&format!(
                    "        <state state=\"{}\" reason=\"syn-ack\" reason_ttl=\"0\"/>\n",
                    port.status
                ));
                xml.push_str("      </port>\n");
            }
            
            xml.push_str("    </ports>\n");
            xml.push_str("  </host>\n");
        }
        
        xml.push_str("</nmaprun>\n");
        Ok(xml)
    }
    
    fn format_csv(&self, result: MultiHostScanResult) -> Result<String> {
        let mut csv = String::new();
        csv.push_str("target,target_ip,port,status,service,version,response_time_ms,scan_type\n");
        
        for host in &result.hosts {
            for port in &host.ports {
                let service_name = port.service_detected.as_ref()
                    .map(|s| s.name.as_str()).unwrap_or("");
                let service_version = port.service_detected.as_ref()
                    .and_then(|s| s.version.as_ref().map(|v| v.as_str()))
                    .unwrap_or("");
                let response_time = port.response_time
                    .map(|rt| rt.to_string()).unwrap_or_else(|| "".to_string());
                    
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{:?}\n",
                    host.target,
                    host.target_ip,
                    port.port,
                    port.status,
                    service_name,
                    service_version,
                    response_time,
                    result.scan_type
                ));
            }
        }
        
        Ok(csv)
    }
}

fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "TELNET",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NETBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "ORACLE",
        3306 => "MYSQL",
        3389 => "RDP",
        5000 => "UPNP",
        5432 => "POSTGRESQL",
        5900 => "VNC",
        6379 => "REDIS",
        8080 => "HTTP-ALT",
        8443 => "HTTPS-ALT",
        27017 => "MONGODB",
        _ => "UNKNOWN"
    }
}
