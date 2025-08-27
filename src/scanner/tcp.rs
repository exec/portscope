use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use pnet::packet::tcp::{TcpFlags, MutableTcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType::Layer4};
use pnet::transport::tcp_packet_iter;
use anyhow::Result;

use crate::scanner::results::PortStatus;

pub async fn connect_scan(target: IpAddr, port: u16, timeout_ms: u64) -> PortStatus {
    let addr = SocketAddr::new(target, port);
    let duration = Duration::from_millis(timeout_ms);
    
    match timeout(duration, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => PortStatus::Open,
        Ok(Err(e)) => {
            // Connection refused is immediate and means port is closed
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortStatus::Closed
            } else {
                // Other errors like network unreachable, host unreachable
                PortStatus::Filtered
            }
        },
        Err(_) => PortStatus::Filtered,
    }
}

/// Fast connect scan with shorter timeout for local networks
pub async fn fast_connect_scan(target: IpAddr, port: u16, timeout_ms: u64) -> PortStatus {
    let addr = SocketAddr::new(target, port);
    
    // Use shorter timeout for initial attempt (good for LANs)
    let short_timeout = Duration::from_millis(timeout_ms.min(300));
    
    match timeout(short_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => PortStatus::Open,
        Ok(Err(e)) => {
            if e.kind() == std::io::ErrorKind::ConnectionRefused {
                PortStatus::Closed
            } else {
                // Retry with full timeout for other errors
                let full_timeout = Duration::from_millis(timeout_ms);
                match timeout(full_timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => PortStatus::Open,
                    Ok(Err(_)) => PortStatus::Closed,
                    Err(_) => PortStatus::Filtered,
                }
            }
        },
        Err(_) => {
            // Short timeout failed, could be slow network - try full timeout
            let remaining_timeout = Duration::from_millis(timeout_ms.saturating_sub(300));
            match timeout(remaining_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => PortStatus::Open,
                Ok(Err(_)) => PortStatus::Closed,
                Err(_) => PortStatus::Filtered,
            }
        }
    }
}

pub async fn syn_scan(target: IpAddr, port: u16, timeout_ms: u64) -> PortStatus {
    if !is_root() {
        return connect_scan(target, port, timeout_ms).await;
    }
    
    match perform_raw_scan(target, port, timeout_ms, TcpFlags::SYN).await {
        Ok(status) => status,
        Err(_) => PortStatus::Error,
    }
}

pub async fn fin_scan(target: IpAddr, port: u16, timeout_ms: u64) -> PortStatus {
    if !is_root() {
        return PortStatus::Error;
    }
    
    match perform_raw_scan(target, port, timeout_ms, TcpFlags::FIN).await {
        Ok(status) => status,
        Err(_) => PortStatus::Error,
    }
}

pub async fn xmas_scan(target: IpAddr, port: u16, timeout_ms: u64) -> PortStatus {
    if !is_root() {
        return PortStatus::Error;
    }
    
    let flags = TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG;
    match perform_raw_scan(target, port, timeout_ms, flags).await {
        Ok(status) => status,
        Err(_) => PortStatus::Error,
    }
}

pub async fn null_scan(target: IpAddr, port: u16, timeout_ms: u64) -> PortStatus {
    if !is_root() {
        return PortStatus::Error;
    }
    
    match perform_raw_scan(target, port, timeout_ms, 0).await {
        Ok(status) => status,
        Err(_) => PortStatus::Error,
    }
}

async fn perform_raw_scan(
    target: IpAddr,
    port: u16,
    timeout_ms: u64,
    flags: u8,
) -> Result<PortStatus> {
    match target {
        IpAddr::V4(ipv4) => {
            // Create raw TCP socket
            let protocol = Layer4(pnet::transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
            
            #[cfg(windows)]
            {
                // On Windows, raw socket support requires administrative privileges
                // and has different behavior. For now, fall back to connect scan
                return Ok(connect_scan(target, port, timeout_ms).await);
            }
            
            #[cfg(not(windows))]
            {
                let (mut tx, mut rx) = transport_channel(4096, protocol)
                    .map_err(|e| anyhow::anyhow!("Failed to create raw socket: {}", e))?;
                
                // Generate random source port to avoid conflicts
                let source_port = (rand::random::<u16>() % 32768) + 32768;
                let sequence = rand::random::<u32>();
                
                // Build TCP packet with proper headers
                let mut tcp_packet = MutableTcpPacket::owned(vec![0u8; 20])
                    .ok_or_else(|| anyhow::anyhow!("Failed to create TCP packet"))?;
                
                tcp_packet.set_source(source_port);
                tcp_packet.set_destination(port);
                tcp_packet.set_sequence(sequence);
                tcp_packet.set_acknowledgement(0);
                tcp_packet.set_flags(flags);
                tcp_packet.set_window(65535);  // Maximum window size
                tcp_packet.set_data_offset(5); // 20 bytes / 4 = 5
                tcp_packet.set_urgent_ptr(0);
                tcp_packet.set_checksum(0);
                
                // Calculate and set TCP checksum
                let local_ip = std::net::Ipv4Addr::new(127, 0, 0, 1); // Will be replaced by kernel
                let checksum = pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), &local_ip, &ipv4);
                tcp_packet.set_checksum(checksum);
                
                // Send the packet
                tx.send_to(tcp_packet, IpAddr::V4(ipv4))
                    .map_err(|e| anyhow::anyhow!("Failed to send packet: {}", e))?;
                
                // Listen for response
                let start = std::time::Instant::now();
                let duration = Duration::from_millis(timeout_ms);
                
                let mut iter = tcp_packet_iter(&mut rx);
                
                // For closed ports, we should get RST immediately
                // For open ports, we get SYN-ACK quickly  
                // Only filtered ports will timeout
                let check_interval = Duration::from_millis(10);
                
                while start.elapsed() < duration {
                    match iter.next_with_timeout(check_interval) {
                        Ok(Some((packet, addr))) => {
                            // Verify this is our response
                            if packet.get_source() == port && 
                               packet.get_destination() == source_port &&
                               addr == IpAddr::V4(ipv4) {
                                
                                let tcp_flags = packet.get_flags();
                                
                                // SYN-ACK indicates open port
                                if tcp_flags & TcpFlags::SYN != 0 && tcp_flags & TcpFlags::ACK != 0 {
                                    return Ok(PortStatus::Open);
                                }
                                // RST indicates closed port (immediate response)
                                else if tcp_flags & TcpFlags::RST != 0 {
                                    return Ok(PortStatus::Closed);
                                }
                                // For stealth scans, no response typically means open/filtered
                                else if flags != TcpFlags::SYN {
                                    return Ok(PortStatus::Open);
                                }
                            }
                        }
                        Ok(None) => {
                            // No packet yet, continue waiting
                            continue;
                        },
                        Err(_) => {
                            // Timeout on individual packet, continue waiting for full duration
                            continue;
                        }
                    }
                }
                
                // Timeout - port is filtered or stealth scan indicates open
                if flags == TcpFlags::SYN {
                    Ok(PortStatus::Filtered)
                } else {
                    // For stealth scans (FIN, XMAS, NULL), no response usually means open/filtered
                    Ok(PortStatus::Open)
                }
            }
        }
        IpAddr::V6(_) => {
            Err(anyhow::anyhow!("IPv6 raw socket scanning not yet implemented"))
        }
    }
}

pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // On Windows, check if running as Administrator
        use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TOKEN_QUERY, TOKEN_ELEVATION, TokenElevation};
        use winapi::shared::minwindef::{DWORD, FALSE};
        use std::ptr;
        use std::mem;
        
        unsafe {
            let mut token_handle = ptr::null_mut();
            
            // Get process token
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle) == FALSE {
                return false;
            }
            
            let mut elevation: DWORD = 0;
            let mut return_length: DWORD = 0;
            
            // Check if process is elevated (running as Administrator)
            let result = GetTokenInformation(
                token_handle,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                mem::size_of::<DWORD>() as DWORD,
                &mut return_length,
            );
            
            // Clean up token handle
            winapi::um::handleapi::CloseHandle(token_handle);
            
            result != FALSE && elevation != 0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}