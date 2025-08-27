use std::net::{IpAddr, Ipv4Addr};
use anyhow::{Result, anyhow};
use ipnet::IpNet;

pub fn parse_targets(target_spec: &str) -> Result<Vec<IpAddr>> {
    let mut targets = Vec::new();
    
    for part in target_spec.split(',') {
        let part = part.trim();
        
        if part.contains('/') {
            targets.extend(parse_cidr(part)?);
        } else if part.contains('-') && !part.contains(':') {
            targets.extend(parse_ip_range(part)?);
        } else {
            targets.push(parse_single_target(part)?);
        }
    }
    
    targets.sort();
    targets.dedup();
    
    Ok(targets)
}

fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
    let network: IpNet = cidr.parse()
        .map_err(|_| anyhow!("Invalid CIDR notation: {}", cidr))?;
    
    match network {
        IpNet::V4(net) => {
            let mut ips = Vec::new();
            for ip in net.hosts() {
                ips.push(IpAddr::V4(ip));
            }
            Ok(ips)
        }
        IpNet::V6(net) => {
            let mut ips = Vec::new();
            let mut count = 0;
            for ip in net.hosts() {
                if count >= 1000 {
                    break;
                }
                ips.push(IpAddr::V6(ip));
                count += 1;
            }
            Ok(ips)
        }
    }
}

fn parse_ip_range(range: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid IP range format: {}", range));
    }
    
    let start_ip: IpAddr = parts[0].trim().parse()
        .map_err(|_| anyhow!("Invalid start IP: {}", parts[0]))?;
    let end_ip: IpAddr = parts[1].trim().parse()
        .map_err(|_| anyhow!("Invalid end IP: {}", parts[1]))?;
    
    match (start_ip, end_ip) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            let mut ips = Vec::new();
            let start_u32 = u32::from(start);
            let end_u32 = u32::from(end);
            
            if start_u32 > end_u32 {
                return Err(anyhow!("Start IP must be less than or equal to end IP"));
            }
            
            if end_u32 - start_u32 > 10000 {
                return Err(anyhow!("IP range too large (max 10000 addresses)"));
            }
            
            for ip_u32 in start_u32..=end_u32 {
                ips.push(IpAddr::V4(Ipv4Addr::from(ip_u32)));
            }
            
            Ok(ips)
        }
        (IpAddr::V6(_), IpAddr::V6(_)) => {
            Err(anyhow!("IPv6 ranges not yet supported"))
        }
        _ => {
            Err(anyhow!("Start and end IP must be the same version"))
        }
    }
}

fn parse_single_target(target: &str) -> Result<IpAddr> {
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }
    
    use std::net::ToSocketAddrs;
    let addr = format!("{}:0", target)
        .to_socket_addrs()
        .map_err(|_| anyhow!("Failed to resolve hostname: {}", target))?
        .next()
        .ok_or_else(|| anyhow!("No IP address found for hostname: {}", target))?;
    
    Ok(addr.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_ip() {
        let targets = parse_targets("192.168.1.1").unwrap();
        assert_eq!(targets, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]);
    }

    #[test]
    fn test_parse_cidr() {
        let targets = parse_targets("192.168.1.0/30").unwrap();
        assert_eq!(targets.len(), 2);
        assert!(targets.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(targets.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
    }

    #[test]
    fn test_parse_ip_range() {
        let targets = parse_targets("192.168.1.1-192.168.1.3").unwrap();
        assert_eq!(targets.len(), 3);
        assert!(targets.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(targets.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))));
        assert!(targets.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3))));
    }

    #[test]
    fn test_parse_mixed() {
        let targets = parse_targets("192.168.1.1,192.168.1.10-192.168.1.11").unwrap();
        assert_eq!(targets.len(), 3);
    }

    #[test]
    fn test_invalid_cidr() {
        let result = parse_targets("192.168.1.0/99");
        assert!(result.is_err());
    }

    #[test]
    fn test_large_range_rejected() {
        let result = parse_targets("0.0.0.0-255.255.255.255");
        assert!(result.is_err());
    }
}