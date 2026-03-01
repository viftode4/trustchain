//! Minimal STUN client for NAT traversal.
//!
//! Sends a STUN Binding Request to discover our public IP:port as seen
//! by the STUN server. Only supports the XOR-MAPPED-ADDRESS attribute
//! from RFC 5389.

use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// STUN magic cookie (RFC 5389).
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN attribute type for XOR-MAPPED-ADDRESS.
const XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN attribute type for MAPPED-ADDRESS (fallback).
const MAPPED_ADDRESS: u16 = 0x0001;

/// Discover our public address by sending a STUN Binding Request.
///
/// Returns the public `SocketAddr` as seen by the STUN server.
pub async fn discover_public_addr(stun_server: &str) -> Result<SocketAddr, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind failed: {e}"))?;

    // Build STUN Binding Request (20 bytes).
    // Header: type=0x0001 (Binding Request), length=0x0000, magic cookie, transaction ID (12 bytes).
    let mut request = [0u8; 20];
    request[0] = 0x00; // Type high byte
    request[1] = 0x01; // Type low byte (Binding Request)
    // Length = 0 (no attributes)
    request[2] = 0x00;
    request[3] = 0x00;
    // Magic cookie
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 random bytes)
    use rand::Rng;
    let tx_id: [u8; 12] = rand::thread_rng().gen();
    request[8..20].copy_from_slice(&tx_id);

    socket
        .send_to(&request, stun_server)
        .await
        .map_err(|e| format!("send failed: {e}"))?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.recv(&mut buf),
    )
    .await
    .map_err(|_| "STUN timeout".to_string())?
    .map_err(|e| format!("recv failed: {e}"))?;

    if n < 20 {
        return Err("STUN response too short".to_string());
    }

    // Verify it's a Binding Response (0x0101).
    if buf[0] != 0x01 || buf[1] != 0x01 {
        return Err(format!(
            "unexpected STUN message type: 0x{:02x}{:02x}",
            buf[0], buf[1]
        ));
    }

    // Verify transaction ID matches.
    if buf[8..20] != tx_id {
        return Err("STUN transaction ID mismatch".to_string());
    }

    // Parse attributes.
    parse_stun_response(&buf[20..n], &buf[4..8], &tx_id)
}

/// Parse STUN response attributes, looking for XOR-MAPPED-ADDRESS or MAPPED-ADDRESS.
pub fn parse_stun_response(attrs: &[u8], magic: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[offset], attrs[offset + 1]]);
        let attr_len = u16::from_be_bytes([attrs[offset + 2], attrs[offset + 3]]) as usize;
        let value_start = offset + 4;

        if value_start + attr_len > attrs.len() {
            break;
        }

        let value = &attrs[value_start..value_start + attr_len];

        if attr_type == XOR_MAPPED_ADDRESS {
            return parse_xor_mapped_address(value, magic, tx_id);
        }
        if attr_type == MAPPED_ADDRESS {
            return parse_mapped_address(value);
        }

        // Align to 4-byte boundary.
        offset = value_start + ((attr_len + 3) & !3);
    }

    Err("no MAPPED-ADDRESS found in STUN response".to_string())
}

fn parse_xor_mapped_address(value: &[u8], magic: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
    if value.len() < 8 {
        return Err("XOR-MAPPED-ADDRESS too short".to_string());
    }

    let family = value[1];
    let xor_port = u16::from_be_bytes([value[2], value[3]]);
    let port = xor_port ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            let xor_ip = [value[4], value[5], value[6], value[7]];
            let ip = [
                xor_ip[0] ^ magic[0],
                xor_ip[1] ^ magic[1],
                xor_ip[2] ^ magic[2],
                xor_ip[3] ^ magic[3],
            ];
            Ok(SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
                port,
            ))
        }
        0x02 => {
            // IPv6: XOR with magic cookie (4 bytes) + transaction ID (12 bytes) = 16 bytes
            if value.len() < 20 {
                return Err("XOR-MAPPED-ADDRESS IPv6 too short".to_string());
            }
            let mut xor_key = [0u8; 16];
            xor_key[..4].copy_from_slice(magic);
            xor_key[4..16].copy_from_slice(tx_id);
            let mut ip_bytes = [0u8; 16];
            for i in 0..16 {
                ip_bytes[i] = value[4 + i] ^ xor_key[i];
            }
            Ok(SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes)),
                port,
            ))
        }
        _ => Err(format!("unknown address family: {family}")),
    }
}

fn parse_mapped_address(value: &[u8]) -> Result<SocketAddr, String> {
    if value.len() < 8 {
        return Err("MAPPED-ADDRESS too short".to_string());
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);

    match family {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(value[4], value[5], value[6], value[7]);
            Ok(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        _ => Err(format!("unsupported MAPPED-ADDRESS family: {family}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_parse_xor_mapped_address_ipv4() {
        let magic = MAGIC_COOKIE.to_be_bytes();
        let tx_id = [0u8; 12]; // dummy transaction ID (not used for IPv4)

        let port: u16 = 12345;
        let xor_port = port ^ (MAGIC_COOKIE >> 16) as u16;

        let ip_bytes: [u8; 4] = [203, 0, 113, 42];
        let xor_ip: [u8; 4] = [
            ip_bytes[0] ^ magic[0],
            ip_bytes[1] ^ magic[1],
            ip_bytes[2] ^ magic[2],
            ip_bytes[3] ^ magic[3],
        ];

        let mut attr = Vec::new();
        attr.extend_from_slice(&0x0020u16.to_be_bytes());
        attr.extend_from_slice(&0x0008u16.to_be_bytes());
        attr.push(0x00);
        attr.push(0x01);
        attr.extend_from_slice(&xor_port.to_be_bytes());
        attr.extend_from_slice(&xor_ip);

        let result = parse_stun_response(&attr, &magic, &tx_id).unwrap();
        assert_eq!(result.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 42)));
        assert_eq!(result.port(), 12345);
    }

    #[test]
    fn test_stun_parse_xor_mapped_address_ipv6() {
        let magic = MAGIC_COOKIE.to_be_bytes();
        let tx_id: [u8; 12] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];

        // Target IPv6: 2001:db8::1 = [0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1]
        let ip_bytes: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut xor_key = [0u8; 16];
        xor_key[..4].copy_from_slice(&magic);
        xor_key[4..16].copy_from_slice(&tx_id);
        let mut xor_ip = [0u8; 16];
        for i in 0..16 {
            xor_ip[i] = ip_bytes[i] ^ xor_key[i];
        }

        let port: u16 = 9000;
        let xor_port = port ^ (MAGIC_COOKIE >> 16) as u16;

        let mut attr = Vec::new();
        attr.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
        attr.extend_from_slice(&0x0014u16.to_be_bytes()); // Length: 20
        attr.push(0x00); // reserved
        attr.push(0x02); // family: IPv6
        attr.extend_from_slice(&xor_port.to_be_bytes());
        attr.extend_from_slice(&xor_ip);

        let result = parse_stun_response(&attr, &magic, &tx_id).unwrap();
        assert_eq!(result.ip(), std::net::IpAddr::V6("2001:db8::1".parse().unwrap()));
        assert_eq!(result.port(), 9000);
    }

    #[test]
    fn test_stun_parse_mapped_address_ipv4() {
        let magic = MAGIC_COOKIE.to_be_bytes();
        let tx_id = [0u8; 12];

        let mut attr = Vec::new();
        attr.extend_from_slice(&0x0001u16.to_be_bytes());
        attr.extend_from_slice(&0x0008u16.to_be_bytes());
        attr.push(0x00);
        attr.push(0x01);
        attr.extend_from_slice(&8080u16.to_be_bytes());
        attr.extend_from_slice(&[192, 168, 1, 1]);

        let result = parse_stun_response(&attr, &magic, &tx_id).unwrap();
        assert_eq!(result.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(result.port(), 8080);
    }
}
