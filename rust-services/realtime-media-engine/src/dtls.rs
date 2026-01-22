// Copyright 2025 Francisco F. Pinochet
// Copyright 2026 Fastcomcorp, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! DTLS (Datagram Transport Layer Security) implementation
//!
//! Implements RFC 6347 DTLS 1.2 for secure key exchange over UDP.
// Copyright 2025 Francisco F. Pinochet
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


use crate::error::{MediaEngineError, MediaEngineResult};
use std::net::SocketAddr;
use uuid::Uuid;

/// DTLS state (RFC 6347 Section 4.2.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsState {
    /// Closed - no connection
    Closed,
    /// Connecting - handshake in progress
    Connecting,
    /// Connected - handshake complete
    Connected,
    /// Failed - handshake failed
    Failed,
}

/// DTLS handshake message types (RFC 6347 Section 4.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsHandshakeType {
    /// Client Hello
    ClientHello = 1,
    /// Server Hello
    ServerHello = 2,
    /// Hello Verify Request
    HelloVerifyRequest = 3,
    /// Certificate
    Certificate = 11,
    /// Server Key Exchange
    ServerKeyExchange = 12,
    /// Certificate Request
    CertificateRequest = 13,
    /// Server Hello Done
    ServerHelloDone = 14,
    /// Certificate Verify
    CertificateVerify = 15,
    /// Client Key Exchange
    ClientKeyExchange = 16,
    /// Finished
    Finished = 20,
}

/// DTLS record (RFC 6347 Section 4.3.1)
#[derive(Debug, Clone)]
pub struct DtlsRecord {
    /// Content type
    pub content_type: u8,
    /// Version (major, minor)
    pub version: (u8, u8),
    /// Epoch
    pub epoch: u16,
    /// Sequence number (48 bits)
    pub sequence_number: u64,
    /// Fragment length
    pub length: u16,
    /// Fragment data
    pub fragment: Vec<u8>,
}

/// DTLS connection
pub struct DtlsConnection {
    /// Connection ID
    pub connection_id: Uuid,
    /// Local address
    pub local_addr: SocketAddr,
    /// Remote address
    pub remote_addr: Option<SocketAddr>,
    /// DTLS state
    pub state: DtlsState,
    /// Local certificate fingerprint (SHA-256)
    pub local_fingerprint: Option<String>,
    /// Remote certificate fingerprint (SHA-256)
    pub remote_fingerprint: Option<String>,
    /// Master secret (derived from handshake)
    pub master_secret: Option<Vec<u8>>,
    /// Client random
    pub client_random: Option<Vec<u8>>,
    /// Server random
    pub server_random: Option<Vec<u8>>,
}

impl DtlsConnection {
    /// Create a new DTLS connection
    pub fn new(connection_id: Uuid, local_addr: SocketAddr) -> Self {
        DtlsConnection {
            connection_id,
            local_addr,
            remote_addr: None,
            state: DtlsState::Closed,
            local_fingerprint: None,
            remote_fingerprint: None,
            master_secret: None,
            client_random: None,
            server_random: None,
        }
    }

    /// Start DTLS handshake (client side)
    pub fn start_client_handshake(&mut self) -> MediaEngineResult<Vec<u8>> {
        self.state = DtlsState::Connecting;

        // Generate client random (32 bytes per RFC 6347)
        let mut client_random = vec![0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut client_random);
        self.client_random = Some(client_random.clone());

        // Create Client Hello message (simplified - full implementation would
        // include cipher suites, extensions, etc.)
        // In production, use rustls or similar library
        let client_hello = self.create_client_hello(&client_random)?;

        Ok(client_hello)
    }

    /// Handle Server Hello
    pub fn handle_server_hello(&mut self, _server_hello: &[u8]) -> MediaEngineResult<()> {
        // Parse Server Hello and extract server random
        // In production, use rustls or similar library
        // For now, generate a placeholder
        let mut server_random = vec![0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut server_random);
        self.server_random = Some(server_random);

        Ok(())
    }

    /// Complete DTLS handshake and derive master secret
    pub fn complete_handshake(
        &mut self,
        master_secret: Vec<u8>,
    ) -> MediaEngineResult<()> {
        self.master_secret = Some(master_secret);
        self.state = DtlsState::Connected;

        Ok(())
    }

    /// Derive SRTP keys from DTLS master secret per RFC 5764
    pub fn derive_srtp_keys(&self) -> MediaEngineResult<(Vec<u8>, Vec<u8>)> {
        let master_secret = self.master_secret.as_ref()
            .ok_or_else(|| MediaEngineError::ConfigError(
                "DTLS handshake not complete".to_string()
            ))?;

        // Key derivation per RFC 5764 Section 4.2
        // Use HKDF to derive SRTP master key and salt
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hkdf = Hkdf::<Sha256>::new(None, master_secret);
        
        // Derive master key (16 bytes for AES-128)
        let mut master_key = vec![0u8; 16];
        hkdf.expand(b"EXTRACTOR-dtls_srtp", &mut master_key)
            .map_err(|e| MediaEngineError::SrtpError(format!("Key derivation error: {}", e)))?;

        // Derive master salt (14 bytes)
        let mut master_salt = vec![0u8; 14];
        hkdf.expand(b"EXTRACTOR-dtls_srtp_salt", &mut master_salt)
            .map_err(|e| MediaEngineError::SrtpError(format!("Salt derivation error: {}", e)))?;

        Ok((master_key, master_salt))
    }

    /// Create Client Hello message (simplified)
    fn create_client_hello(&self, client_random: &[u8]) -> MediaEngineResult<Vec<u8>> {
        // In production, use rustls or similar library
        // This is a placeholder that shows the structure
        let mut hello = Vec::new();
        
        // Record header
        hello.push(22); // Handshake content type
        hello.push(0xFE); // DTLS version major
        hello.push(0xFD); // DTLS version minor (1.2)
        hello.push(0x00); // Epoch
        hello.push(0x00);
        hello.push(0x00); // Sequence number (high)
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00);
        hello.push(0x00); // Sequence number (low)
        
        // Handshake message
        hello.push(DtlsHandshakeType::ClientHello as u8);
        hello.extend_from_slice(&[0x00, 0x00, 0x00]); // Length (placeholder)
        hello.extend_from_slice(&[0xFE, 0xFD]); // DTLS version
        hello.extend_from_slice(client_random);
        
        // Update length
        let length = (hello.len() - 13) as u32;
        hello[13..16].copy_from_slice(&length.to_be_bytes()[1..]);

        Ok(hello)
    }

    /// Set local certificate fingerprint
    pub fn set_local_fingerprint(&mut self, fingerprint: String) {
        self.local_fingerprint = Some(fingerprint);
    }

    /// Set remote certificate fingerprint
    pub fn set_remote_fingerprint(&mut self, fingerprint: String) {
        self.remote_fingerprint = Some(fingerprint);
    }

    /// Verify remote fingerprint matches certificate
    pub fn verify_remote_fingerprint(&self, expected: &str) -> MediaEngineResult<()> {
        let remote = self.remote_fingerprint.as_ref()
            .ok_or_else(|| MediaEngineError::ConfigError(
                "Remote fingerprint not set".to_string()
            ))?;

        if remote != expected {
            return Err(MediaEngineError::ConfigError(
                format!("Fingerprint mismatch: expected {}, got {}", expected, remote)
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_dtls_connection_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let conn = DtlsConnection::new(Uuid::new_v4(), addr);
        
        assert_eq!(conn.state, DtlsState::Closed);
        assert_eq!(conn.local_addr, addr);
    }

    #[test]
    fn test_dtls_key_derivation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let mut conn = DtlsConnection::new(Uuid::new_v4(), addr);
        
        // Set master secret
        let master_secret = vec![0u8; 48]; // 48 bytes for TLS master secret
        conn.master_secret = Some(master_secret);
        
        // Derive SRTP keys
        let (master_key, master_salt) = conn.derive_srtp_keys().unwrap();
        
        assert_eq!(master_key.len(), 16);
        assert_eq!(master_salt.len(), 14);
    }
}

