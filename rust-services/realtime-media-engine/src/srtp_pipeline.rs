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

//! SRTP (Secure Real-time Transport Protocol) pipeline
//!
//! Implements RFC 3711 SRTP encryption/decryption.
//! Uses AES-128-GCM for encryption and authentication.
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
use crate::rtp_handler::RtpPacket;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};

/// SRTP configuration
#[derive(Debug, Clone)]
pub struct SrtpConfig {
    /// Master key (16 bytes for AES-128)
    pub master_key: Vec<u8>,
    /// Master salt (14 bytes)
    pub master_salt: Vec<u8>,
    /// SSRC for this stream
    pub ssrc: u32,
    /// Rollover counter (for sequence number extension)
    pub roc: u32,
}

/// SRTP pipeline for encrypting/decrypting RTP packets
pub struct SrtpPipeline {
    /// Encryption key (derived from master key)
    #[allow(dead_code)]
    encryption_key: Vec<u8>,
    /// Authentication key (derived from master key)
    #[allow(dead_code)]
    auth_key: Vec<u8>,
    /// Salt key (derived from master salt)
    salt_key: Vec<u8>,
    /// SSRC
    ssrc: u32,
    /// Sequence number (16 bits, with rollover)
    sequence_number: AtomicU64, // Using u64 to handle rollover
    /// Rollover counter (32 bits, increments when sequence wraps)
    roc: AtomicU64,
    /// Cipher instance
    cipher: Aes128Gcm,
}

impl SrtpPipeline {
    /// Create a new SRTP pipeline from configuration
    pub fn new(config: SrtpConfig) -> MediaEngineResult<Self> {
        // Validate key sizes
        if config.master_key.len() != 16 {
            return Err(MediaEngineError::SrtpError(
                format!("Master key must be 16 bytes, got {}", config.master_key.len())
            ));
        }
        if config.master_salt.len() != 14 {
            return Err(MediaEngineError::SrtpError(
                format!("Master salt must be 14 bytes, got {}", config.master_salt.len())
            ));
        }

        // Derive encryption key using HKDF
        let hkdf = Hkdf::<Sha256>::new(None, &config.master_key);
        let mut encryption_key = vec![0u8; 16];
        hkdf.expand(b"SRTP encryption key", &mut encryption_key)
            .map_err(|e| MediaEngineError::SrtpError(format!("HKDF error: {}", e)))?;

        // Derive authentication key
        let mut auth_key = vec![0u8; 16];
        hkdf.expand(b"SRTP authentication key", &mut auth_key)
            .map_err(|e| MediaEngineError::SrtpError(format!("HKDF error: {}", e)))?;

        // Derive salt key
        let mut salt_key = vec![0u8; 14];
        let hkdf_salt = Hkdf::<Sha256>::new(None, &config.master_salt);
        hkdf_salt.expand(b"SRTP salt key", &mut salt_key)
            .map_err(|e| MediaEngineError::SrtpError(format!("HKDF error: {}", e)))?;

        // Create cipher
        let cipher = Aes128Gcm::new_from_slice(&encryption_key)
            .map_err(|e| MediaEngineError::SrtpError(format!("Cipher init error: {}", e)))?;

        Ok(SrtpPipeline {
            encryption_key,
            auth_key,
            salt_key,
            ssrc: config.ssrc,
            sequence_number: AtomicU64::new(0),
            roc: AtomicU64::new(config.roc as u64),
            cipher,
        })
    }

    /// Encrypt RTP packet to SRTP
    pub fn encrypt(&self, packet: &RtpPacket) -> MediaEngineResult<Vec<u8>> {
        // Use packet's sequence number
        let seq_low = packet.header.sequence_number;
        
        // Get current ROC
        let roc = self.roc.load(Ordering::SeqCst) as u32;
        
        // Check if sequence number wrapped (went backwards significantly)
        let current_seq = self.sequence_number.load(Ordering::SeqCst);
        let seq_combined = (roc as u64) << 16 | (seq_low as u64);
        
        if seq_combined > current_seq {
            // Update sequence number
            self.sequence_number.store(seq_combined, Ordering::SeqCst);
            
            // Check if we need to increment ROC
            if seq_low < (current_seq & 0xFFFF) as u16 {
                self.roc.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Generate IV (Initialization Vector) for AES-GCM
        let iv = self.generate_iv(seq_low, roc);

        // Encrypt payload (without AAD for now - will add in Phase 2)
        let nonce = Nonce::from_slice(&iv);
        let ciphertext = self.cipher
            .encrypt(nonce, packet.payload.as_ref())
            .map_err(|e| MediaEngineError::SrtpError(format!("Encryption error: {}", e)))?;

        // Build SRTP packet: RTP header + encrypted payload (includes auth tag)
        let mut srtp_packet = packet.header.serialize().to_vec();
        srtp_packet.extend_from_slice(&ciphertext);

        Ok(srtp_packet)
    }

    /// Decrypt SRTP packet to RTP
    pub fn decrypt(&self, srtp_data: &[u8]) -> MediaEngineResult<RtpPacket> {
        // Parse RTP header first
        let (header, encrypted_payload) = crate::rtp_handler::RtpHeader::parse(srtp_data)?;

        // Extract sequence number
        let seq_low = header.sequence_number;
        
        // Get current ROC (we'll need to detect rollover)
        let roc = self.roc.load(Ordering::SeqCst) as u32;

        // Generate IV
        let iv = self.generate_iv(seq_low, roc);

        // Decrypt payload (ciphertext includes auth tag)
        let nonce = Nonce::from_slice(&iv);
        
        if encrypted_payload.len() < 16 {
            return Err(MediaEngineError::SrtpError(
                "SRTP packet too short for authentication tag".to_string()
            ));
        }

        let plaintext = self.cipher
            .decrypt(nonce, encrypted_payload)
            .map_err(|e| MediaEngineError::SrtpError(format!("Decryption error: {}", e)))?;

        // Update sequence number tracking
        let current_seq = self.sequence_number.load(Ordering::SeqCst);
        let seq_combined = (roc as u64) << 16 | (seq_low as u64);
        
        // Handle sequence number rollover
        if seq_combined > current_seq {
            self.sequence_number.store(seq_combined, Ordering::SeqCst);
        }

        Ok(RtpPacket {
            header,
            payload: plaintext.into(),
        })
    }

    /// Generate IV (Initialization Vector) for AES-GCM per RFC 7714
    /// IV format per RFC 3711 Section 4.1.1 (adapted for GCM):
    /// IV = salt_key XOR (SSRC || ROC || seq_low || 0x00)
    /// For AES-128-GCM, IV is 12 bytes
    fn generate_iv(&self, seq_low: u16, roc: u32) -> Vec<u8> {
        let mut iv = vec![0u8; 12]; // 12 bytes for AES-GCM

        // Build IV per RFC 3711: SSRC (4 bytes) || ROC (4 bytes) || seq_low (2 bytes) || padding (2 bytes)
        iv[0..4].copy_from_slice(&self.ssrc.to_be_bytes());
        iv[4..8].copy_from_slice(&roc.to_be_bytes());
        iv[8..10].copy_from_slice(&seq_low.to_be_bytes());
        // Last 2 bytes remain 0 (padding)

        // XOR with salt key per RFC 3711 Section 4.1.1
        // Salt key is 14 bytes, but we only use first 12 for IV
        for i in 0..12.min(self.salt_key.len()) {
            iv[i] ^= self.salt_key[i];
        }

        iv
    }

    /// Get current sequence number
    pub fn current_sequence(&self) -> u64 {
        self.sequence_number.load(Ordering::SeqCst)
    }

    /// Get current rollover counter
    pub fn current_roc(&self) -> u32 {
        self.roc.load(Ordering::SeqCst) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_handler::{RtpHeader, RtpPacket};
    use bytes::Bytes;

    fn create_test_packet() -> RtpPacket {
        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 96,
            sequence_number: 1,
            timestamp: 1000,
            ssrc: 12345,
            csrc: vec![],
            extension_header: None,
        };

        RtpPacket {
            header,
            payload: Bytes::from("test payload data"),
        }
    }

    #[test]
    fn test_srtp_encrypt_decrypt() {
        // Create test keys
        let master_key = vec![0u8; 16];
        let master_salt = vec![0u8; 14];

        let config = SrtpConfig {
            master_key,
            master_salt,
            ssrc: 12345,
            roc: 0,
        };

        let pipeline = SrtpPipeline::new(config).unwrap();
        let packet = create_test_packet();

        // Encrypt
        let encrypted = pipeline.encrypt(&packet).unwrap();

        // Decrypt
        let decrypted = pipeline.decrypt(&encrypted).unwrap();

        // Verify
        assert_eq!(packet.header.sequence_number, decrypted.header.sequence_number);
        assert_eq!(packet.header.timestamp, decrypted.header.timestamp);
        assert_eq!(packet.header.ssrc, decrypted.header.ssrc);
        assert_eq!(packet.payload, decrypted.payload);
    }

    #[test]
    fn test_srtp_sequence_tracking() {
        let master_key = vec![0u8; 16];
        let master_salt = vec![0u8; 14];

        let config = SrtpConfig {
            master_key,
            master_salt,
            ssrc: 12345,
            roc: 0,
        };

        let pipeline = SrtpPipeline::new(config).unwrap();

        // Encrypt multiple packets with increasing sequence numbers
        for i in 0..10 {
            let mut packet = create_test_packet();
            packet.header.sequence_number = i + 1;
            pipeline.encrypt(&packet).unwrap();
        }

        // Check sequence number tracking (should track the last sequence)
        // The sequence is stored as (roc << 16) | seq_low
        let last_seq = pipeline.current_sequence();
        assert!(last_seq >= 10, "Expected sequence >= 10, got {}", last_seq);
    }
}

