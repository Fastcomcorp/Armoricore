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

//! RTP (Real-time Transport Protocol) packet handling
//!
//! Implements RFC 3550 RTP packet parsing and construction.
//! This is the foundation for all media transport in ArcRTC.
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
use bytes::{BufMut, Bytes, BytesMut};

/// RTP header as defined in RFC 3550
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    /// RTP version (must be 2)
    pub version: u8,
    /// Padding flag
    pub padding: bool,
    /// Extension flag
    pub extension: bool,
    /// CSRC count
    pub csrc_count: u8,
    /// Marker bit
    pub marker: bool,
    /// Payload type (7 bits)
    pub payload_type: u8,
    /// Sequence number (16 bits)
    pub sequence_number: u16,
    /// Timestamp (32 bits)
    pub timestamp: u32,
    /// SSRC (Synchronization Source) identifier (32 bits)
    pub ssrc: u32,
    /// CSRC (Contributing Source) identifiers
    pub csrc: Vec<u32>,
    /// Extension header (optional)
    pub extension_header: Option<ExtensionHeader>,
}

/// RTP extension header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionHeader {
    /// Extension profile identifier
    pub profile: u16,
    /// Extension data
    pub data: Bytes,
}

/// Complete RTP packet
#[derive(Debug, Clone)]
pub struct RtpPacket {
    /// RTP header
    pub header: RtpHeader,
    /// Payload data
    pub payload: Bytes,
}

impl RtpHeader {
    /// Minimum RTP header size (12 bytes)
    pub const MIN_SIZE: usize = 12;

    /// Parse RTP header from bytes
    pub fn parse(mut data: &[u8]) -> MediaEngineResult<(Self, &[u8])> {
        if data.len() < Self::MIN_SIZE {
            return Err(MediaEngineError::RtpParseError(
                format!("RTP header too short: {} bytes", data.len())
            ));
        }

        // First byte: V(2) P(1) X(1) CC(4)
        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x03;
        if version != 2 {
            return Err(MediaEngineError::RtpParseError(
                format!("Invalid RTP version: {}", version)
            ));
        }
        let padding = (first_byte & 0x20) != 0;
        let extension = (first_byte & 0x10) != 0;
        let csrc_count = first_byte & 0x0F;

        // Second byte: M(1) PT(7)
        let second_byte = data[1];
        let marker = (second_byte & 0x80) != 0;
        let payload_type = second_byte & 0x7F;

        // Sequence number (16 bits)
        let sequence_number = u16::from_be_bytes([data[2], data[3]]);

        // Timestamp (32 bits)
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        // SSRC (32 bits)
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        // Move past fixed header
        data = &data[Self::MIN_SIZE..];

        // CSRC list (4 bytes each)
        let mut csrc = Vec::with_capacity(csrc_count as usize);
        for _ in 0..csrc_count {
            if data.len() < 4 {
                return Err(MediaEngineError::RtpParseError(
                    "Incomplete CSRC list".to_string()
                ));
            }
            let csrc_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            csrc.push(csrc_id);
            data = &data[4..];
        }

        // Extension header (optional)
        let extension_header = if extension {
            if data.len() < 4 {
                return Err(MediaEngineError::RtpParseError(
                    "Incomplete extension header".to_string()
                ));
            }
            let profile = u16::from_be_bytes([data[0], data[1]]);
            let length = u16::from_be_bytes([data[2], data[3]]) as usize;
            let ext_data_len = length * 4; // Length is in 32-bit words

            if data.len() < 4 + ext_data_len {
                return Err(MediaEngineError::RtpParseError(
                    "Incomplete extension data".to_string()
                ));
            }

            let ext_data = Bytes::copy_from_slice(&data[4..4 + ext_data_len]);
            data = &data[4 + ext_data_len..];

            Some(ExtensionHeader {
                profile,
                data: ext_data,
            })
        } else {
            None
        };

        let header = RtpHeader {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc,
            extension_header,
        };

        Ok((header, data))
    }

    /// Serialize RTP header to bytes
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.size());

        // First byte: V(2) P(1) X(1) CC(4)
        let mut first_byte = (self.version & 0x03) << 6;
        if self.padding {
            first_byte |= 0x20;
        }
        if self.extension {
            first_byte |= 0x10;
        }
        first_byte |= self.csrc_count & 0x0F;
        buf.put_u8(first_byte);

        // Second byte: M(1) PT(7)
        let mut second_byte = self.payload_type & 0x7F;
        if self.marker {
            second_byte |= 0x80;
        }
        buf.put_u8(second_byte);

        // Sequence number
        buf.put_u16(self.sequence_number);

        // Timestamp
        buf.put_u32(self.timestamp);

        // SSRC
        buf.put_u32(self.ssrc);

        // CSRC list
        for &csrc_id in &self.csrc {
            buf.put_u32(csrc_id);
        }

        // Extension header
        if let Some(ref ext) = self.extension_header {
            buf.put_u16(ext.profile);
            let length = (ext.data.len() + 3) / 4; // Round up to 32-bit words
            buf.put_u16(length as u16);
            buf.put_slice(&ext.data);
            // Pad to 32-bit boundary if needed
            let padding = (4 - (ext.data.len() % 4)) % 4;
            for _ in 0..padding {
                buf.put_u8(0);
            }
        }

        buf
    }

    /// Calculate header size in bytes
    pub fn size(&self) -> usize {
        let mut size = Self::MIN_SIZE;
        size += self.csrc.len() * 4;
        if let Some(ref ext) = self.extension_header {
            size += 4; // Profile + length
            size += ext.data.len();
            // Pad to 32-bit boundary
            size += (4 - (ext.data.len() % 4)) % 4;
        }
        size
    }
}

impl RtpPacket {
    /// Parse RTP packet from bytes
    pub fn parse(data: &[u8]) -> MediaEngineResult<Self> {
        let (header, payload_data) = RtpHeader::parse(data)?;

        // Handle padding if present
        let payload = if header.padding {
            if payload_data.is_empty() {
                return Err(MediaEngineError::RtpParseError(
                    "Packet has padding flag but no payload".to_string()
                ));
            }
            let padding_len = payload_data[payload_data.len() - 1] as usize;
            if padding_len > payload_data.len() {
                return Err(MediaEngineError::RtpParseError(
                    format!("Invalid padding length: {}", padding_len)
                ));
            }
            Bytes::copy_from_slice(&payload_data[..payload_data.len() - padding_len])
        } else {
            Bytes::copy_from_slice(payload_data)
        };

        Ok(RtpPacket { header, payload })
    }

    /// Serialize RTP packet to bytes
    pub fn serialize(&self) -> BytesMut {
        let mut buf = self.header.serialize();
        buf.put_slice(&self.payload);
        buf
    }

    /// Check if packet is audio
    pub fn is_audio(&self) -> bool {
        // Payload types 0-23 are static (audio)
        // For dynamic payloads (96-127), we'd need to check SDP
        // For now, assume payload types < 96 are audio
        self.header.payload_type < 96
    }

    /// Check if packet is video
    pub fn is_video(&self) -> bool {
        // Payload types 96-127 are typically video (dynamic)
        // For now, assume payload types >= 96 are video
        self.header.payload_type >= 96
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_header_parse_minimal() {
        // Minimal RTP header (12 bytes)
        let data = [
            0x80, 0x60, // V=2, P=0, X=0, CC=0, M=0, PT=96
            0x00, 0x01, // Sequence number = 1
            0x00, 0x00, 0x00, 0x01, // Timestamp = 1
            0x00, 0x00, 0x00, 0x01, // SSRC = 1
        ];

        let (header, remaining) = RtpHeader::parse(&data).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.padding, false);
        assert_eq!(header.extension, false);
        assert_eq!(header.csrc_count, 0);
        assert_eq!(header.marker, false);
        assert_eq!(header.payload_type, 96);
        assert_eq!(header.sequence_number, 1);
        assert_eq!(header.timestamp, 1);
        assert_eq!(header.ssrc, 1);
        assert_eq!(header.csrc.len(), 0);
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_rtp_header_serialize() {
        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 96,
            sequence_number: 1,
            timestamp: 1,
            ssrc: 1,
            csrc: vec![],
            extension_header: None,
        };

        let serialized = header.serialize();
        let (parsed, _) = RtpHeader::parse(&serialized).unwrap();

        assert_eq!(header, parsed);
    }

    #[test]
    fn test_rtp_packet_parse() {
        let header_data = [
            0x80, 0x60, // V=2, P=0, X=0, CC=0, M=0, PT=96
            0x00, 0x01, // Sequence number = 1
            0x00, 0x00, 0x00, 0x01, // Timestamp = 1
            0x00, 0x00, 0x00, 0x01, // SSRC = 1
        ];
        let payload_data = b"test payload";

        let mut packet_data = Vec::from(header_data);
        packet_data.extend_from_slice(payload_data);

        let packet = RtpPacket::parse(&packet_data).unwrap();
        assert_eq!(packet.header.sequence_number, 1);
        assert_eq!(packet.payload, Bytes::from("test payload"));
    }

    #[test]
    fn test_rtp_packet_serialize() {
        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 96,
            sequence_number: 1,
            timestamp: 1,
            ssrc: 1,
            csrc: vec![],
            extension_header: None,
        };

        let packet = RtpPacket {
            header,
            payload: Bytes::from("test payload"),
        };

        let serialized = packet.serialize();
        let parsed = RtpPacket::parse(&serialized).unwrap();

        assert_eq!(packet.header, parsed.header);
        assert_eq!(packet.payload, parsed.payload);
    }
}

