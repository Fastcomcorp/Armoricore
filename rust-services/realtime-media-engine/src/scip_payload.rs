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

//! RFC 9607 - RTP Payload Format for the SCIP Codec
//!
//! Implements RTP payload format for SCIP (Secure Communication Interoperability Protocol).
//! SCIP is a secure, low-latency codec ideal for encrypted media in classified workflows.
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
use bytes::{BufMut, Bytes, BytesMut};

/// SCIP Packet Type (from RFC 9607)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScipPacketType {
    /// Audio frame
    Audio = 0,
    /// Video frame
    Video = 1,
    /// Control frame
    Control = 2,
    /// FEC frame
    Fec = 3,
}

impl ScipPacketType {
    /// Parse from byte
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte & 0x03 {
            0 => Some(ScipPacketType::Audio),
            1 => Some(ScipPacketType::Video),
            2 => Some(ScipPacketType::Control),
            3 => Some(ScipPacketType::Fec),
            _ => None,
        }
    }
}

/// SCIP Packet (RFC 9607)
#[derive(Debug, Clone)]
pub struct ScipPacket {
    /// Packet type
    pub packet_type: ScipPacketType,
    /// Sequence number (14 bits)
    pub sequence_number: u16,
    /// Timestamp (32 bits)
    pub timestamp: u32,
    /// Payload data (encrypted)
    pub payload: Bytes,
    /// Frame number (for video)
    pub frame_number: Option<u32>,
    /// Keyframe indicator
    pub is_keyframe: bool,
}

impl ScipPacket {
    /// Parse SCIP packet from bytes
    pub fn parse(data: &[u8]) -> MediaEngineResult<Self> {
        if data.len() < 6 {
            return Err(MediaEngineError::CodecError(
                "SCIP packet too short".to_string(),
            ));
        }

        // SCIP header format (RFC 9607):
        // Byte 0: Packet type (2 bits) + Reserved (6 bits)
        let packet_type_byte = data[0];
        let packet_type = ScipPacketType::from_byte(packet_type_byte).ok_or_else(|| {
            MediaEngineError::CodecError(format!("Invalid SCIP packet type: {}", packet_type_byte & 0x03))
        })?;

        // Bytes 1-2: Sequence number (14 bits, big-endian)
        let sequence_number = u16::from_be_bytes([data[1], data[2]]) & 0x3FFF;

        // Bytes 3-6: Timestamp (32 bits, big-endian)
        let timestamp = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);

        // Remaining bytes: Payload
        let payload = Bytes::copy_from_slice(&data[7..]);

        // For video packets, check if it's a keyframe (first byte of payload)
        let is_keyframe = if packet_type == ScipPacketType::Video && !payload.is_empty() {
            payload[0] & 0x80 != 0
        } else {
            false
        };

        // Frame number is embedded in payload for video (optional)
        let frame_number = if packet_type == ScipPacketType::Video && payload.len() >= 4 {
            Some(u32::from_be_bytes([
                payload[0] & 0x7F,
                payload[1],
                payload[2],
                payload[3],
            ]))
        } else {
            None
        };

        Ok(ScipPacket {
            packet_type,
            sequence_number,
            timestamp,
            payload,
            frame_number,
            is_keyframe,
        })
    }

    /// Serialize SCIP packet to bytes
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(7 + self.payload.len());
        
        // Byte 0: Packet type
        buf.put_u8(self.packet_type as u8);
        
        // Bytes 1-2: Sequence number (14 bits)
        buf.put_u16(self.sequence_number);
        
        // Bytes 3-6: Timestamp
        buf.put_u32(self.timestamp);
        
        // Payload
        buf.put_slice(&self.payload);
        
        buf
    }
}

/// SCIP RTP Payload Format Handler (RFC 9607)
pub struct ScipPayloadHandler {
    /// Sequence number
    sequence_number: u16,
}

impl ScipPayloadHandler {
    /// Create a new SCIP payload handler
    pub fn new() -> Self {
        Self {
            sequence_number: 0,
        }
    }

    /// Wrap SCIP packet in RTP packet
    pub fn wrap_in_rtp(
        &mut self,
        scip_packet: &ScipPacket,
        ssrc: u32,
        payload_type: u8,
    ) -> MediaEngineResult<RtpPacket> {
        use crate::rtp_handler::RtpHeader;

        let marker = scip_packet.is_keyframe && scip_packet.packet_type == ScipPacketType::Video;

        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker,
            payload_type,
            sequence_number: self.sequence_number,
            timestamp: scip_packet.timestamp,
            ssrc,
            csrc: vec![],
            extension_header: None,
        };

        self.sequence_number = self.sequence_number.wrapping_add(1);

        // RTP payload is the serialized SCIP packet
        let scip_data = scip_packet.serialize();

        Ok(RtpPacket {
            header,
            payload: scip_data.freeze(),
        })
    }

    /// Extract SCIP packet from RTP packet
    pub fn extract_from_rtp(&self, rtp_packet: &RtpPacket) -> MediaEngineResult<ScipPacket> {
        ScipPacket::parse(&rtp_packet.payload)
    }
}

impl Default for ScipPayloadHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scip_packet_parse() {
        let mut data = vec![0x00]; // Audio packet type
        data.extend_from_slice(&1234u16.to_be_bytes()); // Sequence number
        data.extend_from_slice(&5678u32.to_be_bytes()); // Timestamp
        data.extend_from_slice(b"audio payload");

        let packet = ScipPacket::parse(&data).unwrap();
        assert_eq!(packet.packet_type, ScipPacketType::Audio);
        assert_eq!(packet.sequence_number, 1234);
        assert_eq!(packet.timestamp, 5678);
    }

    #[test]
    fn test_scip_rtp_wrap() {
        let mut handler = ScipPayloadHandler::new();
        let scip_packet = ScipPacket {
            packet_type: ScipPacketType::Audio,
            sequence_number: 1,
            timestamp: 1000,
            payload: Bytes::from("test audio"),
            frame_number: None,
            is_keyframe: false,
        };

        let rtp = handler.wrap_in_rtp(&scip_packet, 12345, 97).unwrap();
        assert_eq!(rtp.header.timestamp, 1000);
    }
}

