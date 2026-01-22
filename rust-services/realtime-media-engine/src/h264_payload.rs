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

//! RFC 6184 - RTP Payload Format for H.264 Video
//!
//! Implements proper H.264 NAL unit parsing and packetization according to RFC 6184.
//! This is essential for H.264 video processing chains.
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

/// H.264 NAL Unit Type (from RFC 6184)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NalUnitType {
    /// Unspecified
    Unspecified = 0,
    /// Non-IDR coded slice
    NonIdrSlice = 1,
    /// Coded slice data partition A
    DataPartitionA = 2,
    /// Coded slice data partition B
    DataPartitionB = 3,
    /// Coded slice data partition C
    DataPartitionC = 4,
    /// IDR (Instantaneous Decoder Refresh) coded slice
    IdrSlice = 5,
    /// SEI (Supplemental Enhancement Information)
    Sei = 6,
    /// SPS (Sequence Parameter Set)
    Sps = 7,
    /// PPS (Picture Parameter Set)
    Pps = 8,
    /// Access unit delimiter
    AccessUnitDelimiter = 9,
    /// End of sequence
    EndOfSequence = 10,
    /// End of stream
    EndOfStream = 11,
    /// Filler data
    Filler = 12,
    /// SPS extension
    SpsExtension = 13,
    /// Prefix NAL unit
    PrefixNal = 14,
    /// Subset SPS
    SubsetSps = 15,
    /// Reserved
    Reserved = 16,
}

impl NalUnitType {
    /// Parse NAL unit type from byte
    pub fn from_byte(byte: u8) -> Self {
        match byte & 0x1F {
            0 => NalUnitType::Unspecified,
            1 => NalUnitType::NonIdrSlice,
            2 => NalUnitType::DataPartitionA,
            3 => NalUnitType::DataPartitionB,
            4 => NalUnitType::DataPartitionC,
            5 => NalUnitType::IdrSlice,
            6 => NalUnitType::Sei,
            7 => NalUnitType::Sps,
            8 => NalUnitType::Pps,
            9 => NalUnitType::AccessUnitDelimiter,
            10 => NalUnitType::EndOfSequence,
            11 => NalUnitType::EndOfStream,
            12 => NalUnitType::Filler,
            13 => NalUnitType::SpsExtension,
            14 => NalUnitType::PrefixNal,
            15 => NalUnitType::SubsetSps,
            _ => NalUnitType::Reserved,
        }
    }

    /// Check if this is a keyframe (IDR or SPS/PPS)
    pub fn is_keyframe(&self) -> bool {
        matches!(
            self,
            NalUnitType::IdrSlice | NalUnitType::Sps | NalUnitType::Pps
        )
    }
}

/// H.264 NAL Unit
#[derive(Debug, Clone)]
pub struct NalUnit {
    /// NAL unit type
    pub nal_type: NalUnitType,
    /// NAL unit data (without start code)
    pub data: Bytes,
    /// Forbidden zero bit (should be 0)
    pub forbidden_zero_bit: bool,
    /// NRI (NAL Reference IDC) - 2 bits
    pub nri: u8,
}

impl NalUnit {
    /// Parse NAL unit from bytes (with or without start code)
    pub fn parse(data: &[u8]) -> MediaEngineResult<Self> {
        if data.is_empty() {
            return Err(MediaEngineError::CodecError(
                "Empty NAL unit data".to_string(),
            ));
        }

        let mut offset = 0;

        // Skip start code (0x00000001 or 0x000001)
        if data.len() >= 4 && &data[0..4] == &[0x00, 0x00, 0x00, 0x01] {
            offset = 4;
        } else if data.len() >= 3 && &data[0..3] == &[0x00, 0x00, 0x01] {
            offset = 3;
        }

        if offset >= data.len() {
            return Err(MediaEngineError::CodecError(
                "NAL unit has only start code".to_string(),
            ));
        }

        // Parse NAL unit header (first byte)
        let header_byte = data[offset];
        let forbidden_zero_bit = (header_byte & 0x80) != 0;
        let nri = (header_byte >> 5) & 0x03;
        let nal_type_byte = header_byte & 0x1F;
        let nal_type = NalUnitType::from_byte(nal_type_byte);

        // Extract NAL unit data (without start code, with header)
        let nal_data = Bytes::copy_from_slice(&data[offset..]);

        Ok(NalUnit {
            nal_type,
            data: nal_data,
            forbidden_zero_bit,
            nri,
        })
    }

    /// Get NAL unit size
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// H.264 RTP Payload Format Handler (RFC 6184)
pub struct H264PayloadHandler {
    /// Maximum RTP payload size (MTU - RTP header - IP/UDP headers)
    max_payload_size: usize,
    /// Sequence number for fragmentation
    pub sequence_number: u16,
}

impl H264PayloadHandler {
    /// Create a new H.264 payload handler
    pub fn new(max_payload_size: usize) -> Self {
        Self {
            max_payload_size,
            sequence_number: 0,
        }
    }

    /// Packetize H.264 NAL unit into RTP packets (RFC 6184)
    ///
    /// Single NAL Unit Mode: If NAL unit fits in one packet, use single NAL unit mode.
    /// Fragmentation Unit (FU) Mode: If NAL unit is too large, fragment it.
    pub fn packetize_nal_unit(
        &mut self,
        nal_unit: &NalUnit,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
    ) -> MediaEngineResult<Vec<RtpPacket>> {
        let nal_size = nal_unit.size();

        // Single NAL Unit Mode (RFC 6184 Section 5.6)
        if nal_size <= self.max_payload_size {
            return Ok(vec![self.create_single_nal_packet(
                nal_unit,
                timestamp,
                ssrc,
                payload_type,
            )?]);
        }

        // Fragmentation Unit (FU) Mode (RFC 6184 Section 5.8)
        self.create_fragmentation_units(nal_unit, timestamp, ssrc, payload_type)
    }

    /// Create single NAL unit packet (RFC 6184 Section 5.6)
    fn create_single_nal_packet(
        &mut self,
        nal_unit: &NalUnit,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
    ) -> MediaEngineResult<RtpPacket> {
        use crate::rtp_handler::RtpHeader;

        let marker = nal_unit.nal_type.is_keyframe();

        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker,
            payload_type,
            sequence_number: self.sequence_number,
            timestamp,
            ssrc,
            csrc: vec![],
            extension_header: None,
        };

        self.sequence_number = self.sequence_number.wrapping_add(1);

        Ok(RtpPacket {
            header,
            payload: nal_unit.data.clone(),
        })
    }

    /// Create fragmentation units (RFC 6184 Section 5.8)
    fn create_fragmentation_units(
        &mut self,
        nal_unit: &NalUnit,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
    ) -> MediaEngineResult<Vec<RtpPacket>> {
        use crate::rtp_handler::RtpHeader;

        let nal_data = &nal_unit.data;
        let nal_header = nal_data[0];

        // FU-A payload size: max_payload_size - 2 (for FU indicator + FU header)
        let fu_payload_size = self.max_payload_size - 2;
        let num_fragments = (nal_data.len() + fu_payload_size - 1) / fu_payload_size;

        let mut packets = Vec::with_capacity(num_fragments);
        let mut offset = 1; // Skip NAL header byte

        for fragment_index in 0..num_fragments {
            let is_start = fragment_index == 0;
            let is_end = fragment_index == num_fragments - 1;
            let remaining = nal_data.len() - offset;
            let fragment_size = remaining.min(fu_payload_size);

            // FU indicator (RFC 6184 Section 5.8)
            // F(1) + NRI(2) + Type(5) = 28 (FU-A)
            let fu_indicator = (nal_header & 0x60) | 28; // Preserve F and NRI, set type to 28

            // FU header (RFC 6184 Section 5.8)
            let mut fu_header = nal_header & 0x1F; // NAL unit type
            if is_start {
                fu_header |= 0x80; // S bit
            }
            if is_end {
                fu_header |= 0x40; // E bit
            }

            // Build payload: FU indicator + FU header + fragment data
            let mut payload = BytesMut::with_capacity(2 + fragment_size);
            payload.put_u8(fu_indicator);
            payload.put_u8(fu_header);
            payload.put_slice(&nal_data[offset..offset + fragment_size]);

            let header = RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: is_end && nal_unit.nal_type.is_keyframe(), // Mark last fragment of keyframe
                payload_type,
                sequence_number: self.sequence_number,
                timestamp,
                ssrc,
                csrc: vec![],
                extension_header: None,
            };

            self.sequence_number = self.sequence_number.wrapping_add(1);

            packets.push(RtpPacket {
                header,
                payload: payload.freeze(),
            });

            offset += fragment_size;
        }

        Ok(packets)
    }

    /// Depacketize RTP packets back to NAL units (RFC 6184)
    pub fn depacketize(&self, packets: &[RtpPacket]) -> MediaEngineResult<Vec<NalUnit>> {
        let mut nal_units = Vec::new();
        let mut fu_buffer: Option<(NalUnitType, BytesMut)> = None;

        for packet in packets {
            if packet.payload.is_empty() {
                continue;
            }

            let payload = &packet.payload;
            let first_byte = payload[0];

            // Check if this is a fragmentation unit (type 28 or 29)
            let nal_type = first_byte & 0x1F;
            if nal_type == 28 || nal_type == 29 {
                // Fragmentation Unit (FU-A or FU-B)
                if payload.len() < 2 {
                    return Err(MediaEngineError::CodecError(
                        "FU packet too short".to_string(),
                    ));
                }

                let fu_header = payload[1];
                let is_start = (fu_header & 0x80) != 0;
                let is_end = (fu_header & 0x40) != 0;
                let nal_unit_type_byte = fu_header & 0x1F;

                if is_start {
                    // Start of new FU
                    let nal_type = NalUnitType::from_byte(nal_unit_type_byte);
                    let nri = (first_byte >> 5) & 0x03;
                    let forbidden_zero_bit = (first_byte & 0x80) != 0;

                    // Reconstruct NAL header
                    let mut nal_header = BytesMut::with_capacity(1);
                    nal_header.put_u8(
                        (if forbidden_zero_bit { 0x80 } else { 0 })
                            | (nri << 5)
                            | nal_unit_type_byte,
                    );

                    let mut data = BytesMut::new();
                    data.put_slice(&nal_header);
                    data.put_slice(&payload[2..]); // Skip FU indicator and header

                    fu_buffer = Some((nal_type, data));
                } else if let Some((ref nal_type, ref mut buffer)) = fu_buffer {
                    // Continuation of FU
                    buffer.put_slice(&payload[2..]);

                    if is_end {
                        // End of FU - create complete NAL unit
                        let complete_data = buffer.split().freeze();
                        let header_byte = complete_data[0];
                        let nal_unit = NalUnit {
                            nal_type: *nal_type,
                            data: complete_data,
                            forbidden_zero_bit: (header_byte & 0x80) != 0,
                            nri: (header_byte >> 5) & 0x03,
                        };
                        nal_units.push(nal_unit);
                        fu_buffer = None;
                    }
                } else {
                    return Err(MediaEngineError::CodecError(
                        "FU continuation without start".to_string(),
                    ));
                }
            } else {
                // Single NAL Unit Mode
                let nal_unit = NalUnit::parse(payload)?;
                nal_units.push(nal_unit);
            }
        }

        Ok(nal_units)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nal_unit_parse() {
        // SPS NAL unit (type 7)
        let sps_data = vec![0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x00, 0x1e, 0x95];
        let nal = NalUnit::parse(&sps_data).unwrap();
        assert_eq!(nal.nal_type, NalUnitType::Sps);
        assert!(!nal.forbidden_zero_bit);
    }

    #[test]
    fn test_single_nal_packetization() {
        let mut handler = H264PayloadHandler::new(1200);
        let nal_data = vec![0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x00, 0x10];
        let nal = NalUnit::parse(&nal_data).unwrap();

        let packets = handler
            .packetize_nal_unit(&nal, 1000, 12345, 96)
            .unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].payload.len(), nal.size());
    }

    #[test]
    fn test_fragmentation() {
        let mut handler = H264PayloadHandler::new(100); // Small MTU to force fragmentation
        let mut large_nal = vec![0x00, 0x00, 0x00, 0x01, 0x65];
        large_nal.extend(vec![0x88; 200]); // Large NAL unit
        let nal = NalUnit::parse(&large_nal).unwrap();

        let packets = handler
            .packetize_nal_unit(&nal, 1000, 12345, 96)
            .unwrap();
        assert!(packets.len() > 1); // Should be fragmented
    }
}

