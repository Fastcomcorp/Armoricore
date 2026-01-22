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

//! draft-ietf-avtcore-rtp-vvc - RTP Payload Format for Versatile Video Coding (VVC/H.266)
//!
//! Implements RTP payload format for VVC/H.266 codec.
//! Supports scalable 8K video with low overhead for future AI-enhanced processing.
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

/// VVC NAL Unit Type (from draft-ietf-avtcore-rtp-vvc)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VvcNalUnitType {
    /// VPS (Video Parameter Set)
    Vps = 32,
    /// SPS (Sequence Parameter Set)
    Sps = 33,
    /// PPS (Picture Parameter Set)
    Pps = 34,
    /// Prefix APS (Adaptation Parameter Set)
    PrefixAps = 35,
    /// Suffix APS
    SuffixAps = 36,
    /// PH (Picture Header)
    PictureHeader = 37,
    /// Access unit delimiter
    AccessUnitDelimiter = 38,
    /// End of sequence
    EndOfSequence = 39,
    /// End of bitstream
    EndOfBitstream = 40,
    /// Filler data
    Filler = 41,
    /// IDR (Instantaneous Decoder Refresh) with RADL
    IdrWithRadl = 19,
    /// IDR with NLF
    IdrWithNlf = 20,
    /// CRA (Clean Random Access)
    Cra = 21,
    /// GDR (Gradual Decoder Refresh)
    Gdr = 22,
    /// TRAIL (Trailing picture)
    Trail = 0,
    /// STSA (Step-wise Temporal Sub-layer Access)
    Stsa = 1,
    /// RADL (Reference Adaptive Decoder Refresh)
    Radl = 2,
    /// RASL (Random Access Skipped Leading)
    Rasl = 3,
}

impl VvcNalUnitType {
    /// Parse VVC NAL unit type from byte
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte & 0x3F {
            0 => Some(VvcNalUnitType::Trail),
            1 => Some(VvcNalUnitType::Stsa),
            2 => Some(VvcNalUnitType::Radl),
            3 => Some(VvcNalUnitType::Rasl),
            19 => Some(VvcNalUnitType::IdrWithRadl),
            20 => Some(VvcNalUnitType::IdrWithNlf),
            21 => Some(VvcNalUnitType::Cra),
            22 => Some(VvcNalUnitType::Gdr),
            32 => Some(VvcNalUnitType::Vps),
            33 => Some(VvcNalUnitType::Sps),
            34 => Some(VvcNalUnitType::Pps),
            35 => Some(VvcNalUnitType::PrefixAps),
            36 => Some(VvcNalUnitType::SuffixAps),
            37 => Some(VvcNalUnitType::PictureHeader),
            38 => Some(VvcNalUnitType::AccessUnitDelimiter),
            39 => Some(VvcNalUnitType::EndOfSequence),
            40 => Some(VvcNalUnitType::EndOfBitstream),
            41 => Some(VvcNalUnitType::Filler),
            _ => None,
        }
    }

    /// Check if this is a keyframe
    pub fn is_keyframe(&self) -> bool {
        matches!(
            self,
            VvcNalUnitType::IdrWithRadl
                | VvcNalUnitType::IdrWithNlf
                | VvcNalUnitType::Cra
                | VvcNalUnitType::Vps
                | VvcNalUnitType::Sps
                | VvcNalUnitType::Pps
        )
    }
}

/// VVC NAL Unit
#[derive(Debug, Clone)]
pub struct VvcNalUnit {
    /// NAL unit type
    pub nal_type: VvcNalUnitType,
    /// NAL unit data (without start code)
    pub data: Bytes,
    /// NAL unit header byte
    pub header_byte: u8,
}

impl VvcNalUnit {
    /// Parse VVC NAL unit from bytes
    pub fn parse(data: &[u8]) -> MediaEngineResult<Self> {
        if data.is_empty() {
            return Err(MediaEngineError::CodecError(
                "Empty VVC NAL unit data".to_string(),
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
                "VVC NAL unit has only start code".to_string(),
            ));
        }

        let header_byte = data[offset];
        let nal_type = VvcNalUnitType::from_byte(header_byte).ok_or_else(|| {
            MediaEngineError::CodecError(format!("Invalid VVC NAL unit type: {}", header_byte & 0x3F))
        })?;

        let nal_data = Bytes::copy_from_slice(&data[offset..]);

        Ok(VvcNalUnit {
            nal_type,
            data: nal_data,
            header_byte,
        })
    }

    /// Get NAL unit size
    pub fn size(&self) -> usize {
        self.data.len()
    }
}

/// VVC RTP Payload Format Handler (draft-ietf-avtcore-rtp-vvc)
pub struct VvcPayloadHandler {
    /// Maximum RTP payload size
    pub max_payload_size: usize,
    /// Sequence number for fragmentation
    pub sequence_number: u16,
}

impl VvcPayloadHandler {
    /// Create a new VVC payload handler
    pub fn new(max_payload_size: usize) -> Self {
        Self {
            max_payload_size,
            sequence_number: 0,
        }
    }

    /// Packetize VVC NAL unit into RTP packets
    ///
    /// Similar to H.264, supports single NAL unit mode and fragmentation.
    pub fn packetize_nal_unit(
        &mut self,
        nal_unit: &VvcNalUnit,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
    ) -> MediaEngineResult<Vec<RtpPacket>> {
        let nal_size = nal_unit.size();

        // Single NAL Unit Mode
        if nal_size <= self.max_payload_size {
            return Ok(vec![self.create_single_nal_packet(
                nal_unit,
                timestamp,
                ssrc,
                payload_type,
            )?]);
        }

        // Aggregation Packet or Fragmentation Unit Mode
        // For simplicity, we'll use fragmentation similar to H.264
        self.create_fragmentation_units(nal_unit, timestamp, ssrc, payload_type)
    }

    /// Create single NAL unit packet
    fn create_single_nal_packet(
        &mut self,
        nal_unit: &VvcNalUnit,
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

    /// Create fragmentation units for large NAL units
    fn create_fragmentation_units(
        &mut self,
        nal_unit: &VvcNalUnit,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
    ) -> MediaEngineResult<Vec<RtpPacket>> {
        use crate::rtp_handler::RtpHeader;

        let nal_data = &nal_unit.data;
        let fu_payload_size = self.max_payload_size - 2; // Reserve space for FU header
        let num_fragments = (nal_data.len() + fu_payload_size - 1) / fu_payload_size;

        let mut packets = Vec::with_capacity(num_fragments);
        let mut offset = 1; // Skip NAL header

        for fragment_index in 0..num_fragments {
            let is_start = fragment_index == 0;
            let is_end = fragment_index == num_fragments - 1;
            let remaining = nal_data.len() - offset;
            let fragment_size = remaining.min(fu_payload_size);

            // FU header (similar to H.264 but for VVC)
            let mut fu_header = nal_unit.header_byte & 0x3F; // NAL unit type (6 bits for VVC)
            if is_start {
                fu_header |= 0x80; // S bit
            }
            if is_end {
                fu_header |= 0x40; // E bit
            }

            let mut payload = BytesMut::with_capacity(2 + fragment_size);
            payload.put_u8(nal_unit.header_byte); // FU indicator (preserve header)
            payload.put_u8(fu_header);
            payload.put_slice(&nal_data[offset..offset + fragment_size]);

            let header = RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: is_end && nal_unit.nal_type.is_keyframe(),
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

    /// Depacketize RTP packets back to VVC NAL units
    pub fn depacketize(&self, packets: &[RtpPacket]) -> MediaEngineResult<Vec<VvcNalUnit>> {
        let mut nal_units = Vec::new();
        let mut fu_buffer: Option<(VvcNalUnitType, BytesMut)> = None;

        for packet in packets {
            if packet.payload.is_empty() {
                continue;
            }

            let payload = &packet.payload;
            let first_byte = payload[0];
            let nal_type_byte = first_byte & 0x3F;

            // Check if this is a fragmentation unit (type 50-51 for VVC)
            if nal_type_byte == 50 || nal_type_byte == 51 {
                if payload.len() < 2 {
                    return Err(MediaEngineError::CodecError(
                        "VVC FU packet too short".to_string(),
                    ));
                }

                let fu_header = payload[1];
                let is_start = (fu_header & 0x80) != 0;
                let is_end = (fu_header & 0x40) != 0;
                let nal_unit_type_byte = fu_header & 0x3F;

                if is_start {
                    let nal_type = VvcNalUnitType::from_byte(nal_unit_type_byte).ok_or_else(|| {
                        MediaEngineError::CodecError(format!("Invalid VVC NAL type: {}", nal_unit_type_byte))
                    })?;

                    let mut nal_header = BytesMut::with_capacity(1);
                    nal_header.put_u8(first_byte & 0xC0 | nal_unit_type_byte); // Preserve F and NRI

                    let mut data = BytesMut::new();
                    data.put_slice(&nal_header);
                    data.put_slice(&payload[2..]);

                    fu_buffer = Some((nal_type, data));
                } else if let Some((ref nal_type, ref mut buffer)) = fu_buffer {
                    buffer.put_slice(&payload[2..]);

                    if is_end {
                        let complete_data = buffer.split().freeze();
                        let header_byte = complete_data[0];
                        let nal_unit = VvcNalUnit {
                            nal_type: *nal_type,
                            data: complete_data,
                            header_byte,
                        };
                        nal_units.push(nal_unit);
                        fu_buffer = None;
                    }
                } else {
                    return Err(MediaEngineError::CodecError(
                        "VVC FU continuation without start".to_string(),
                    ));
                }
            } else {
                // Single NAL Unit Mode
                let nal_unit = VvcNalUnit::parse(payload)?;
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
    fn test_vvc_nal_unit_parse() {
        // VPS NAL unit (type 32)
        let vps_data = vec![0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0c, 0x01];
        let nal = VvcNalUnit::parse(&vps_data).unwrap();
        assert_eq!(nal.nal_type, VvcNalUnitType::Vps);
    }

    #[test]
    fn test_vvc_packetization() {
        let mut handler = VvcPayloadHandler::new(1200);
        let nal_data = vec![0x00, 0x00, 0x00, 0x01, 0x4c, 0x01, 0xff, 0xf0];
        let nal = VvcNalUnit::parse(&nal_data).unwrap();

        let packets = handler
            .packetize_nal_unit(&nal, 1000, 12345, 98)
            .unwrap();
        assert_eq!(packets.len(), 1);
    }
}

