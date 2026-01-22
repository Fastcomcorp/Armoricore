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

//! Protocol Bridge for WebRTC ↔ ArcRTC Interoperability
//!
//! Converts between WebRTC (SDP/ICE) and ArcRTC (ArcSignaling/ArcRTP) protocols
//! to enable interoperability between browser and native clients.
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
use crate::arcsignaling::{
    ArcSignalingMessage, ConnectRequest, ConnectAck,
    PeerCapabilities,
};
use crate::arcrtp_handler::{ArcRtpPacket, ArcRtpQuality, ArcRtpPriority};
use crate::rtp_handler::RtpPacket;
use uuid::Uuid;

/// SDP (Session Description Protocol) representation
#[derive(Debug, Clone)]
pub struct Sdp {
    /// SDP version
    pub version: String,
    /// Origin
    pub origin: String,
    /// Session name
    pub session_name: String,
    /// Media descriptions
    pub media_descriptions: Vec<MediaDescription>,
    /// Attributes
    pub attributes: Vec<SdpAttribute>,
}

/// Media description in SDP
#[derive(Debug, Clone)]
pub struct MediaDescription {
    /// Media type (audio, video)
    pub media_type: String,
    /// Port
    pub port: u16,
    /// Protocol (RTP/AVP, etc.)
    pub protocol: String,
    /// Payload types
    pub payload_types: Vec<u8>,
    /// Attributes
    pub attributes: Vec<SdpAttribute>,
}

/// SDP attribute
#[derive(Debug, Clone)]
pub struct SdpAttribute {
    /// Attribute name
    pub name: String,
    /// Attribute value
    pub value: Option<String>,
}

/// ICE candidate
#[derive(Debug, Clone)]
pub struct IceCandidate {
    /// Foundation
    pub foundation: String,
    /// Component ID
    pub component: u32,
    /// Transport protocol
    pub transport: String,
    /// Priority
    pub priority: u64,
    /// Candidate address
    pub address: String,
    /// Candidate port
    pub port: u16,
    /// Candidate type (host, srflx, relay)
    pub candidate_type: String,
    /// Related address (for relay)
    pub related_address: Option<String>,
    /// Related port (for relay)
    pub related_port: Option<u16>,
}

/// Protocol bridge
pub struct ProtocolBridge;

impl ProtocolBridge {
    /// Convert SDP offer to ArcSignaling CONNECT request
    pub fn sdp_to_arcsignaling_connect(sdp: &Sdp, session_id: Uuid, peer_id: Uuid) -> MediaEngineResult<ArcSignalingMessage> {
        // Extract capabilities from SDP
        let mut audio_codecs = Vec::new();
        let mut video_codecs = Vec::new();
        let mut resolutions = Vec::new();
        let mut max_bitrate = 0u32;

        for media_desc in &sdp.media_descriptions {
            match media_desc.media_type.as_str() {
                "audio" => {
                    // Extract audio codecs from SDP
                    // Common codecs: opus, PCMU, PCMA, G722
                    for &pt in &media_desc.payload_types {
                        let codec = Self::payload_type_to_codec(pt, "audio")?;
                        if !audio_codecs.contains(&codec) {
                            audio_codecs.push(codec);
                        }
                    }
                }
                "video" => {
                    // Extract video codecs from SDP
                    // Common codecs: VP8, VP9, H264, AV1
                    for &pt in &media_desc.payload_types {
                        let codec = Self::payload_type_to_codec(pt, "video")?;
                        if !video_codecs.contains(&codec) {
                            video_codecs.push(codec);
                        }
                    }
                }
                _ => {}
            }
        }

        // Extract resolution from SDP attributes
        for attr in &sdp.attributes {
            if attr.name == "imageattr" || attr.name == "fmtp" {
                // Parse resolution from attribute
                // Simplified - in production would parse actual SDP format
                if let Some(value) = &attr.value {
                    if value.contains("1920") {
                        resolutions.push("1080p".to_string());
                    } else if value.contains("1280") {
                        resolutions.push("720p".to_string());
                    }
                }
            }
        }

        // Default capabilities if not found
        if audio_codecs.is_empty() {
            audio_codecs.push("opus".to_string());
        }
        if video_codecs.is_empty() {
            video_codecs.push("h264".to_string());
            video_codecs.push("vp9".to_string());
        }
        if resolutions.is_empty() {
            resolutions.push("720p".to_string());
            resolutions.push("1080p".to_string());
        }
        if max_bitrate == 0 {
            max_bitrate = 5_000_000; // 5 Mbps default
        }

        let capabilities = PeerCapabilities {
            audio_codecs,
            video_codecs,
            resolutions,
            max_bitrate,
            encryption_supported: true, // Assume SRTP support
        };

        Ok(ArcSignalingMessage::Connect(ConnectRequest {
            version: "1.0".to_string(),
            session_id,
            peer_id,
            capabilities,
            relay_servers: None, // Would extract from ICE candidates
        }))
    }

    /// Convert ArcSignaling CONNECT_ACK to SDP answer
    pub fn arcsignaling_ack_to_sdp(ack: &ConnectAck, session_id: Uuid) -> MediaEngineResult<Sdp> {
        let mut media_descriptions = Vec::new();

        // Create audio media description
        if ack.capabilities.audio_codecs.contains(&"opus".to_string()) {
            media_descriptions.push(MediaDescription {
                media_type: "audio".to_string(),
                port: 50000, // Default port
                protocol: "RTP/SAVPF".to_string(), // Secure RTP with feedback
                payload_types: vec![111], // Opus payload type
                attributes: vec![
                    SdpAttribute {
                        name: "rtpmap".to_string(),
                        value: Some("111 opus/48000/2".to_string()),
                    },
                    SdpAttribute {
                        name: "fmtp".to_string(),
                        value: Some("111 minptime=10;useinbandfec=1".to_string()),
                    },
                ],
            });
        }

        // Create video media description
        if let Some(video_codec) = ack.capabilities.video_codecs.first() {
            let payload_type = match video_codec.as_str() {
                "h264" => 96,
                "vp9" => 98,
                "vp8" => 97,
                _ => 96,
            };

            media_descriptions.push(MediaDescription {
                media_type: "video".to_string(),
                port: 50002, // Default port
                protocol: "RTP/SAVPF".to_string(),
                payload_types: vec![payload_type],
                attributes: vec![
                    SdpAttribute {
                        name: "rtpmap".to_string(),
                        value: Some(format!("{} {}/90000", payload_type, video_codec)),
                    },
                ],
            });
        }

        let mut attributes = vec![
            SdpAttribute {
                name: "fingerprint".to_string(),
                value: Some("sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00".to_string()),
            },
            SdpAttribute {
                name: "setup".to_string(),
                value: Some("actpass".to_string()),
            },
        ];

        if ack.connection_params.encryption_enabled {
            attributes.push(SdpAttribute {
                name: "crypto".to_string(),
                value: Some("1 AES_128_GCM_128 inline:...".to_string()),
            });
        }

        Ok(Sdp {
            version: "0".to_string(),
            origin: format!("- {} {} IN IP4 127.0.0.1", session_id, 1),
            session_name: "-".to_string(),
            media_descriptions,
            attributes,
        })
    }

    /// Convert RTP packet to ArcRTP packet
    pub fn rtp_to_arcrtp(
        rtp: &RtpPacket,
        quality: ArcRtpQuality,
        priority: ArcRtpPriority,
    ) -> ArcRtpPacket {
        ArcRtpPacket::from_rtp(rtp, quality, priority)
    }

    /// Convert ArcRTP packet to RTP packet
    pub fn arcrtp_to_rtp(arcrtp: &ArcRtpPacket) -> RtpPacket {
        arcrtp.to_rtp()
    }

    /// Convert ICE candidate to ArcSignaling relay server info
    pub fn ice_candidate_to_relay_server(candidate: &IceCandidate) -> Option<crate::arcsignaling::RelayServer> {
        if candidate.candidate_type == "relay" {
            Some(crate::arcsignaling::RelayServer {
                id: candidate.foundation.clone(),
                address: candidate.address.clone(),
                port: candidate.port,
                priority: (candidate.priority >> 24) as u8, // Extract priority byte
            })
        } else {
            None
        }
    }

    /// Convert ArcSignaling relay server to ICE candidate
    pub fn relay_server_to_ice_candidate(relay: &crate::arcsignaling::RelayServer) -> IceCandidate {
        IceCandidate {
            foundation: relay.id.clone(),
            component: 1,
            transport: "udp".to_string(),
            priority: (relay.priority as u64) << 24,
            address: relay.address.clone(),
            port: relay.port,
            candidate_type: "relay".to_string(),
            related_address: None,
            related_port: None,
        }
    }

    /// Parse SDP from string
    pub fn parse_sdp(sdp_string: &str) -> MediaEngineResult<Sdp> {
        let mut sdp = Sdp {
            version: "0".to_string(),
            origin: String::new(),
            session_name: "-".to_string(),
            media_descriptions: Vec::new(),
            attributes: Vec::new(),
        };

        let mut current_media: Option<MediaDescription> = None;

        for line in sdp_string.lines() {
            if line.is_empty() {
                continue;
            }

            if line.len() < 2 {
                continue;
            }

            let key = &line[0..1];
            let value = &line[2..];

            match key {
                "v" => sdp.version = value.to_string(),
                "o" => sdp.origin = value.to_string(),
                "s" => sdp.session_name = value.to_string(),
                "m" => {
                    // Media description
                    if let Some(media) = current_media.take() {
                        sdp.media_descriptions.push(media);
                    }

                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if parts.len() >= 3 {
                        current_media = Some(MediaDescription {
                            media_type: parts[0].to_string(),
                            port: parts[1].parse().unwrap_or(0),
                            protocol: parts[2].to_string(),
                            payload_types: parts[3..].iter()
                                .filter_map(|s| s.parse().ok())
                                .collect(),
                            attributes: Vec::new(),
                        });
                    }
                }
                "a" => {
                    // Attribute
                    let attr = if let Some(colon_pos) = value.find(':') {
                        SdpAttribute {
                            name: value[..colon_pos].to_string(),
                            value: Some(value[colon_pos + 1..].to_string()),
                        }
                    } else {
                        SdpAttribute {
                            name: value.to_string(),
                            value: None,
                        }
                    };

                    if let Some(ref mut media) = current_media {
                        media.attributes.push(attr);
                    } else {
                        sdp.attributes.push(attr);
                    }
                }
                _ => {}
            }
        }

        if let Some(media) = current_media {
            sdp.media_descriptions.push(media);
        }

        Ok(sdp)
    }

    /// Serialize SDP to string
    pub fn serialize_sdp(sdp: &Sdp) -> String {
        let mut lines = Vec::new();

        lines.push(format!("v={}", sdp.version));
        lines.push(format!("o={}", sdp.origin));
        lines.push(format!("s={}", sdp.session_name));

        // Session-level attributes
        for attr in &sdp.attributes {
            if let Some(ref value) = attr.value {
                lines.push(format!("a={}:{}", attr.name, value));
            } else {
                lines.push(format!("a={}", attr.name));
            }
        }

        // Media descriptions
        for media in &sdp.media_descriptions {
            let payload_types: Vec<String> = media.payload_types.iter()
                .map(|pt| pt.to_string())
                .collect();
            lines.push(format!(
                "m={} {} {} {}",
                media.media_type,
                media.port,
                media.protocol,
                payload_types.join(" ")
            ));

            for attr in &media.attributes {
                if let Some(ref value) = attr.value {
                    lines.push(format!("a={}:{}", attr.name, value));
                } else {
                    lines.push(format!("a={}", attr.name));
                }
            }
        }

        lines.join("\r\n") + "\r\n"
    }

    /// Convert payload type to codec name
    fn payload_type_to_codec(payload_type: u8, media_type: &str) -> MediaEngineResult<String> {
        match (media_type, payload_type) {
            ("audio", 0) => Ok("PCMU".to_string()),
            ("audio", 8) => Ok("PCMA".to_string()),
            ("audio", 9) => Ok("G722".to_string()),
            ("audio", 111) => Ok("opus".to_string()),
            ("audio", 96) => Ok("opus".to_string()), // Dynamic
            ("video", 96) => Ok("h264".to_string()), // Dynamic
            ("video", 97) => Ok("vp8".to_string()),
            ("video", 98) => Ok("vp9".to_string()),
            ("video", 99) => Ok("av1".to_string()),
            _ => Err(MediaEngineError::ConfigError(
                format!("Unknown payload type {} for {}", payload_type, media_type)
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sdp() {
        let sdp_string = "v=0\r\n\
o=- 123456789 123456789 IN IP4 127.0.0.1\r\n\
s=-\r\n\
m=audio 50000 RTP/SAVPF 111\r\n\
a=rtpmap:111 opus/48000/2\r\n\
m=video 50002 RTP/SAVPF 96\r\n\
a=rtpmap:96 H264/90000\r\n";

        let sdp = ProtocolBridge::parse_sdp(sdp_string).unwrap();
        assert_eq!(sdp.version, "0");
        assert_eq!(sdp.media_descriptions.len(), 2);
    }

    #[test]
    fn test_rtp_to_arcrtp() {
        let rtp = RtpPacket {
            header: crate::rtp_handler::RtpHeader {
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
            },
            payload: bytes::Bytes::from("test"),
        };

        let arcrtp = ProtocolBridge::rtp_to_arcrtp(
            &rtp,
            ArcRtpQuality::Good,
            ArcRtpPriority::High,
        );

        assert_eq!(arcrtp.header.base.sequence_number, 1);
        assert_eq!(arcrtp.header.quality, ArcRtpQuality::Good);
        assert_eq!(arcrtp.header.priority, ArcRtpPriority::High);
    }

    #[test]
    fn test_arcrtp_to_rtp() {
        let base_header = crate::rtp_handler::RtpHeader {
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

        let arcrtp = ArcRtpPacket::new(
            base_header.clone(),
            ArcRtpQuality::Excellent,
            ArcRtpPriority::Critical,
            bytes::Bytes::from("test"),
        );

        let rtp = ProtocolBridge::arcrtp_to_rtp(&arcrtp);
        assert_eq!(rtp.header.sequence_number, base_header.sequence_number);
        assert_eq!(rtp.payload, arcrtp.payload);
    }
}

