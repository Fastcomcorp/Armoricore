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

//! SDP (Session Description Protocol) implementation
//!
//! Implements RFC 4566 SDP parsing and generation.
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

/// SDP session description (RFC 4566)
#[derive(Debug, Clone)]
pub struct SessionDescription {
    /// Protocol version (v=)
    pub version: u32,
    /// Origin (o=)
    pub origin: Origin,
    /// Session name (s=)
    pub session_name: String,
    /// Session information (i=)
    pub session_info: Option<String>,
    /// URI (u=)
    pub uri: Option<String>,
    /// Email addresses (e=)
    pub emails: Vec<String>,
    /// Phone numbers (p=)
    pub phones: Vec<String>,
    /// Connection data (c=)
    pub connection: Option<Connection>,
    /// Bandwidth information (b=)
    pub bandwidth: Vec<Bandwidth>,
    /// Timing (t=)
    pub timing: Vec<Timing>,
    /// Repeat times (r=)
    pub repeat: Vec<Repeat>,
    /// Time zones (z=)
    pub time_zones: Vec<TimeZone>,
    /// Encryption keys (k=)
    pub encryption_key: Option<String>,
    /// Attributes (a=)
    pub attributes: Vec<Attribute>,
    /// Media descriptions (m=)
    pub media_descriptions: Vec<MediaDescription>,
}

/// SDP origin (RFC 4566 Section 5.2)
#[derive(Debug, Clone)]
pub struct Origin {
    /// Username
    pub username: String,
    /// Session ID
    pub session_id: u64,
    /// Session version
    pub session_version: u64,
    /// Network type
    pub network_type: String,
    /// Address type
    pub address_type: String,
    /// Unicast address
    pub unicast_address: String,
}

/// SDP connection data (RFC 4566 Section 5.7)
#[derive(Debug, Clone)]
pub struct Connection {
    /// Network type
    pub network_type: String,
    /// Address type
    pub address_type: String,
    /// Connection address
    pub address: String,
}

/// SDP bandwidth (RFC 4566 Section 5.8)
#[derive(Debug, Clone)]
pub struct Bandwidth {
    /// Bandwidth type
    pub bandwidth_type: String,
    /// Bandwidth value
    pub value: u64,
}

/// SDP timing (RFC 4566 Section 5.9)
#[derive(Debug, Clone)]
pub struct Timing {
    /// Start time
    pub start: u64,
    /// Stop time
    pub stop: u64,
}

/// SDP repeat (RFC 4566 Section 5.10)
#[derive(Debug, Clone)]
pub struct Repeat {
    /// Repeat interval
    pub interval: String,
    /// Active duration
    pub duration: String,
    /// Offsets from start time
    pub offsets: Vec<String>,
}

/// SDP time zone (RFC 4566 Section 5.11)
#[derive(Debug, Clone)]
pub struct TimeZone {
    /// Adjustment time
    pub adjustment_time: u64,
    /// Offset
    pub offset: String,
}

/// SDP attribute (RFC 4566 Section 5.13)
#[derive(Debug, Clone)]
pub struct Attribute {
    /// Attribute name
    pub name: String,
    /// Attribute value (optional)
    pub value: Option<String>,
}

/// SDP media description (RFC 4566 Section 5.14)
#[derive(Debug, Clone)]
pub struct MediaDescription {
    /// Media type (audio, video, etc.)
    pub media_type: String,
    /// Port
    pub port: u16,
    /// Number of ports (if > 1)
    pub port_count: Option<u16>,
    /// Protocol (RTP/AVP, RTP/SAVP, etc.)
    pub protocol: String,
    /// Payload types
    pub payload_types: Vec<u8>,
    /// Media title (i=)
    pub media_title: Option<String>,
    /// Connection data (c=)
    pub connection: Option<Connection>,
    /// Bandwidth (b=)
    pub bandwidth: Vec<Bandwidth>,
    /// Encryption key (k=)
    pub encryption_key: Option<String>,
    /// Attributes (a=)
    pub attributes: Vec<Attribute>,
}

impl SessionDescription {
    /// Parse SDP from string per RFC 4566
    pub fn parse(sdp_string: &str) -> MediaEngineResult<Self> {
        let mut sdp = SessionDescription {
            version: 0,
            origin: Origin {
                username: "-".to_string(),
                session_id: 0,
                session_version: 0,
                network_type: "IN".to_string(),
                address_type: "IP4".to_string(),
                unicast_address: String::new(),
            },
            session_name: "-".to_string(),
            session_info: None,
            uri: None,
            emails: Vec::new(),
            phones: Vec::new(),
            connection: None,
            bandwidth: Vec::new(),
            timing: Vec::new(),
            repeat: Vec::new(),
            time_zones: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            media_descriptions: Vec::new(),
        };

        let mut current_media: Option<MediaDescription> = None;
        let lines: Vec<&str> = sdp_string.lines().collect();

        for line in lines {
            if line.is_empty() || line.len() < 2 {
                continue;
            }

            let key = &line[0..1];
            let value = &line[2..];

            match key {
                "v" => {
                    sdp.version = value.parse()
                        .map_err(|_| MediaEngineError::RtpParseError(
                            format!("Invalid SDP version: {}", value)
                        ))?;
                }
                "o" => {
                    sdp.origin = Self::parse_origin(value)?;
                }
                "s" => {
                    sdp.session_name = value.to_string();
                }
                "i" => {
                    if let Some(ref mut media) = current_media {
                        media.media_title = Some(value.to_string());
                    } else {
                        sdp.session_info = Some(value.to_string());
                    }
                }
                "u" => {
                    sdp.uri = Some(value.to_string());
                }
                "e" => {
                    sdp.emails.push(value.to_string());
                }
                "p" => {
                    sdp.phones.push(value.to_string());
                }
                "c" => {
                    let conn = Self::parse_connection(value)?;
                    if let Some(ref mut media) = current_media {
                        media.connection = Some(conn);
                    } else {
                        sdp.connection = Some(conn);
                    }
                }
                "b" => {
                    let bw = Self::parse_bandwidth(value)?;
                    if let Some(ref mut media) = current_media {
                        media.bandwidth.push(bw);
                    } else {
                        sdp.bandwidth.push(bw);
                    }
                }
                "t" => {
                    let timing = Self::parse_timing(value)?;
                    sdp.timing.push(timing);
                }
                "r" => {
                    let repeat = Self::parse_repeat(value)?;
                    sdp.repeat.push(repeat);
                }
                "z" => {
                    let tz = Self::parse_timezone(value)?;
                    sdp.time_zones.push(tz);
                }
                "k" => {
                    if let Some(ref mut media) = current_media {
                        media.encryption_key = Some(value.to_string());
                    } else {
                        sdp.encryption_key = Some(value.to_string());
                    }
                }
                "a" => {
                    let attr = Self::parse_attribute(value)?;
                    if let Some(ref mut media) = current_media {
                        media.attributes.push(attr);
                    } else {
                        sdp.attributes.push(attr);
                    }
                }
                "m" => {
                    // Save previous media description
                    if let Some(media) = current_media.take() {
                        sdp.media_descriptions.push(media);
                    }

                    // Parse new media description
                    current_media = Some(Self::parse_media(value)?);
                }
                _ => {
                    // Unknown line type, skip
                }
            }
        }

        // Add last media description
        if let Some(media) = current_media {
            sdp.media_descriptions.push(media);
        }

        Ok(sdp)
    }

    /// Serialize SDP to string per RFC 4566
    pub fn serialize(&self) -> String {
        let mut lines = Vec::new();

        // Version (required)
        lines.push(format!("v={}", self.version));

        // Origin (required)
        lines.push(format!(
            "o={} {} {} {} {} {}",
            self.origin.username,
            self.origin.session_id,
            self.origin.session_version,
            self.origin.network_type,
            self.origin.address_type,
            self.origin.unicast_address
        ));

        // Session name (required)
        lines.push(format!("s={}", self.session_name));

        // Session information (optional)
        if let Some(ref info) = self.session_info {
            lines.push(format!("i={}", info));
        }

        // URI (optional)
        if let Some(ref uri) = self.uri {
            lines.push(format!("u={}", uri));
        }

        // Emails (optional)
        for email in &self.emails {
            lines.push(format!("e={}", email));
        }

        // Phones (optional)
        for phone in &self.phones {
            lines.push(format!("p={}", phone));
        }

        // Connection (optional, but recommended)
        if let Some(ref conn) = self.connection {
            lines.push(format!(
                "c={} {} {}",
                conn.network_type, conn.address_type, conn.address
            ));
        }

        // Bandwidth (optional)
        for bw in &self.bandwidth {
            lines.push(format!("b={}:{}", bw.bandwidth_type, bw.value));
        }

        // Timing (required)
        for timing in &self.timing {
            lines.push(format!("t={} {}", timing.start, timing.stop));
        }

        // Repeat (optional)
        for repeat in &self.repeat {
            let offsets = repeat.offsets.join(" ");
            lines.push(format!("r={} {} {}", repeat.interval, repeat.duration, offsets));
        }

        // Time zones (optional)
        for tz in &self.time_zones {
            lines.push(format!("z={} {}", tz.adjustment_time, tz.offset));
        }

        // Encryption key (optional)
        if let Some(ref key) = self.encryption_key {
            lines.push(format!("k={}", key));
        }

        // Attributes (optional)
        for attr in &self.attributes {
            if let Some(ref value) = attr.value {
                lines.push(format!("a={}:{}", attr.name, value));
            } else {
                lines.push(format!("a={}", attr.name));
            }
        }

        // Media descriptions
        for media in &self.media_descriptions {
            lines.push(media.serialize());
        }

        lines.join("\r\n") + "\r\n"
    }

    /// Parse origin line
    fn parse_origin(value: &str) -> MediaEngineResult<Origin> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 6 {
            return Err(MediaEngineError::RtpParseError(
                "Invalid origin format".to_string()
            ));
        }

        Ok(Origin {
            username: parts[0].to_string(),
            session_id: parts[1].parse()
                .map_err(|_| MediaEngineError::RtpParseError(
                    "Invalid session ID".to_string()
                ))?,
            session_version: parts[2].parse()
                .map_err(|_| MediaEngineError::RtpParseError(
                    "Invalid session version".to_string()
                ))?,
            network_type: parts[3].to_string(),
            address_type: parts[4].to_string(),
            unicast_address: parts[5].to_string(),
        })
    }

    /// Parse connection line
    fn parse_connection(value: &str) -> MediaEngineResult<Connection> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(MediaEngineError::RtpParseError(
                "Invalid connection format".to_string()
            ));
        }

        Ok(Connection {
            network_type: parts[0].to_string(),
            address_type: parts[1].to_string(),
            address: parts[2].to_string(),
        })
    }

    /// Parse bandwidth line
    fn parse_bandwidth(value: &str) -> MediaEngineResult<Bandwidth> {
        if let Some(colon_pos) = value.find(':') {
            let bw_type = value[..colon_pos].to_string();
            let bw_value = value[colon_pos + 1..].parse()
                .map_err(|_| MediaEngineError::RtpParseError(
                    "Invalid bandwidth value".to_string()
                ))?;

            Ok(Bandwidth {
                bandwidth_type: bw_type,
                value: bw_value,
            })
        } else {
            Err(MediaEngineError::RtpParseError(
                "Invalid bandwidth format".to_string()
            ))
        }
    }

    /// Parse timing line
    fn parse_timing(value: &str) -> MediaEngineResult<Timing> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(MediaEngineError::RtpParseError(
                "Invalid timing format".to_string()
            ));
        }

        Ok(Timing {
            start: parts[0].parse()
                .map_err(|_| MediaEngineError::RtpParseError(
                    "Invalid start time".to_string()
                ))?,
            stop: parts[1].parse()
                .map_err(|_| MediaEngineError::RtpParseError(
                    "Invalid stop time".to_string()
                ))?,
        })
    }

    /// Parse repeat line
    fn parse_repeat(value: &str) -> MediaEngineResult<Repeat> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(MediaEngineError::RtpParseError(
                "Invalid repeat format".to_string()
            ));
        }

        Ok(Repeat {
            interval: parts[0].to_string(),
            duration: parts[1].to_string(),
            offsets: parts[2..].iter().map(|s| s.to_string()).collect(),
        })
    }

    /// Parse timezone line
    fn parse_timezone(value: &str) -> MediaEngineResult<TimeZone> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(MediaEngineError::RtpParseError(
                "Invalid timezone format".to_string()
            ));
        }

        Ok(TimeZone {
            adjustment_time: parts[0].parse()
                .map_err(|_| MediaEngineError::RtpParseError(
                    "Invalid adjustment time".to_string()
                ))?,
            offset: parts[1].to_string(),
        })
    }

    /// Parse attribute line
    fn parse_attribute(value: &str) -> MediaEngineResult<Attribute> {
        if let Some(colon_pos) = value.find(':') {
            Ok(Attribute {
                name: value[..colon_pos].to_string(),
                value: Some(value[colon_pos + 1..].to_string()),
            })
        } else {
            Ok(Attribute {
                name: value.to_string(),
                value: None,
            })
        }
    }

    /// Parse media line
    fn parse_media(value: &str) -> MediaEngineResult<MediaDescription> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(MediaEngineError::RtpParseError(
                "Invalid media format".to_string()
            ));
        }

        let port_str = parts[1];
        let (port, port_count) = if let Some(slash_pos) = port_str.find('/') {
            let port_val = port_str[..slash_pos].parse()
                .map_err(|_| MediaEngineError::RtpParseError(
                    "Invalid port".to_string()
                ))?;
            let count = port_str[slash_pos + 1..].parse()
                .map_err(|_| MediaEngineError::RtpParseError(
                    "Invalid port count".to_string()
                ))?;
            (port_val, Some(count))
        } else {
            (port_str.parse()
                .map_err(|_| MediaEngineError::RtpParseError(
                    "Invalid port".to_string()
                ))?, None)
        };

        let payload_types: Vec<u8> = parts[3..].iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        Ok(MediaDescription {
            media_type: parts[0].to_string(),
            port,
            port_count,
            protocol: parts[2].to_string(),
            payload_types,
            media_title: None,
            connection: None,
            bandwidth: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
        })
    }

    /// Get ICE attributes (RFC 5245)
    pub fn get_ice_attributes(&self) -> (Option<String>, Option<String>) {
        let mut ufrag = None;
        let mut pwd = None;

        for attr in &self.attributes {
            if attr.name == "ice-ufrag" {
                ufrag = attr.value.clone();
            } else if attr.name == "ice-pwd" {
                pwd = attr.value.clone();
            }
        }

        (ufrag, pwd)
    }

    /// Get DTLS fingerprint (RFC 5763)
    pub fn get_dtls_fingerprint(&self) -> Option<String> {
        for attr in &self.attributes {
            if attr.name == "fingerprint" {
                return attr.value.clone();
            }
        }
        None
    }
}

impl MediaDescription {
    /// Serialize media description
    fn serialize(&self) -> String {
        let mut lines = Vec::new();

        // Media line (m=)
        let port_str = if let Some(count) = self.port_count {
            format!("{}/{}", self.port, count)
        } else {
            self.port.to_string()
        };
        let payload_str: Vec<String> = self.payload_types.iter()
            .map(|pt| pt.to_string())
            .collect();
        lines.push(format!(
            "m={} {} {} {}",
            self.media_type, port_str, self.protocol, payload_str.join(" ")
        ));

        // Media title (i=)
        if let Some(ref title) = self.media_title {
            lines.push(format!("i={}", title));
        }

        // Connection (c=)
        if let Some(ref conn) = self.connection {
            lines.push(format!(
                "c={} {} {}",
                conn.network_type, conn.address_type, conn.address
            ));
        }

        // Bandwidth (b=)
        for bw in &self.bandwidth {
            lines.push(format!("b={}:{}", bw.bandwidth_type, bw.value));
        }

        // Encryption key (k=)
        if let Some(ref key) = self.encryption_key {
            lines.push(format!("k={}", key));
        }

        // Attributes (a=)
        for attr in &self.attributes {
            if let Some(ref value) = attr.value {
                lines.push(format!("a={}:{}", attr.name, value));
            } else {
                lines.push(format!("a={}", attr.name));
            }
        }

        lines.join("\r\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdp_parse_minimal() {
        let sdp_str = "v=0\r\n\
o=- 1234567890 1234567890 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 5000 RTP/AVP 96\r\n";

        let sdp = SessionDescription::parse(sdp_str).unwrap();
        assert_eq!(sdp.version, 0);
        assert_eq!(sdp.media_descriptions.len(), 1);
        assert_eq!(sdp.media_descriptions[0].media_type, "audio");
    }

    #[test]
    fn test_sdp_serialize() {
        let sdp = SessionDescription {
            version: 0,
            origin: Origin {
                username: "-".to_string(),
                session_id: 1234567890,
                session_version: 1234567890,
                network_type: "IN".to_string(),
                address_type: "IP4".to_string(),
                unicast_address: "127.0.0.1".to_string(),
            },
            session_name: "-".to_string(),
            session_info: None,
            uri: None,
            emails: Vec::new(),
            phones: Vec::new(),
            connection: None,
            bandwidth: Vec::new(),
            timing: vec![Timing { start: 0, stop: 0 }],
            repeat: Vec::new(),
            time_zones: Vec::new(),
            encryption_key: None,
            attributes: Vec::new(),
            media_descriptions: vec![MediaDescription {
                media_type: "audio".to_string(),
                port: 5000,
                port_count: None,
                protocol: "RTP/AVP".to_string(),
                payload_types: vec![96],
                media_title: None,
                connection: None,
                bandwidth: Vec::new(),
                encryption_key: None,
                attributes: Vec::new(),
            }],
        };

        let serialized = sdp.serialize();
        assert!(serialized.contains("v=0"));
        assert!(serialized.contains("m=audio"));
    }
}

