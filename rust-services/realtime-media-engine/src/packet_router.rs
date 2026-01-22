//! Packet routing infrastructure
//!
//! Implements efficient packet routing with load balancing and quality-based routing.
//! Uses ArcRTP priority for intelligent packet routing.
// Copyright 2025 Francisco F. Pinochet
// Copyright 2026 Fastcomcorp
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
use crate::arcrtp_handler::{ArcRtpPacket, ArcRtpPriority};
use std::collections::HashMap;
use std::net::SocketAddr;
use uuid::Uuid;

/// Route information
#[derive(Debug, Clone)]
pub struct Route {
    /// Route ID
    pub route_id: Uuid,
    /// Destination address
    pub destination: SocketAddr,
    /// Route priority (higher = more preferred)
    pub priority: u8,
    /// Route quality score (0-100)
    pub quality_score: u8,
    /// Is route active
    pub active: bool,
}

/// Packet priority (deprecated - use ArcRtpPriority instead)
/// Kept for backward compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[deprecated(note = "Use ArcRtpPriority from arcrtp_handler instead")]
pub enum PacketPriority {
    /// Critical: Audio keyframes, silence breaks
    Critical = 0,
    /// High: Video keyframes (I-frames)
    High = 1,
    /// Medium: Video delta frames (P-frames)
    Medium = 2,
    /// Low: Video B-frames, redundant data
    Low = 3,
}

impl From<ArcRtpPriority> for PacketPriority {
    fn from(priority: ArcRtpPriority) -> Self {
        match priority {
            ArcRtpPriority::Critical => PacketPriority::Critical,
            ArcRtpPriority::High => PacketPriority::High,
            ArcRtpPriority::Medium => PacketPriority::Medium,
            ArcRtpPriority::Low => PacketPriority::Low,
        }
    }
}

impl From<PacketPriority> for ArcRtpPriority {
    fn from(priority: PacketPriority) -> Self {
        match priority {
            PacketPriority::Critical => ArcRtpPriority::Critical,
            PacketPriority::High => ArcRtpPriority::High,
            PacketPriority::Medium => ArcRtpPriority::Medium,
            PacketPriority::Low => ArcRtpPriority::Low,
        }
    }
}

/// Load balancer
#[derive(Debug, Clone)]
pub struct LoadBalancer {
    /// Round-robin index
    round_robin_index: usize,
    /// Quality-based routing enabled
    quality_based: bool,
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(quality_based: bool) -> Self {
        LoadBalancer {
            round_robin_index: 0,
            quality_based,
        }
    }

    /// Select best route from available routes
    pub fn select_route<'a>(&mut self, routes: &'a [&'a Route]) -> Option<&'a Route> {
        if routes.is_empty() {
            return None;
        }

        // Filter active routes
        let active_routes: Vec<&Route> = routes.iter()
            .filter(|r| r.active)
            .copied()
            .collect();

        if active_routes.is_empty() {
            return None;
        }

        if self.quality_based {
            // Select route with highest quality score
            active_routes.iter()
                .max_by_key(|r| r.quality_score)
                .copied()
        } else {
            // Round-robin selection
            let selected = active_routes[self.round_robin_index % active_routes.len()];
            self.round_robin_index = (self.round_robin_index + 1) % active_routes.len();
            Some(selected)
        }
    }
}

/// Packet router
pub struct PacketRouter {
    /// Routes by stream ID
    routes: HashMap<Uuid, Vec<Route>>,
    /// Load balancer
    load_balancer: LoadBalancer,
    /// Route statistics
    route_stats: HashMap<Uuid, RouteStats>,
}

/// Route statistics
#[derive(Debug, Clone, Default)]
pub struct RouteStats {
    /// Packets routed
    pub packets_routed: u64,
    /// Bytes routed
    pub bytes_routed: u64,
    /// Errors
    pub errors: u64,
}

impl PacketRouter {
    /// Create a new packet router
    pub fn new(quality_based_routing: bool) -> Self {
        PacketRouter {
            routes: HashMap::new(),
            load_balancer: LoadBalancer::new(quality_based_routing),
            route_stats: HashMap::new(),
        }
    }

    /// Add route for a stream
    pub fn add_route(&mut self, stream_id: Uuid, route: Route) -> MediaEngineResult<()> {
        self.routes.entry(stream_id)
            .or_insert_with(Vec::new)
            .push(route.clone());

        // Initialize stats
        self.route_stats.insert(route.route_id, RouteStats::default());

        Ok(())
    }

    /// Remove route
    pub fn remove_route(&mut self, stream_id: &Uuid, route_id: &Uuid) -> MediaEngineResult<()> {
        if let Some(routes) = self.routes.get_mut(stream_id) {
            routes.retain(|r| r.route_id != *route_id);
            if routes.is_empty() {
                self.routes.remove(stream_id);
            }
        }

        self.route_stats.remove(route_id);

        Ok(())
    }

    /// Get routes for a stream
    pub fn get_routes(&self, stream_id: &Uuid) -> Option<&[Route]> {
        self.routes.get(stream_id).map(|v| v.as_slice())
    }

    /// Route packet to destination (standard RTP packet)
    pub fn route_packet(
        &mut self,
        stream_id: &Uuid,
        packet: &RtpPacket,
    ) -> MediaEngineResult<Option<SocketAddr>> {
        // Convert to ArcRTP priority for routing
        let priority = ArcRtpPriority::from(self.determine_packet_priority(packet));
        self.route_by_priority(stream_id, priority, packet.payload.len())
    }

    /// Route ArcRTP packet to destination (uses ArcRTP priority field)
    pub fn route_arcrtp_packet(
        &mut self,
        stream_id: &Uuid,
        packet: &ArcRtpPacket,
    ) -> MediaEngineResult<Option<SocketAddr>> {
        // Use ArcRTP priority directly from packet
        let priority = packet.priority();
        self.route_by_priority(stream_id, priority, packet.payload.len())
    }

    /// Route by priority (internal implementation)
    fn route_by_priority(
        &mut self,
        stream_id: &Uuid,
        priority: ArcRtpPriority,
        payload_size: usize,
    ) -> MediaEngineResult<Option<SocketAddr>> {
        // Get routes for stream
        let routes = match self.routes.get(stream_id) {
            Some(routes) => routes,
            None => return Err(MediaEngineError::StreamNotFound {
                stream_id: stream_id.to_string(),
            }),
        };

        // Filter routes by priority (critical packets use high-priority routes)
        let available_routes: Vec<&Route> = match priority {
            ArcRtpPriority::Critical => {
                // Critical priority: use only highest priority routes (priority >= 2)
                routes.iter()
                    .filter(|r| r.active && r.priority >= 2)
                    .collect()
            }
            ArcRtpPriority::High => {
                // High priority: use routes with priority >= 1
                routes.iter()
                    .filter(|r| r.active && r.priority >= 1)
                    .collect()
            }
            ArcRtpPriority::Medium | ArcRtpPriority::Low => {
                // Medium/Low priority: use all active routes
                routes.iter()
                    .filter(|r| r.active)
                    .collect()
            }
        };

        // Select route
        let route = match self.load_balancer.select_route(&available_routes) {
            Some(route) => route,
            None => return Ok(None),
        };

        // Update statistics
        if let Some(stats) = self.route_stats.get_mut(&route.route_id) {
            stats.packets_routed += 1;
            stats.bytes_routed += payload_size as u64;
        }

        Ok(Some(route.destination))
    }

    /// Determine packet priority from RTP packet
    /// SECURITY: Audio packets are always Critical priority to ensure voice quality
    pub fn determine_packet_priority(&self, packet: &RtpPacket) -> PacketPriority {
        // Audio packets are always critical
        if packet.is_audio() {
            return PacketPriority::Critical;
        }

        // Video keyframes (I-frames) are high priority
        if packet.is_video() && packet.header.marker {
            return PacketPriority::High;
        }

        // Video delta frames are medium priority
        if packet.is_video() {
            return PacketPriority::Medium;
        }

        // Default to low priority
        PacketPriority::Low
    }

    /// Determine ArcRTP priority from RTP packet
    /// SECURITY: Audio packets are always Critical priority to ensure voice quality
    pub fn determine_arcrtp_priority(&self, packet: &RtpPacket) -> ArcRtpPriority {
        // Audio packets are always critical
        if packet.is_audio() {
            return ArcRtpPriority::Critical;
        }

        // Video keyframes (I-frames) are high priority
        if packet.is_video() && packet.header.marker {
            return ArcRtpPriority::High;
        }

        // Video delta frames are medium priority
        if packet.is_video() {
            return ArcRtpPriority::Medium;
        }

        // Default to low priority
        ArcRtpPriority::Low
    }

    /// Update route quality
    pub fn update_route_quality(&mut self, route_id: &Uuid, quality_score: u8) -> MediaEngineResult<()> {
        // Find and update route
        for routes in self.routes.values_mut() {
            for route in routes.iter_mut() {
                if route.route_id == *route_id {
                    route.quality_score = quality_score.min(100);
                    return Ok(());
                }
            }
        }

        Err(MediaEngineError::StreamNotFound {
            stream_id: format!("route {}", route_id),
        })
    }

    /// Get route statistics
    pub fn get_route_stats(&self, route_id: &Uuid) -> Option<&RouteStats> {
        self.route_stats.get(route_id)
    }

    /// Get all route statistics
    pub fn get_all_stats(&self) -> &HashMap<Uuid, RouteStats> {
        &self.route_stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_handler::{RtpHeader, RtpPacket};
    use crate::arcrtp_handler::{ArcRtpPacket, ArcRtpQuality, ArcRtpPriority};
    use bytes::Bytes;

    fn create_test_packet(is_audio: bool) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: if is_audio { 96 } else { 97 },
                sequence_number: 1,
                timestamp: 1000,
                ssrc: 12345,
                csrc: vec![],
                extension_header: None,
            },
            payload: Bytes::from("test"),
        }
    }

    fn create_test_arcrtp_packet(priority: ArcRtpPriority) -> ArcRtpPacket {
        let rtp_header = RtpHeader {
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
        ArcRtpPacket::new(rtp_header, ArcRtpQuality::Good, priority, Bytes::from("test"))
    }

    #[test]
    fn test_add_route() {
        let mut router = PacketRouter::new(false);
        let stream_id = Uuid::new_v4();
        let route = Route {
            route_id: Uuid::new_v4(),
            destination: "127.0.0.1:8080".parse().unwrap(),
            priority: 5,
            quality_score: 80,
            active: true,
        };

        router.add_route(stream_id, route).unwrap();
        assert!(router.get_routes(&stream_id).is_some());
    }

    #[test]
    fn test_route_packet() {
        let mut router = PacketRouter::new(false);
        let stream_id = Uuid::new_v4();
        let route = Route {
            route_id: Uuid::new_v4(),
            destination: "127.0.0.1:8080".parse().unwrap(),
            priority: 5,
            quality_score: 80,
            active: true,
        };

        router.add_route(stream_id, route).unwrap();

        let packet = create_test_packet(true); // Audio packet
        let destination = router.route_packet(&stream_id, &packet).unwrap();
        assert!(destination.is_some());
    }

    #[test]
    fn test_route_arcrtp_packet() {
        let mut router = PacketRouter::new(false);
        let stream_id = Uuid::new_v4();
        let route = Route {
            route_id: Uuid::new_v4(),
            destination: "127.0.0.1:8080".parse().unwrap(),
            priority: 5,
            quality_score: 80,
            active: true,
        };

        router.add_route(stream_id, route).unwrap();

        // Test Critical priority (audio)
        let packet = create_test_arcrtp_packet(ArcRtpPriority::Critical);
        let destination = router.route_arcrtp_packet(&stream_id, &packet).unwrap();
        assert!(destination.is_some());
    }

    #[test]
    fn test_packet_priority_audio() {
        let router = PacketRouter::new(false);
        // Create actual audio packet (payload type < 96, e.g., 0 = PCMU)
        let audio_packet = RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 0,  // PCMU - definitely audio (< 96)
                sequence_number: 1,
                timestamp: 1000,
                ssrc: 12345,
                csrc: vec![],
                extension_header: None,
            },
            payload: Bytes::from("test"),
        };
        let priority = router.determine_packet_priority(&audio_packet);
        assert_eq!(priority, PacketPriority::Critical);
    }

    #[test]
    fn test_arcrtp_priority_audio() {
        let router = PacketRouter::new(false);
        let audio_packet = RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 0,  // PCMU - audio
                sequence_number: 1,
                timestamp: 1000,
                ssrc: 12345,
                csrc: vec![],
                extension_header: None,
            },
            payload: Bytes::from("test"),
        };
        let priority = router.determine_arcrtp_priority(&audio_packet);
        assert_eq!(priority, ArcRtpPriority::Critical);
    }

    #[test]
    fn test_priority_conversion() {
        // Test conversion between PacketPriority and ArcRtpPriority
        assert_eq!(ArcRtpPriority::from(PacketPriority::Critical), ArcRtpPriority::Critical);
        assert_eq!(ArcRtpPriority::from(PacketPriority::High), ArcRtpPriority::High);
        assert_eq!(ArcRtpPriority::from(PacketPriority::Medium), ArcRtpPriority::Medium);
        assert_eq!(ArcRtpPriority::from(PacketPriority::Low), ArcRtpPriority::Low);

        assert_eq!(PacketPriority::from(ArcRtpPriority::Critical), PacketPriority::Critical);
        assert_eq!(PacketPriority::from(ArcRtpPriority::High), PacketPriority::High);
        assert_eq!(PacketPriority::from(ArcRtpPriority::Medium), PacketPriority::Medium);
        assert_eq!(PacketPriority::from(ArcRtpPriority::Low), PacketPriority::Low);
    }

    #[test]
    fn test_priority_based_routing() {
        let mut router = PacketRouter::new(false);
        let stream_id = Uuid::new_v4();
        
        // Add routes with different priorities
        let high_priority_route = Route {
            route_id: Uuid::new_v4(),
            destination: "127.0.0.1:8080".parse().unwrap(),
            priority: 3, // High priority route
            quality_score: 90,
            active: true,
        };
        
        let low_priority_route = Route {
            route_id: Uuid::new_v4(),
            destination: "127.0.0.1:8081".parse().unwrap(),
            priority: 1, // Low priority route
            quality_score: 50,
            active: true,
        };

        router.add_route(stream_id, high_priority_route.clone()).unwrap();
        router.add_route(stream_id, low_priority_route.clone()).unwrap();

        // Critical priority should prefer high-priority route
        let critical_packet = create_test_arcrtp_packet(ArcRtpPriority::Critical);
        let destination = router.route_arcrtp_packet(&stream_id, &critical_packet).unwrap();
        assert!(destination.is_some());
        // Should route to high-priority route (priority >= 2)
        assert_eq!(destination.unwrap(), high_priority_route.destination);
    }
}

