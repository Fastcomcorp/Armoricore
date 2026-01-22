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

//! ArcRTP Distribution for Native Apps
//!
//! Provides ultra-low latency live streaming (< 50ms) for native applications
//! using ArcRTP protocol instead of HLS (3-6 second latency)

use anyhow::Result;
use std::sync::Arc;
use tracing::{info, warn};

/// ArcRTP distributor for native app live streaming
/// 
/// This module provides direct ArcRTP packet distribution for native applications
/// that require ultra-low latency (< 50ms vs 3-6 seconds for HLS).
/// 
/// ArcRTP distribution uses:
/// - Priority-based routing (Critical for audio, High for video keyframes)
/// - Quality indicators for adaptive bitrate
/// - Direct packet forwarding (no HLS segmentation overhead)
pub struct ArcRtpDistributor {
    stream_id: String,
    // In a full implementation, this would connect to the realtime-media-engine
    // to forward ArcRTP packets directly to native app clients
}

impl ArcRtpDistributor {
    /// Create a new ArcRTP distributor for a stream
    pub fn new(stream_id: String) -> Self {
        Self { stream_id }
    }

    /// Start ArcRTP distribution for a live stream
    /// 
    /// This connects to the realtime-media-engine and forwards ArcRTP packets
    /// directly to native app clients, bypassing HLS segmentation.
    /// 
    /// **Latency Comparison:**
    /// - HLS: 3-6 seconds (segment-based)
    /// - ArcRTP: < 50ms (direct packet forwarding)
    pub async fn start_distribution(&self) -> Result<()> {
        info!(
            stream_id = self.stream_id,
            "Starting ArcRTP distribution for native apps"
        );

        // TODO: Implement connection to realtime-media-engine
        // This would:
        // 1. Connect to realtime-media-engine gRPC service
        // 2. Register stream for ArcRTP distribution
        // 3. Forward RTMP input to ArcRTP encoder
        // 4. Distribute ArcRTP packets to connected native clients
        // 5. Use priority-based routing (Critical for audio, High for video)
        // 6. Include quality indicators for adaptive bitrate

        warn!(
            stream_id = self.stream_id,
            "ArcRTP distribution not yet fully implemented. Requires integration with realtime-media-engine gRPC service."
        );

        Ok(())
    }

    /// Stop ArcRTP distribution
    pub async fn stop_distribution(&self) -> Result<()> {
        info!(
            stream_id = self.stream_id,
            "Stopping ArcRTP distribution"
        );

        // TODO: Implement cleanup
        // 1. Disconnect from realtime-media-engine
        // 2. Stop packet forwarding
        // 3. Clean up resources

        Ok(())
    }

    /// Get distribution statistics
    pub async fn get_stats(&self) -> Result<ArcRtpDistributionStats> {
        // TODO: Implement statistics collection
        Ok(ArcRtpDistributionStats {
            stream_id: self.stream_id.clone(),
            connected_clients: 0,
            packets_sent: 0,
            average_latency_ms: 0,
            quality_switches: 0,
        })
    }
}

/// ArcRTP distribution statistics
#[derive(Debug, Clone)]
pub struct ArcRtpDistributionStats {
    pub stream_id: String,
    pub connected_clients: u32,
    pub packets_sent: u64,
    pub average_latency_ms: u32,
    pub quality_switches: u32,
}

/// Integration point for live transcoder
/// 
/// This allows the live transcoder to optionally enable ArcRTP distribution
/// alongside HLS for native app clients.
impl ArcRtpDistributor {
    /// Enable ArcRTP distribution for a stream
    /// 
    /// This should be called when starting live transcoding if native app
    /// support is required.
    pub async fn enable_for_stream(stream_id: &str) -> Result<Arc<Self>> {
        let distributor = Arc::new(Self::new(stream_id.to_string()));
        distributor.start_distribution().await?;
        Ok(distributor)
    }
}

