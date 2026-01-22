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

//! Real-time Media Engine for ArcRTC Protocol
//!
//! This crate provides the core media transport layer for ArcRTC, including:
//! - RTP packet parsing and construction
//! - SRTP encryption/decryption
//! - Stream management
//! - Packet routing
//! - Low-latency buffering
//!
//! # Foundation + Basic VoIP
//!
//! This initial implementation focuses on:
//! - Basic RTP/SRTP pipeline
//! - VoIP-optimized audio handling
//! - Stream lifecycle management
//! - Integration with armoricore-keys
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


pub mod error;
pub mod rtp_handler;
pub mod rtcp;
pub mod srtp_pipeline;
pub mod stream_manager;
pub mod jitter_buffer;
pub mod packet_loss_concealment;
pub mod key_integration;
pub mod audio_pipeline;
pub mod fec;
pub mod nack;
pub mod audio_processing;
pub mod connection_health;
pub mod bandwidth_estimation;
pub mod congestion_control;
pub mod codec_selection;
pub mod packet_router;
pub mod video_pipeline;
pub mod adaptive_bitrate;
pub mod arcsignaling;
pub mod arcrtp_handler;
pub mod protocol_bridge;
pub mod webrtc_media;
pub mod hardware_acceleration;
pub mod low_latency;
pub mod ice;
pub mod dtls;
pub mod sdp;
pub mod h264_payload;
pub mod vvc_payload;
pub mod scip_payload;
pub mod rtp_retransmission;

// Re-export main types
pub use error::{MediaEngineError, MediaEngineResult};
pub use rtp_handler::{RtpPacket, RtpHeader};
pub use srtp_pipeline::{SrtpPipeline, SrtpConfig};
pub use stream_manager::{StreamManager, StreamConfig, StreamState, MediaType};
pub use key_integration::SrtpKeyManager;
pub use audio_pipeline::{AudioPipeline, AudioConfig, AudioFrame};
pub use fec::{FecEncoder, FecDecoder, FecConfig, FecPacket};
pub use nack::{NackManager, NackConfig, NackMessage, NackStats};
pub use audio_processing::{
    EchoCanceller, EchoCancellerConfig,
    NoiseSuppressor, NoiseSuppressorConfig,
    AutomaticGainControl, AgcConfig,
};
pub use connection_health::{
    ConnectionHealthMonitor, ConnectionQuality, NetworkMetrics, ConnectionStats,
};
pub use bandwidth_estimation::{
    BandwidthEstimator, BandwidthEstimatorConfig, BandwidthEstimate, EstimationMethod,
};
pub use congestion_control::{
    CongestionController, CongestionControlConfig,
};
pub use codec_selection::{
    CodecSelector, CodecInfo, NetworkProfile,
};
pub use arcsignaling::{
    ArcSignalingHandler, ArcSignalingMessage, ArcSignalingSession,
    ConnectRequest, ConnectAck, StreamNegotiate, StreamAck,
    QualityUpdate, Disconnect, ArcMediaType, SessionState,
};
pub use arcrtp_handler::{
    ArcRtpPacket, ArcRtpHeader, ArcRtpQuality, ArcRtpPriority,
};
pub use protocol_bridge::{
    ProtocolBridge, Sdp, MediaDescription, SdpAttribute, IceCandidate as ProtocolBridgeIceCandidate,
};
pub use ice::{IceAgent, IceCandidate, IceCandidatePair, IceCandidateType, IceConnectionState, IcePairState};
pub use dtls::{DtlsConnection, DtlsState, DtlsHandshakeType};
pub use rtcp::{RtcpHeader, SenderReport, ReceiverReport, ReceptionReport, RtcpPacketType};
pub use sdp::{SessionDescription, Origin, Connection, MediaDescription as SdpMediaDescription, Attribute};
pub use webrtc_media::{
    WebRtcMediaEngine, WebRtcConnection, WebRtcConnectionState,
    DtlsState as WebRtcDtlsState, IceState,
};
pub use hardware_acceleration::{
    HardwareEncoder, HardwareDecoder, HardwareAccelerationManager,
    HardwareBackend, HardwareCapabilities,
};
pub use low_latency::{
    ZeroCopyBuffer, BatchProcessor, OptimizedPacketRouter, HardwareTimestamp,
};
pub use packet_router::{
    PacketRouter, Route, PacketPriority, LoadBalancer, RouteStats,
};
pub use video_pipeline::{
    VideoPipeline, VideoConfig, VideoCodec, VideoResolution, VideoFrame,
};
pub use adaptive_bitrate::{
    AdaptiveBitrateController, AdaptiveBitrateConfig,
};
pub use h264_payload::{H264PayloadHandler, NalUnit, NalUnitType};
pub use vvc_payload::{VvcPayloadHandler, VvcNalUnit};
pub use scip_payload::{ScipPayloadHandler, ScipPacket, ScipPacketType};
pub use rtp_retransmission::{RtpRetransmissionHandler, RetransmissionRequest};
