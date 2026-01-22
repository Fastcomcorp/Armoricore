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

//! gRPC service implementation
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


use realtime_media_engine::{
    StreamManager, StreamConfig,
    AudioPipeline, AudioConfig, AudioFrame,
    PacketRouter, RtpPacket, SrtpConfig,
    key_integration::SrtpKeyManager,
    H264PayloadHandler, NalUnit,
    VvcPayloadHandler, VvcNalUnit,
    ScipPayloadHandler, ScipPacket, ScipPacketType as EngineScipPacketType,
    RtpRetransmissionHandler, RetransmissionRequest as EngineRetransmissionRequest,
};
use bytes::Bytes;
use crate::armoricore_media_engine::media_engine_server::MediaEngine;
use crate::armoricore_media_engine::*;
use armoricore_keys::{KeyStore, local_store::LocalKeyStore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use uuid::Uuid;

/// Media Engine gRPC service
pub struct MediaEngineService {
    stream_manager: Arc<RwLock<StreamManager>>,
    // Use Mutex for AudioPipeline since it contains non-Send types
    audio_pipelines: Arc<Mutex<HashMap<Uuid, AudioPipeline>>>,
    packet_router: Arc<RwLock<PacketRouter>>,
    key_manager: Arc<SrtpKeyManager>,
    // RFC handlers
    h264_handlers: Arc<Mutex<HashMap<String, H264PayloadHandler>>>,
    vvc_handlers: Arc<Mutex<HashMap<String, VvcPayloadHandler>>>,
    scip_handlers: Arc<Mutex<HashMap<String, ScipPayloadHandler>>>,
    retransmission_handlers: Arc<Mutex<HashMap<String, RtpRetransmissionHandler>>>,
}

impl MediaEngineService {
    /// Create a new media engine service
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize key store
        let storage_path = std::env::var("KEY_STORAGE_PATH")
            .unwrap_or_else(|_| "./keys".to_string());
        let local_store = LocalKeyStore::new(&storage_path, None).await?;
        let key_store = Arc::new(KeyStore::new(Arc::new(local_store)));
        let key_manager = Arc::new(SrtpKeyManager::new(key_store));

        Ok(MediaEngineService {
            stream_manager: Arc::new(RwLock::new(StreamManager::new())),
            audio_pipelines: Arc::new(Mutex::new(HashMap::new())),
            packet_router: Arc::new(RwLock::new(PacketRouter::new(true))),
            key_manager,
            h264_handlers: Arc::new(Mutex::new(HashMap::new())),
            vvc_handlers: Arc::new(Mutex::new(HashMap::new())),
            scip_handlers: Arc::new(Mutex::new(HashMap::new())),
            retransmission_handlers: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

#[tonic::async_trait]
impl MediaEngine for MediaEngineService {
    async fn create_stream(
        &self,
        request: Request<CreateStreamRequest>,
    ) -> Result<Response<CreateStreamResponse>, Status> {
        let req = request.into_inner();
        let config = req.config.ok_or_else(|| Status::invalid_argument("config is required"))?;

        // Convert proto config to internal config
        let user_id = Uuid::parse_str(&config.user_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid user_id: {}", e)))?;

        let media_type = match config.media_type() {
            crate::armoricore_media_engine::MediaType::Audio => realtime_media_engine::MediaType::Audio,
            crate::armoricore_media_engine::MediaType::Video => realtime_media_engine::MediaType::Video,
        };

        // Create SRTP config if encryption enabled
        let srtp_config = if config.encryption_enabled {
            let session_id = Uuid::new_v4();
            // Create keys first
            self.key_manager.create_session_keys(&session_id, config.ssrc).await
                .map_err(|e| Status::internal(format!("Failed to create keys: {}", e)))?;
            
            // Retrieve keys
            let (master_key, master_salt) = self.key_manager.get_session_keys(&session_id).await
                .map_err(|e| Status::internal(format!("Failed to get keys: {}", e)))?;
            
            // SrtpConfig uses Vec<u8>, so we can use the vectors directly
            Some(SrtpConfig {
                master_key,
                master_salt,
                ssrc: config.ssrc,
                roc: 0, // Initial ROC
            })
        } else {
            None
        };

        let stream_config = StreamConfig {
            user_id,
            media_type,
            ssrc: config.ssrc,
            payload_type: config.payload_type as u8,
            codec: config.codec.clone(),
            bitrate: config.bitrate,
            srtp_config,
        };

        let mut manager = self.stream_manager.write().await;
        let stream_id = manager.create_stream(stream_config)
            .map_err(|e| Status::internal(format!("Failed to create stream: {}", e)))?;

        // Create audio pipeline if audio stream
        if media_type == realtime_media_engine::MediaType::Audio {
            let audio_config = AudioConfig {
                codec: config.codec.clone(),
                bitrate: config.bitrate,
                sample_rate: 16000, // Default VoIP
                channels: 1,
                frame_size_ms: 20,
                dtx: true,
                fec: true,
                plc: true,
            };
            let pipeline = AudioPipeline::new(audio_config)
                .map_err(|e| Status::internal(format!("Failed to create pipeline: {}", e)))?;
            
            let mut pipelines = self.audio_pipelines.lock().unwrap();
            pipelines.insert(stream_id, pipeline);
        }

        Ok(Response::new(CreateStreamResponse {
            stream_id: stream_id.to_string(),
            success: true,
            error: String::new(),
        }))
    }

    async fn stop_stream(
        &self,
        request: Request<StopStreamRequest>,
    ) -> Result<Response<StopStreamResponse>, Status> {
        let req = request.into_inner();
        let stream_id = Uuid::parse_str(&req.stream_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid stream_id: {}", e)))?;

        let mut manager = self.stream_manager.write().await;
        manager.remove_stream(&stream_id)
            .map_err(|e| Status::internal(format!("Failed to stop stream: {}", e)))?;

        // Remove audio pipeline
        let mut pipelines = self.audio_pipelines.lock().unwrap();
        pipelines.remove(&stream_id);

        Ok(Response::new(StopStreamResponse {
            success: true,
            error: String::new(),
        }))
    }

    async fn get_stream(
        &self,
        request: Request<GetStreamRequest>,
    ) -> Result<Response<GetStreamResponse>, Status> {
        let req = request.into_inner();
        let stream_id = Uuid::parse_str(&req.stream_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid stream_id: {}", e)))?;

        let manager = self.stream_manager.read().await;
        if let Some(stream) = manager.get_stream(&stream_id) {
            let proto_media_type = match stream.config.media_type {
                realtime_media_engine::MediaType::Audio => crate::armoricore_media_engine::MediaType::Audio,
                realtime_media_engine::MediaType::Video => crate::armoricore_media_engine::MediaType::Video,
            };

            let config = Some(crate::armoricore_media_engine::StreamConfig {
                user_id: stream.config.user_id.to_string(),
                media_type: proto_media_type as i32,
                ssrc: stream.config.ssrc,
                payload_type: stream.config.payload_type as u32,
                codec: stream.config.codec.clone(),
                bitrate: stream.config.bitrate,
                encryption_enabled: stream.srtp_pipeline.is_some(),
            });

            let proto_state = match stream.state {
                realtime_media_engine::StreamState::Initializing => crate::armoricore_media_engine::StreamState::Initializing,
                realtime_media_engine::StreamState::Active => crate::armoricore_media_engine::StreamState::Active,
                realtime_media_engine::StreamState::Paused => crate::armoricore_media_engine::StreamState::Paused,
                realtime_media_engine::StreamState::Stopped => crate::armoricore_media_engine::StreamState::Stopped,
                realtime_media_engine::StreamState::Error => crate::armoricore_media_engine::StreamState::Error,
            };

            Ok(Response::new(GetStreamResponse {
                exists: true,
                config,
                state: proto_state as i32,
            }))
        } else {
            Ok(Response::new(GetStreamResponse {
                exists: false,
                config: None,
                state: crate::armoricore_media_engine::StreamState::Stopped as i32,
            }))
        }
    }

    async fn route_packet(
        &self,
        request: Request<RoutePacketRequest>,
    ) -> Result<Response<RoutePacketResponse>, Status> {
        let req = request.into_inner();
        let stream_id = Uuid::parse_str(&req.stream_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid stream_id: {}", e)))?;

        // Parse RTP packet
        let packet = realtime_media_engine::RtpPacket::parse(&req.rtp_packet)
            .map_err(|e| Status::invalid_argument(format!("Invalid RTP packet: {}", e)))?;

        let mut router = self.packet_router.write().await;
        match router.route_packet(&stream_id, &packet) {
            Ok(Some(destination)) => Ok(Response::new(RoutePacketResponse {
                success: true,
                destination: destination.to_string(),
                error: String::new(),
            })),
            Ok(None) => Ok(Response::new(RoutePacketResponse {
                success: false,
                destination: String::new(), // Empty string if no destination
                error: "No route available".to_string(),
            })),
            Err(e) => Err(Status::internal(format!("Routing error: {}", e))),
        }
    }

    async fn encode_audio(
        &self,
        request: Request<EncodeAudioRequest>,
    ) -> Result<Response<EncodeAudioResponse>, Status> {
        let req = request.into_inner();
        let stream_id = Uuid::parse_str(&req.stream_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid stream_id: {}", e)))?;

        let mut pipelines = self.audio_pipelines.lock().unwrap();
        let pipeline = pipelines.get_mut(&stream_id)
            .ok_or_else(|| Status::not_found("Stream not found"))?;

        let frame = AudioFrame {
            samples: req.samples,
            sample_rate: req.sample_rate,
            channels: req.channels as u8,
            timestamp: req.timestamp,
        };

        let encoded = pipeline.encode(&frame)
            .map_err(|e| Status::internal(format!("Encoding error: {}", e)))?;

        Ok(Response::new(EncodeAudioResponse {
            success: true,
            encoded_data: encoded.to_vec(),
            error: String::new(),
        }))
    }

    async fn decode_audio(
        &self,
        request: Request<DecodeAudioRequest>,
    ) -> Result<Response<DecodeAudioResponse>, Status> {
        let req = request.into_inner();
        let stream_id = Uuid::parse_str(&req.stream_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid stream_id: {}", e)))?;

        let mut pipelines = self.audio_pipelines.lock().unwrap();
        let pipeline = pipelines.get_mut(&stream_id)
            .ok_or_else(|| Status::not_found("Stream not found"))?;

        let frame = pipeline.decode(&req.encoded_data, req.timestamp)
            .map_err(|e| Status::internal(format!("Decoding error: {}", e)))?;

        Ok(Response::new(DecodeAudioResponse {
            success: true,
            samples: frame.samples,
            sample_rate: frame.sample_rate,
            channels: frame.channels as u32,
            error: String::new(),
        }))
    }

    async fn update_stream_state(
        &self,
        request: Request<UpdateStreamStateRequest>,
    ) -> Result<Response<UpdateStreamStateResponse>, Status> {
        let req = request.into_inner();
        let stream_id = Uuid::parse_str(&req.stream_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid stream_id: {}", e)))?;

        let new_state = match req.new_state() {
            crate::armoricore_media_engine::StreamState::Initializing => realtime_media_engine::StreamState::Initializing,
            crate::armoricore_media_engine::StreamState::Active => realtime_media_engine::StreamState::Active,
            crate::armoricore_media_engine::StreamState::Paused => realtime_media_engine::StreamState::Paused,
            crate::armoricore_media_engine::StreamState::Stopped => realtime_media_engine::StreamState::Stopped,
            crate::armoricore_media_engine::StreamState::Error => realtime_media_engine::StreamState::Error,
        };

        let mut manager = self.stream_manager.write().await;
        manager.update_stream_state(&stream_id, new_state)
            .map_err(|e| Status::internal(format!("Failed to update state: {}", e)))?;

        Ok(Response::new(UpdateStreamStateResponse {
            success: true,
            error: String::new(),
        }))
    }

    async fn get_stream_stats(
        &self,
        request: Request<GetStreamStatsRequest>,
    ) -> Result<Response<GetStreamStatsResponse>, Status> {
        let req = request.into_inner();
        let stream_id = Uuid::parse_str(&req.stream_id)
            .map_err(|e| Status::invalid_argument(format!("Invalid stream_id: {}", e)))?;

        let manager = self.stream_manager.read().await;
        if let Some(stream) = manager.get_stream(&stream_id) {
            let stats = Some(StreamStats {
                packets_sent: stream.stats.packets_sent,
                packets_received: stream.stats.packets_received,
                bytes_sent: stream.stats.bytes_sent,
                bytes_received: stream.stats.bytes_received,
                packets_lost: stream.stats.packets_lost,
                jitter_ms: stream.stats.jitter_ms,
                rtt_ms: stream.stats.rtt_ms,
            });

            Ok(Response::new(GetStreamStatsResponse {
                exists: true,
                stats,
            }))
        } else {
            Ok(Response::new(GetStreamStatsResponse {
                exists: false,
                stats: None,
            }))
        }
    }

    // RFC 6184 - H.264 Payload Format
    async fn packetize_h264(
        &self,
        request: Request<PacketizeH264Request>,
    ) -> Result<Response<PacketizeH264Response>, Status> {
        // Bytes and Duration not used in this function

        let req = request.into_inner();
        let handler_key = format!("h264_{}", req.max_payload_size);
        
        let mut handlers = self.h264_handlers.lock().unwrap();
        let handler = handlers.entry(handler_key.clone())
            .or_insert_with(|| H264PayloadHandler::new(req.max_payload_size as usize));

        // Parse NAL unit
        let nal_unit = NalUnit::parse(&req.nal_unit)
            .map_err(|e| Status::invalid_argument(format!("Failed to parse NAL unit: {}", e)))?;

        // Packetize
        let packets = handler.packetize_nal_unit(&nal_unit, req.timestamp, req.ssrc, req.payload_type as u8)
            .map_err(|e| Status::internal(format!("Failed to packetize: {}", e)))?;

        // Serialize packets
        let rtp_packets: Vec<Vec<u8>> = packets.iter()
            .map(|p| p.serialize().to_vec())
            .collect();

        Ok(Response::new(PacketizeH264Response {
            success: true,
            rtp_packets: rtp_packets.iter().map(|p| p.clone()).collect(),
            error: String::new(),
        }))
    }

    async fn depacketize_h264(
        &self,
        request: Request<DepacketizeH264Request>,
    ) -> Result<Response<DepacketizeH264Response>, Status> {
        // Bytes not used in this function

        let req = request.into_inner();
        
        // Parse RTP packets
        let mut rtp_packets = Vec::new();
        for packet_data in req.rtp_packets {
            let packet = RtpPacket::parse(&packet_data)
                .map_err(|e| Status::invalid_argument(format!("Failed to parse RTP packet: {}", e)))?;
            rtp_packets.push(packet);
        }

        // Use a handler for depacketization (max_payload_size doesn't matter for depacketization)
        let handler = H264PayloadHandler::new(1200);
        let nal_units = handler.depacketize(&rtp_packets)
            .map_err(|e| Status::internal(format!("Failed to depacketize: {}", e)))?;

        // Serialize NAL units
        let nal_unit_data: Vec<Vec<u8>> = nal_units.iter()
            .map(|nal| nal.data.to_vec())
            .collect();

        Ok(Response::new(DepacketizeH264Response {
            success: true,
            nal_units: nal_unit_data,
            error: String::new(),
        }))
    }

    // draft-ietf-avtcore-rtp-vvc - VVC Payload Format
    async fn packetize_vvc(
        &self,
        request: Request<PacketizeVvcRequest>,
    ) -> Result<Response<PacketizeVvcResponse>, Status> {
        let req = request.into_inner();
        let handler_key = format!("vvc_{}", req.max_payload_size);
        
        let mut handlers = self.vvc_handlers.lock().unwrap();
        let handler = handlers.entry(handler_key.clone())
            .or_insert_with(|| VvcPayloadHandler::new(req.max_payload_size as usize));

        // Parse VVC NAL unit
        let nal_unit = VvcNalUnit::parse(&req.nal_unit)
            .map_err(|e| Status::invalid_argument(format!("Failed to parse VVC NAL unit: {}", e)))?;

        // Packetize
        let packets = handler.packetize_nal_unit(&nal_unit, req.timestamp, req.ssrc, req.payload_type as u8)
            .map_err(|e| Status::internal(format!("Failed to packetize: {}", e)))?;

        // Serialize packets
        let rtp_packets: Vec<Vec<u8>> = packets.iter()
            .map(|p| p.serialize().to_vec())
            .collect();

        Ok(Response::new(PacketizeVvcResponse {
            success: true,
            rtp_packets: rtp_packets.iter().map(|p| p.clone()).collect(),
            error: String::new(),
        }))
    }

    async fn depacketize_vvc(
        &self,
        request: Request<DepacketizeVvcRequest>,
    ) -> Result<Response<DepacketizeVvcResponse>, Status> {
        let req = request.into_inner();
        
        // Parse RTP packets
        let mut rtp_packets = Vec::new();
        for packet_data in req.rtp_packets {
            let packet = RtpPacket::parse(&packet_data)
                .map_err(|e| Status::invalid_argument(format!("Failed to parse RTP packet: {}", e)))?;
            rtp_packets.push(packet);
        }

        // Use a handler for depacketization
        let handler = VvcPayloadHandler::new(1200);
        let nal_units = handler.depacketize(&rtp_packets)
            .map_err(|e| Status::internal(format!("Failed to depacketize: {}", e)))?;

        // Serialize NAL units
        let nal_unit_data: Vec<Vec<u8>> = nal_units.iter()
            .map(|nal| nal.data.to_vec())
            .collect();

        Ok(Response::new(DepacketizeVvcResponse {
            success: true,
            nal_units: nal_unit_data,
            error: String::new(),
        }))
    }

    // RFC 9607 - SCIP Payload Format
    async fn packetize_scip(
        &self,
        request: Request<PacketizeScipRequest>,
    ) -> Result<Response<PacketizeScipResponse>, Status> {
        let req = request.into_inner();
        
        let mut handlers = self.scip_handlers.lock().unwrap();
        let handler = handlers.entry("default".to_string())
            .or_insert_with(|| ScipPayloadHandler::new());

        // Convert proto ScipPacketType to engine type
        let packet_type = match ScipPacketType::try_from(req.packet_type) {
            Ok(ScipPacketType::ScipAudio) => EngineScipPacketType::Audio,
            Ok(ScipPacketType::ScipVideo) => EngineScipPacketType::Video,
            Ok(ScipPacketType::ScipControl) => EngineScipPacketType::Control,
            Ok(ScipPacketType::ScipFec) => EngineScipPacketType::Fec,
            Err(_) => return Err(Status::invalid_argument("Invalid SCIP packet type")),
        };

        // Create SCIP packet
        let scip_packet = ScipPacket {
            packet_type,
            sequence_number: 0, // Will be set by handler
            timestamp: req.timestamp,
            payload: Bytes::from(req.payload),
            frame_number: None,
            is_keyframe: false,
        };

        // Wrap in RTP
        let rtp_packet = handler.wrap_in_rtp(&scip_packet, req.ssrc, req.payload_type as u8)
            .map_err(|e| Status::internal(format!("Failed to wrap SCIP: {}", e)))?;

        Ok(Response::new(PacketizeScipResponse {
            success: true,
            rtp_packet: rtp_packet.serialize().to_vec(),
            error: String::new(),
        }))
    }

    async fn depacketize_scip(
        &self,
        request: Request<DepacketizeScipRequest>,
    ) -> Result<Response<DepacketizeScipResponse>, Status> {
        let req = request.into_inner();
        
        // Parse RTP packet
        let rtp_packet = RtpPacket::parse(&req.rtp_packet)
            .map_err(|e| Status::invalid_argument(format!("Failed to parse RTP packet: {}", e)))?;

        let handler = ScipPayloadHandler::new();
        let scip_packet = handler.extract_from_rtp(&rtp_packet)
            .map_err(|e| Status::internal(format!("Failed to extract SCIP: {}", e)))?;

        // Convert engine ScipPacketType to proto type
        let packet_type = match scip_packet.packet_type {
            EngineScipPacketType::Audio => ScipPacketType::ScipAudio as i32,
            EngineScipPacketType::Video => ScipPacketType::ScipVideo as i32,
            EngineScipPacketType::Control => ScipPacketType::ScipControl as i32,
            EngineScipPacketType::Fec => ScipPacketType::ScipFec as i32,
        };

        Ok(Response::new(DepacketizeScipResponse {
            success: true,
            payload: scip_packet.payload.to_vec(),
            packet_type,
            timestamp: scip_packet.timestamp,
            error: String::new(),
        }))
    }

    // RFC 4588 - RTP Retransmission
    async fn store_packet_for_retransmission(
        &self,
        request: Request<StorePacketRequest>,
    ) -> Result<Response<StorePacketResponse>, Status> {
        use std::time::Duration;

        let req = request.into_inner();
        
        // Parse RTP packet
        let rtp_packet = RtpPacket::parse(&req.rtp_packet)
            .map_err(|e| Status::invalid_argument(format!("Failed to parse RTP packet: {}", e)))?;

        let handler_key = format!("retrans_{}_{}", req.max_buffer_size, req.retransmission_payload_type);
        
        let mut handlers = self.retransmission_handlers.lock().unwrap();
        let handler = handlers.entry(handler_key)
            .or_insert_with(|| {
                RtpRetransmissionHandler::new(
                    req.max_buffer_size as usize,
                    Duration::from_secs(req.packet_timeout_sec),
                    req.retransmission_payload_type as u8,
                )
            });

        handler.store_sent_packet(rtp_packet);

        Ok(Response::new(StorePacketResponse {
            success: true,
            error: String::new(),
        }))
    }

    async fn process_retransmission_request(
        &self,
        request: Request<RetransmissionRequest>,
    ) -> Result<Response<RetransmissionResponse>, Status> {
        let req = request.into_inner();
        
        // Find handler (simplified - in production, use SSRC to find correct handler)
        let handlers = self.retransmission_handlers.lock().unwrap();
        let handler = handlers.values().next()
            .ok_or_else(|| Status::not_found("No retransmission handler found"))?;

        let engine_request = EngineRetransmissionRequest {
            ssrc: req.ssrc,
            sequence_numbers: req.sequence_numbers.iter().map(|&s| s as u16).collect(),
            timestamp: std::time::Instant::now(),
        };

        let retransmitted = handler.process_retransmission_request(&engine_request)
            .map_err(|e| Status::internal(format!("Failed to process retransmission: {}", e)))?;

        let packets: Vec<Vec<u8>> = retransmitted.iter()
            .map(|p| p.serialize().to_vec())
            .collect();

        Ok(Response::new(RetransmissionResponse {
            success: true,
            retransmission_packets: packets,
            error: String::new(),
        }))
    }

    async fn detect_missing_sequences(
        &self,
        request: Request<DetectMissingRequest>,
    ) -> Result<Response<DetectMissingResponse>, Status> {
        let req = request.into_inner();
        
        // Find handler (simplified - in production, use SSRC to find correct handler)
        let handlers = self.retransmission_handlers.lock().unwrap();
        let handler = handlers.values().next()
            .ok_or_else(|| Status::not_found("No retransmission handler found"))?;

        let missing = handler.detect_missing_sequences(req.expected_sequence as u16);

        Ok(Response::new(DetectMissingResponse {
            success: true,
            missing_sequences: missing.iter().map(|&s| s as u32).collect(),
            error: String::new(),
        }))
    }
}

