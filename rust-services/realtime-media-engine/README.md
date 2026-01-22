# Realtime Media Engine

Real-time media engine for ArcRTC protocol with RTP/SRTP support.

## Overview

This crate provides the core media transport layer for ArcRTC, including:

- **RTP packet parsing and construction** - RFC 3550 compliant
- **SRTP encryption/decryption** - RFC 3711 compliant (AES-128-GCM)
- **Stream management** - Lifecycle and state tracking
- **Jitter buffer** - Adaptive buffering for network jitter
- **Packet loss concealment** - Basic PLC for audio/video

## Implementation Status

### Phase 1: Foundation + Basic VoIP ✅
- ✅ Basic RTP/SRTP pipeline
- ✅ Stream lifecycle management
- ✅ Basic jitter buffer (adaptive)
- ✅ Basic packet loss concealment
- ✅ Integration with `armoricore-keys` (key management)
- ✅ VoIP-optimized audio pipeline (interface ready)

### Phase 2: Reliability & Quality ✅
- ✅ Forward Error Correction (FEC)
- ✅ Selective Retransmission (NACK)
- ✅ Echo cancellation
- ✅ Noise suppression
- ✅ Automatic Gain Control (AGC)
- ✅ Connection health monitoring

### Phase 3: Network Adaptation ✅
- ✅ Advanced bandwidth estimation
- ✅ Congestion control
- ✅ Network-aware codec selection
- ✅ Packet routing
- ✅ Load balancing

### Phase 4: Video Support ✅
- ✅ Video pipeline (H.264, VP9, AV1)
- ✅ Video resolutions (360p to 8K)
- ✅ Enhanced video PLC (frame freezing, interpolation)
- ✅ Adaptive bitrate controller
- ✅ Dynamic resolution adjustment

## Architecture

```
┌─────────────────────────────────────┐
│      Stream Manager                 │
│  • Stream lifecycle                 │
│  • State tracking                   │
│  • SSRC management                  │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┐
       │                │
┌──────▼──────┐  ┌──────▼──────┐
│ RTP Handler │  │ SRTP Pipeline│
│ • Parse     │  │ • Encrypt     │
│ • Serialize │  │ • Decrypt     │
└─────────────┘  └──────────────┘
       │                │
       └───────┬────────┘
               │
       ┌───────▼────────┐
       │ Jitter Buffer  │
       │ • Adaptive     │
       │ • Reordering   │
       └────────────────┘
```

## Usage

### Basic RTP Packet Handling

```rust
use realtime_media_engine::{RtpPacket, RtpHeader};

// Parse RTP packet
let data: &[u8] = /* RTP packet bytes */;
let packet = RtpPacket::parse(data)?;

// Access header fields
println!("Sequence: {}", packet.header.sequence_number);
println!("SSRC: {}", packet.header.ssrc);

// Serialize packet
let serialized = packet.serialize();
```

### SRTP Encryption/Decryption

```rust
use realtime_media_engine::{SrtpPipeline, SrtpConfig};

// Create SRTP configuration
let config = SrtpConfig {
    master_key: vec![0u8; 16],  // 16 bytes for AES-128
    master_salt: vec![0u8; 14], // 14 bytes
    ssrc: 12345,
    roc: 0,
};

// Create pipeline
let pipeline = SrtpPipeline::new(config)?;

// Encrypt RTP packet
let encrypted = pipeline.encrypt(&packet)?;

// Decrypt SRTP packet
let decrypted = pipeline.decrypt(&encrypted)?;
```

### Stream Management

```rust
use realtime_media_engine::{StreamManager, StreamConfig, MediaType};
use uuid::Uuid;

let mut manager = StreamManager::new();

// Create stream
let config = StreamConfig {
    user_id: Uuid::new_v4(),
    media_type: MediaType::Audio,
    ssrc: 12345,
    payload_type: 96,
    codec: "opus".to_string(),
    bitrate: 32000,
    srtp_config: None, // Or Some(srtp_config) for encryption
};

let stream_id = manager.create_stream(config)?;

// Get stream
let stream = manager.get_stream(&stream_id)?;

// Update state
manager.update_stream_state(&stream_id, StreamState::Active)?;

// Remove stream
manager.remove_stream(&stream_id)?;
```

### Jitter Buffer

```rust
use realtime_media_engine::{JitterBuffer, JitterBufferConfig};

// Create jitter buffer
let config = JitterBufferConfig {
    min_latency_ms: 10,
    max_latency_ms: 100,
    initial_latency_ms: 20,
    adaptive: true,
};

let mut buffer = JitterBuffer::new(config);

// Push packets
buffer.push(packet)?;

// Pop ready packets
while let Some(packet) = buffer.pop() {
    // Process packet
}

// Adapt to network conditions
let metrics = NetworkMetrics {
    packet_loss_rate: 0.01,
    jitter_ms: 15.0,
    rtt_ms: 50.0,
};
buffer.adapt(&metrics);
```

### Key Management Integration

```rust
use realtime_media_engine::{SrtpKeyManager, SrtpPipeline};
use armoricore_keys::{KeyStore, local_store::LocalKeyStore};
use uuid::Uuid;

// Create key store
let local_store = LocalKeyStore::new(&storage_path, None).await?;
let key_store = Arc::new(KeyStore::new(Arc::new(local_store)));

// Create key manager
let key_manager = SrtpKeyManager::new(key_store);

// Generate and store session keys
let session_id = Uuid::new_v4();
let (key_id, salt_id) = key_manager.create_session_keys(&session_id, 12345).await?;

// Create SRTP pipeline from stored keys
let pipeline = key_manager.create_srtp_pipeline(&session_id, 12345, 0).await?;

// Cleanup (delete keys when done)
key_manager.delete_session_keys(&session_id).await?;
```

### Video Pipeline

```rust
use realtime_media_engine::{VideoPipeline, VideoConfig, VideoCodec, VideoResolution, VideoFrame};

// Create video pipeline
let config = VideoConfig {
    codec: VideoCodec::H264,
    bitrate: 2_000_000,  // 2 Mbps
    resolution: VideoResolution::P1080,
    frame_rate: 30,
    keyframe_interval: 30,
    adaptive_bitrate: true,
};
let mut pipeline = VideoPipeline::new(config)?;

// Encode video frame
let frame = VideoFrame {
    data: vec![0u8; 1920 * 1080 * 3], // RGB frame
    width: 1920,
    height: 1080,
    timestamp: 1000,
    is_keyframe: false,
    frame_number: 1,
};
let encoded = pipeline.encode(&frame)?;

// Create RTP packet
let packet = pipeline.create_rtp_packet(encoded, 1, 1000, 12345, 97, false)?;

// Decode video frame
let decoded = pipeline.decode(&packet.payload, packet.header.timestamp)?;
```

### Adaptive Bitrate for Video

```rust
use realtime_media_engine::{
    AdaptiveBitrateController, AdaptiveBitrateConfig,
    VideoPipeline, VideoConfig, VideoResolution,
};
use realtime_media_engine::connection_health::NetworkMetrics;

// Create adaptive bitrate controller
let config = AdaptiveBitrateConfig::default();
let mut controller = AdaptiveBitrateController::new(
    config,
    2_000_000,  // Initial bitrate
    VideoResolution::P1080,  // Initial resolution
);

// Update with network metrics
let metrics = NetworkMetrics {
    rtt_ms: 100.0,
    packet_loss_rate: 0.02,
    jitter_ms: 20.0,
    bandwidth_kbps: 3000.0,
    timestamp: std::time::Instant::now(),
};
controller.update_metrics(&metrics);

// Adjust bitrate/resolution based on network
let adjusted = controller.adjust(&mut pipeline)?;
if adjusted {
    println!("Bitrate: {} bps", controller.current_bitrate());
    println!("Resolution: {:?}", controller.current_resolution());
}
```

### Video Packet Loss Concealment

```rust
use realtime_media_engine::packet_loss_concealment::{VideoPlc, VideoPlcConfig};

let config = VideoPlcConfig {
    enabled: true,
    max_conceal_packets: 5,
    enable_interpolation: true,
    enable_motion_compensation: false,
};
let mut plc = VideoPlc::new(config);

// Process received packet
plc.process_packet(&packet)?;

// Conceal lost packet
if let Some(concealed) = plc.conceal(expected_sequence)? {
    // Use concealed frame
}

// Check if keyframe is needed
if plc.needs_keyframe() {
    // Request keyframe from encoder
}
```

### VoIP Audio Pipeline

```rust
use realtime_media_engine::{AudioPipeline, AudioConfig, AudioFrame};

// Create VoIP-optimized audio pipeline
let mut pipeline = AudioPipeline::voip_optimized();
// Or with custom config:
// let config = AudioConfig {
//     codec: "opus".to_string(),
//     bitrate: 32000,      // 32 kbps
//     sample_rate: 16000,  // 16 kHz
//     channels: 1,         // Mono
//     frame_size_ms: 20,   // 20ms frames
//     dtx: true,
//     fec: true,
//     plc: true,
// };
// let mut pipeline = AudioPipeline::new(config)?;

// Create audio frame (320 samples for 20ms at 16kHz)
let samples: Vec<f32> = /* PCM samples */;
let frame = AudioFrame {
    samples,
    sample_rate: 16000,
    channels: 1,
    timestamp: 1000,
};

// Encode to Opus (placeholder in Phase 1, full implementation in Phase 2)
let encoded = pipeline.encode(&frame)?;

// Create RTP packet
let packet = pipeline.create_rtp_packet(encoded, 1, 1000, 12345, 96, false)?;

// Decode from RTP packet
let decoded_frame = pipeline.extract_audio_frame(&packet)?;
```

## Testing

Run tests:

```bash
cargo test --package realtime-media-engine
```

## Dependencies

- `armoricore-keys` - Key management integration
- `ring` - Cryptographic operations (AES-GCM, HMAC)
- `hkdf` - Key derivation (HKDF-SHA256)
- `bytes` - Efficient byte buffer handling
- `uuid` - Stream identification

## Roadmap

### Phase 1 (Current)
- [x] RTP packet parsing
- [x] SRTP encryption/decryption
- [x] Stream management
- [x] Basic jitter buffer
- [x] Basic packet loss concealment
- [x] Integration with `armoricore-keys`
- [x] VoIP-optimized audio pipeline (interface ready)
- [x] Full Opus encoding/decoding (Phase 2) ✅
- [x] Elixir bridge (gRPC) ✅

### Phase 2 ✅
- [x] Forward Error Correction (FEC)
- [x] Selective Retransmission (NACK)
- [x] Enhanced PLC
- [x] Echo cancellation
- [x] Noise suppression
- [x] Automatic Gain Control (AGC)
- [x] Connection health monitoring

### Phase 3 ✅
- [x] Advanced bandwidth estimation (loss-based, delay-based, hybrid)
- [x] Congestion control (AIMD algorithm)
- [x] Network-aware codec selection
- [x] Packet routing infrastructure
- [x] Load balancing (round-robin & quality-based)

### Phase 4 ✅
- [x] Video support (H.264, VP9, AV1)
- [x] Video PLC (frame freezing, interpolation)
- [x] Adaptive bitrate for video

## License

Apache 2.0

