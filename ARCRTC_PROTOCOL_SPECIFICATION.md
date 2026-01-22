# ArcRTC Protocol Specification

## Overview

**ArcRTC** (Armoricore Real-Time Communication) is a high-performance, low-latency media transport protocol designed for various use cases and complement WebRTC. ArcRTC is optimized for:

- **Ultra-low latency** (< 50ms end-to-end)
- **High performance** (minimal overhead)
- **Full control** (packet-level optimization)
- **Native platforms** (mobile, desktop, embedded)
- **Hybrid compatibility** (works alongside WebRTC)

---

## Protocol Design Philosophy

### Core Principles

1. **Performance First** - Every design decision prioritizes low latency and high throughput
2. **Simplicity** - Simpler than WebRTC where possible, without sacrificing features
3. **Flexibility** - Extensible for future requirements
4. **Security** - Built-in encryption and authentication
5. **Compatibility** - Can interoperate with WebRTC when needed

### Key Differentiators from WebRTC

| Feature | WebRTC | ArcRTC |
|---------|--------|--------|
| **Latency** | 100-200ms typical | < 50ms target |
| **Overhead** | Browser stack | Minimal native |
| **Control** | Browser-managed | Full packet control |
| **Codecs** | Browser-supported only | Any codec |
| **Buffering** | Browser-controlled | Adaptive, minimal |
| **Platform** | Browser-first | Native-first |
| **Complexity** | High (ICE, SDP, etc.) | Simplified signaling |

---

## Protocol Architecture

### Layer Structure

```
┌─────────────────────────────────────────────────────────┐
│              Application Layer                          │
│  • Media encoding/decoding                              │
│  • Application logic                                    │
└─────────────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────────────┐
│              ArcRTC Protocol Layer                      │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Signaling Protocol (ArcSignaling)               │   │
│  │  • Connection establishment                      │   │
│  │  • Stream negotiation                            │   │
│  │  • Quality adaptation                            │   │
│  └──────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Media Transport (ArcMedia)                      │   │
│  │  • ArcRTP (Enhanced RTP)                         │   │
│  │  • ArcSRTP (Secure RTP)                          │   │
│  │  • Packet routing                                │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────────────┐
│              Transport Layer                            │
│  • UDP (primary)                                        │
│  • TCP (fallback)                                       │
│  • QUIC (future)                                        │
└─────────────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────────────┐
│              Network Layer                              │
│  • IP                                                   │
└─────────────────────────────────────────────────────────┘
```

---

## ArcSignaling Protocol

### Purpose

Simplified signaling protocol for connection establishment and stream management. More efficient than WebRTC's SDP/ICE approach.

### Message Types

#### 1. Connection Request (`CONNECT`)

**Purpose:** Initiate connection between peers

**Format:**
```json
{
  "type": "CONNECT",
  "version": "1.0",
  "session_id": "uuid",
  "peer_id": "uuid",
  "capabilities": {
    "codecs": ["opus", "vp9", "h264"],
    "resolutions": ["1080p", "720p", "480p"],
    "encryption": ["aes-128-gcm", "aes-256-gcm"],
    "transport": ["udp", "tcp"]
  },
  "network_info": {
    "public_ip": "1.2.3.4",
    "public_port": 50000,
    "nat_type": "cone" | "symmetric" | "restricted"
  },
  "timestamp": 1234567890
}
```

#### 2. Connection Response (`CONNECT_ACK`)

**Purpose:** Accept connection and provide peer information

**Format:**
```json
{
  "type": "CONNECT_ACK",
  "session_id": "uuid",
  "peer_id": "uuid",
  "accepted": true,
  "selected_codecs": {
    "audio": "opus",
    "video": "vp9"
  },
  "network_info": {
    "public_ip": "5.6.7.8",
    "public_port": 50001,
    "relay_servers": [
      {
        "id": "relay-1",
        "address": "relay.example.com",
        "port": 3478,
        "priority": 1
      }
    ]
  },
  "encryption": {
    "algorithm": "aes-128-gcm",
    "key_exchange": "ecdh-p256"
  },
  "timestamp": 1234567891
}
```

#### 3. Stream Start (`STREAM_START`)

**Purpose:** Start a media stream

**Format:**
```json
{
  "type": "STREAM_START",
  "session_id": "uuid",
  "stream_id": "uuid",
  "stream_type": "audio" | "video" | "both",
  "codec": {
    "audio": {
      "name": "opus",
      "bitrate": 128000,
      "sample_rate": 48000,
      "channels": 2
    },
    "video": {
      "name": "vp9",
      "bitrate": 2000000,
      "width": 1920,
      "height": 1080,
      "fps": 30
    }
  },
  "ssrc": 12345678,
  "encryption": {
    "key_id": "uuid",
    "algorithm": "aes-128-gcm"
  },
  "timestamp": 1234567892
}
```

#### 4. Stream Stop (`STREAM_STOP`)

**Purpose:** Stop a media stream

**Format:**
```json
{
  "type": "STREAM_STOP",
  "session_id": "uuid",
  "stream_id": "uuid",
  "reason": "user_request" | "error" | "timeout",
  "timestamp": 1234567893
}
```

#### 5. Quality Adaptation (`QUALITY_ADAPT`)

**Purpose:** Request quality change

**Format:**
```json
{
  "type": "QUALITY_ADAPT",
  "session_id": "uuid",
  "stream_id": "uuid",
  "quality": {
    "bitrate": 1000000,
    "resolution": "720p",
    "fps": 30
  },
  "reason": "bandwidth" | "cpu" | "network",
  "timestamp": 1234567894
}
```

#### 6. Heartbeat (`HEARTBEAT`)

**Purpose:** Keep connection alive and measure latency

**Format:**
```json
{
  "type": "HEARTBEAT",
  "session_id": "uuid",
  "sequence": 12345,
  "timestamp": 1234567895
}
```

#### 7. Heartbeat Response (`HEARTBEAT_ACK`)

**Purpose:** Respond to heartbeat with latency measurement

**Format:**
```json
{
  "type": "HEARTBEAT_ACK",
  "session_id": "uuid",
  "sequence": 12345,
  "original_timestamp": 1234567895,
  "response_timestamp": 1234567896,
  "latency_ms": 1
}
```

### Signaling Transport

**Options:**
1. **WebSocket** (primary) - Over existing Phoenix channels
2. **TCP** (fallback) - Direct TCP connection
3. **Message Bus** (server-side) - NATS for server coordination

### Key Exchange

**Protocol:** ECDH P-256 (same as WebRTC DTLS)

**Flow:**
1. Client A generates key pair, sends public key in `CONNECT`
2. Client B generates key pair, sends public key in `CONNECT_ACK`
3. Both derive shared secret using ECDH
4. Derive media encryption keys using HKDF-SHA256
5. Rotate keys every 24 hours or 2^31 packets

---

## ArcMedia Protocol

### ArcRTP (Enhanced RTP)

**Base:** Standard RTP (RFC 3550) with enhancements

#### Packet Format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|CC|M|PT |       Sequence Number         | Timestamp     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             SSRC                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            CSRC (optional)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Extension Header (optional)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload Data                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Enhancements Over Standard RTP

1. **Reduced Header** (optional)
   - Minimal header for low-latency paths
   - 4 bytes instead of 12 bytes
   - Only: sequence, timestamp, SSRC

2. **Quality Indicator**
   - 2-bit quality field in header
   - Allows rapid quality switching
   - No signaling required

3. **Latency Metadata**
   - Absolute send time in extension
   - Receive time tracking
   - Jitter calculation

4. **Packet Priority**
   - 2-bit priority field
   - Audio > Video keyframes > Video delta
   - Router can prioritize

#### ArcRTP Header Fields

| Field | Bits | Description |
|-------|------|-------------|
| V | 2 | Version (always 2) |
| P | 1 | Padding |
| X | 1 | Extension |
| CC | 4 | CSRC count |
| M | 1 | Marker |
| PT | 7 | Payload type |
| Q | 2 | **Quality indicator (NEW)** |
| PR | 2 | **Priority (NEW)** |
| Sequence | 16 | Sequence number |
| Timestamp | 32 | Timestamp (90kHz for video) |
| SSRC | 32 | Synchronization source |

### ArcSRTP (Secure RTP)

**Base:** SRTP (RFC 3711) with optimizations

#### Encryption

**Default:** AES-128-GCM
**Optional:** AES-256-GCM, ChaCha20-Poly1305

**Key Derivation:**
```
master_key = HKDF-SHA256(shared_secret, "arcrtc-media-key", session_id)
encryption_key = HKDF-SHA256(master_key, "arcrtc-enc", stream_id)
auth_key = HKDF-SHA256(master_key, "arcrtc-auth", stream_id)
salt = HKDF-SHA256(master_key, "arcrtc-salt", stream_id)
```

#### Authentication

**Algorithm:** HMAC-SHA256 (truncated to 80 bits)

**Replay Protection:**
- 64-bit sequence window
- Automatic replay detection
- Configurable window size

#### Key Rotation

**Triggers:**
- Every 24 hours
- Every 2^31 packets
- On security event
- Manual rotation

**Process:**
1. Generate new key pair
2. Send key rotation message
3. Use new key for next packet
4. Keep old key for 1 second (packet reordering)

---

## Connection Establishment

### Simplified Flow (vs WebRTC ICE)

```
Client A                          Server                          Client B
   │                                 │                               │
   │─── CONNECT ────────────────────▶│                               │
   │                                 │─── CONNECT ──────────────────▶│
   │                                 │                               │
   │◀── CONNECT_ACK ─────────────────│                               │
   │                                 │◀── CONNECT_ACK ───────────────│
   │                                 │                               │
   │─── STREAM_START ────────────────▶│─── STREAM_START ────────────▶│
   │                                 │                               │
   │◀── STREAM_START ────────────────│◀── STREAM_START ──────────────│
   │                                 │                               │
   │═══════════════════════════════════════════════════════════════  │
   │                    Media Packets (ArcRTP)                       │
   │═══════════════════════════════════════════════════════════════  │
```

### NAT Traversal

**Strategy:** Simplified vs WebRTC ICE

1. **Direct Connection Attempt**
   - Try direct UDP connection
   - Use public IPs from signaling

2. **Relay Fallback**
   - If direct fails, use relay server
   - Relay server from `CONNECT_ACK`
   - Automatic failover

3. **TCP Fallback**
   - If UDP fails, try TCP
   - Higher latency but more reliable

**No Complex ICE:** Simpler than WebRTC's candidate gathering/checking

---

## Quality Adaptation

### Automatic Adaptation

**Metrics:**
- Packet loss rate
- Round-trip time
- Jitter
- Available bandwidth
- CPU usage

**Adaptation Algorithm:**

```rust
fn adapt_quality(metrics: &QualityMetrics) -> QualityLevel {
    if metrics.packet_loss > 0.05 || metrics.rtt > 100 {
        // Degrade quality
        QualityLevel::Lower
    } else if metrics.packet_loss < 0.01 && metrics.rtt < 50 && metrics.cpu < 0.5 {
        // Improve quality
        QualityLevel::Higher
    } else {
        // Maintain current quality
        QualityLevel::Current
    }
}
```

### Quality Levels

| Level | Video | Audio | Bitrate (Video) | Bitrate (Audio) |
|-------|-------|-------|----------------|-----------------|
| **Ultra** | 1080p@60fps | Opus 192k | 5 Mbps | 192 kbps |
| **High** | 1080p@30fps | Opus 128k | 3 Mbps | 128 kbps |
| **Medium** | 720p@30fps | Opus 96k | 1.5 Mbps | 96 kbps |
| **Low** | 480p@30fps | Opus 64k | 800 kbps | 64 kbps |
| **Very Low** | 360p@24fps | Opus 48k | 400 kbps | 48 kbps |

### Rapid Quality Switching

**Method:** Quality indicator in ArcRTP header

- No signaling required
- Switch within 1 packet
- Seamless quality changes

---

## Performance Optimizations

### 1. Zero-Copy Packet Processing

**Strategy:** Minimize memory copies

```rust
// Direct buffer access, no copying
fn process_packet(buffer: &[u8]) -> Result<()> {
    let rtp = ArcRtp::parse_in_place(buffer)?; // No copy
    route_packet(rtp)?; // Direct reference
    Ok(())
}
```

### 2. Batch Processing

**Strategy:** Process multiple packets together

```rust
fn process_packet_batch(packets: &[ArcRtpPacket]) -> Result<()> {
    // Batch encryption
    encrypt_batch(packets)?;
    // Batch routing
    route_batch(packets)?;
    Ok(())
}
```

### 3. Lock-Free Data Structures

**Strategy:** Use lock-free queues for packet routing

```rust
use crossbeam::channel;

let (tx, rx) = channel::unbounded();
// Lock-free packet queue
```

### 4. SIMD Optimizations

**Strategy:** Use SIMD for encryption/decryption

```rust
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

fn encrypt_simd(data: &mut [u8]) {
    // SIMD-accelerated AES-GCM
}
```

### 5. Pre-allocated Buffers

**Strategy:** Reuse buffers to avoid allocations

```rust
struct PacketPool {
    buffers: Vec<Vec<u8>>,
}

impl PacketPool {
    fn get_buffer(&mut self) -> &mut Vec<u8> {
        // Reuse existing buffer
    }
}
```

---

## Security

### Encryption

**Media:** ArcSRTP (AES-128-GCM default)
**Signaling:** TLS 1.3 (WebSocket) or DTLS 1.3 (UDP)

### Authentication

**Method:** HMAC-SHA256 for packet authentication
**Key Exchange:** ECDH P-256
**Certificate:** Self-signed or CA-signed

### Replay Protection

**Method:** 64-bit sequence window
**Window Size:** Configurable (default 64 packets)

### Key Management

**Storage:** `armoricore-keys` integration
**Rotation:** Every 24 hours or 2^31 packets
**Forward Secrecy:** Supported via key rotation

---

## Interoperability with WebRTC

### Hybrid Mode

**Strategy:** Support both protocols simultaneously

#### Client Selection

```rust
enum TransportProtocol {
    WebRTC,
    ArcRTC,
    Hybrid, // Use both, fallback
}

fn select_protocol(capabilities: &ClientCapabilities) -> TransportProtocol {
    if capabilities.supports_arcrtc && capabilities.native_platform {
        TransportProtocol::ArcRTC
    } else if capabilities.supports_webrtc {
        TransportProtocol::WebRTC
    } else {
        TransportProtocol::Hybrid
    }
}
```

#### Protocol Translation

**ArcRTC → WebRTC:**
- Convert ArcRTP to RTP
- Map codecs
- Translate signaling

**WebRTC → ArcRTC:**
- Convert RTP to ArcRTP
- Map codecs
- Translate signaling

### Signaling Bridge

**Purpose:** Allow WebRTC and ArcRTC clients to communicate

**Implementation:**
- Server-side translation
- Protocol conversion
- Codec transcoding (if needed)

---

## Codec Support

### Audio Codecs

| Codec | Bitrate Range | Latency | Quality |
|-------|---------------|---------|---------|
| **Opus** | 6-510 kbps | Low | Excellent |
| **AAC** | 32-320 kbps | Medium | Good |
| **G.722** | 64 kbps | Low | Good |
| **PCM** | 128-1536 kbps | Very Low | Perfect |

### Video Codecs

| Codec | Bitrate Range | Latency | Quality |
|-------|---------------|---------|---------|
| **VP9** | 500-8000 kbps | Low | Excellent |
| **H.264** | 500-10000 kbps | Medium | Good |
| **AV1** | 400-6000 kbps | Low | Excellent |
| **H.265/HEVC** | 300-5000 kbps | Medium | Excellent |

**Priority:** Opus + VP9 for best latency/quality balance

---

## Latency Targets

### End-to-End Latency Budget

| Component | Target | Maximum |
|-----------|--------|---------|
| **Encoding** | 10ms | 20ms |
| **Network** | 20ms | 50ms |
| **Routing** | 1ms | 5ms |
| **Decoding** | 10ms | 20ms |
| **Buffering** | 5ms | 10ms |
| **Total** | **< 50ms** | **< 100ms** |

### Jitter Buffer

**Initial:** 10ms
**Adaptive:** 5-30ms
**Maximum:** 50ms

---

## Error Handling

### Packet Loss

**Strategy:**
1. Detect via sequence gaps
2. Request retransmission (if critical)
3. Adapt quality if loss > threshold
4. Use FEC (Forward Error Correction) for keyframes

### Network Errors

**Strategy:**
1. Automatic retry with exponential backoff
2. Fallback to relay server
3. Switch to TCP if UDP fails
4. Graceful degradation

### Connection Errors

**Strategy:**
1. Automatic reconnection
2. State preservation
3. Seamless recovery
4. User notification

---

## Monitoring & Metrics

### Key Metrics

1. **Latency**
   - End-to-end latency (P50, P95, P99)
   - One-way latency
   - Jitter

2. **Quality**
   - Packet loss rate
   - Bitrate
   - Resolution/FPS
   - Codec efficiency

3. **Performance**
   - Packets per second
   - Bytes per second
   - CPU usage
   - Memory usage

4. **Network**
   - Round-trip time
   - Bandwidth utilization
   - Connection quality
   - NAT type

### Reporting

**Format:** JSON metrics sent to server
**Frequency:** Every 5 seconds
**Transport:** Signaling channel or separate metrics channel

---

## Implementation Roadmap

### Phase 1: Core Protocol (Weeks 1-4)
- ArcSignaling protocol
- ArcRTP packet format
- Basic connection establishment
- Unit tests

### Phase 2: Security (Weeks 5-6)
- ArcSRTP encryption
- Key exchange
- Authentication
- Security tests

### Phase 3: Quality & Routing (Weeks 7-10)
- Quality adaptation
- Packet routing
- Load balancing
- Performance optimization

### Phase 4: Integration (Weeks 11-12)
- Elixir signaling integration
- WebRTC interoperability
- Hybrid mode
- End-to-end tests

### Phase 5: Optimization (Weeks 13-16)
- Latency optimization
- Performance tuning
- Load testing
- Production hardening

---

## Comparison: ArcRTC vs WebRTC

| Feature | WebRTC | ArcRTC |
|---------|--------|--------|
| **Latency** | 100-200ms | < 50ms |
| **Signaling** | SDP/ICE (complex) | ArcSignaling (simple) |
| **Overhead** | Browser stack | Minimal native |
| **Control** | Limited | Full |
| **Codecs** | Browser-supported | Any |
| **Platform** | Browser-first | Native-first |
| **Complexity** | High | Medium |
| **Ecosystem** | Large | Growing |
| **Interoperability** | Standard | Hybrid mode |

---

## Conclusion

ArcRTC is designed to be:

1. **Faster** - Lower latency, higher performance
2. **Simpler** - Easier to implement and maintain
3. **More Flexible** - Full control, any codec
4. **Compatible** - Works with WebRTC when needed

**Best Use Cases:**
- Native mobile/desktop apps
- Ultra-low latency requirements
- High-performance scenarios
- Custom codec needs
- Full control requirements

**Hybrid Approach:**
- Use ArcRTC for native clients
- Use WebRTC for browser clients
- Server-side translation for interoperability
- Best of both worlds

---

**Protocol Version:** 1.0  
**Last Updated:** 2026-01-22 
**Status:** Specification (Implementation in progress)

