# Armoricore Architecture Plan

## Table of Contents

1. [System Overview](#system-overview)
2. [Architectural Principles](#architectural-principles)
3. [Component Architecture](#component-architecture)
4. [Communication Patterns](#communication-patterns)
5. [Data Flow](#data-flow)
6. [Technology Stack](#technology-stack)
7. [Deployment Architecture](#deployment-architecture)
8. [Scalability Strategy](#scalability-strategy)
9. [Security Architecture](#security-architecture)
10. [Monitoring and Observability](#monitoring-and-observability)
11. [Error Handling and Resilience](#error-handling-and-resilience)
12. [Future Considerations](#future-considerations)

---

## System Overview

Armoricore is a distributed, event-driven backend platform designed to handle:

- **Media Processing**: Video transcoding, segmentation, thumbnail generation
- **Real-Time Communication**: WebSocket-based chat, live comments, presence tracking
- **AI Workflows**: Transcription, captioning, and AI-based processing

The system is built on a **hybrid architecture** combining Rust and Elixir, each optimized for their respective strengths.

---

## Architectural Principles

### 1. **Separation of Concerns**
- Rust handles CPU-intensive, batch-oriented tasks
- Elixir handles high-concurrency, real-time communication
- Clear boundaries via message bus communication

### 2. **Event-Driven Architecture**
- All inter-service communication via message bus
- Loose coupling between components
- Asynchronous processing by default

### 3. **Horizontal Scalability**
- Stateless services enable easy scaling
- Message bus supports distributed processing
- Phoenix PubSub enables multi-node real-time distribution

### 4. **Fault Tolerance**
- Elixir OTP supervision trees for automatic recovery
- Rust services with retry mechanisms and dead-letter queues
- Message bus persistence for event durability

### 5. **Performance Optimization**
- Rust for zero-cost abstractions and memory safety
- Elixir for lightweight concurrency (millions of connections)
- Efficient resource utilization per service type

---

## Component Architecture

### Rust Services Layer

```
┌─────────────────────────────────────────────────────────┐
│                    Rust Services                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │    Media     │  │ Notification │  │      AI      │   │
│  │  Processor   │  │   Worker     │  │   Workers    │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│         │                 │                 │           │
│         └─────────────────┴─────────────────┘           │
│                         │                               │
│              ┌──────────▼──────────┐                    │
│              │  Message Bus Client │                    │
│              │  (NATS/RabbitMQ)    │                    │
│              └─────────────────────┘                    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### Media Processor

**Responsibilities:**
- Consume `media.uploaded` events
- Execute FFmpeg workflows (transcoding, segmentation)
- Generate thumbnails and metadata
- Upload processed files to object storage (S3-compatible)
- Publish `media.ready` events

**Key Libraries:**
- `tokio` - Async runtime
- `ffmpeg-next` or `ffmpeg-sys` - FFmpeg bindings
- `aws-sdk-s3` or `rusoto_s3` - Object storage
- `async-nats` or `lapin` - Message bus client

**Processing Pipeline:**
```
media.uploaded → Validate → Transcode → Segment → Thumbnail → Upload → media.ready
```

#### AI/Captioning Workers

**Responsibilities:**
- Consume `transcription.requested` events
- Perform speech-to-text transcription
- Generate captions/subtitles
- Publish `transcription.complete` events

**Key Libraries:**
- `tokio` - Async runtime
- AI/ML libraries (OpenAI API, Whisper, etc.)
- `async-nats` or `lapin` - Message bus client

---

### Elixir Phoenix Realtime Server

```
┌─────────────────────────────────────────────────────────┐
│              Elixir Phoenix Application                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Phoenix Endpoint                    │   │
│  │         (WebSocket Connections)                  │   │
│  └──────────────────┬───────────────────────────────┘   │
│                     │                                   │
│  ┌──────────────────▼───────────────────────────────┐   │
│  │              Phoenix Channels                    │   │
│  │  - Chat Channel                                  │   │
│  │  - Live Comments Channel                         │   │
│  │  - Presence Channel                              │   │
│  └──────────────────┬───────────────────────────────┘   │
│                     │                                   │
│  ┌──────────────────▼───────────────────────────────┐   │
│  │              Phoenix PubSub                      │   │
│  │         (Distributed Pub/Sub)                    │   │
│  └──────────────────┬───────────────────────────────┘   │
│                     │                                   │
│  ┌──────────────────▼───────────────────────────────┐   │
│  │         Message Bus Subscriber                   │   │
│  │         (NATS/RabbitMQ Client)                   │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### Phoenix Channels

**Chat Channel:**
- Handles real-time chat messages
- Broadcasts via PubSub to all connected clients
- Validates JWT tokens on connect
- Publishes `chat.message` events to message bus (for moderation)

**Live Comments Channel:**
- Handles live streaming comments
- High-frequency message broadcasting
- Rate limiting per user
- Presence tracking

**Presence Channel:**
- Tracks user presence (online/offline)
- Broadcasts presence changes
- Integrates with chat and comments

#### Message Bus Integration

**Subscriptions:**
- `media.ready` → Broadcast to relevant channels
- `transcription.complete` → Broadcast caption availability

**Publishing:**
- `chat.message` → For moderation workflows
- `presence.update` → For analytics

---

## Communication Patterns

### Message Bus Architecture

```
┌─────────────┐
│   PHP API   │───Publish───┐
└─────────────┘             │
                            ▼
                    ┌──────────────┐
                    │ Message Bus  │
                    │ (NATS/Rabbit)│
                    └──────────────┘
                            ▲
        ┌───────────────────┴───────────────────┐
        │                                       │
        ▼                                       ▼
┌──────────────┐                        ┌──────────────┐
│ Rust Services│                        │   Elixir     │
│  (Consumers) │                        │  (Subscriber)│
└──────────────┘                        └──────────────┘
```

### Event Schema

#### Event Structure

```json
{
  "event_type": "media.uploaded",
  "event_id": "uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "source": "php-backend",
  "payload": {
    "media_id": "uuid",
    "user_id": "uuid",
    "file_path": "s3://bucket/key",
    "metadata": {}
  }
}
```

#### Event Types

| Event Type | Publisher | Consumers | Description |
|------------|-----------|-----------|-------------|
| `media.uploaded` | PHP | Rust Media Processor | New media file uploaded |
| `media.ready` | Rust | Elixir, PHP | Media processing complete |
| `chat.message` | Elixir | Rust (optional) | Chat message for moderation |
| `presence.update` | Elixir | Analytics | User presence change |
| `transcription.requested` | PHP | Rust AI Workers | Transcription needed |
| `transcription.complete` | Rust | Elixir, PHP | Transcription ready |

---

## Data Flow

### Media Upload to Playback Flow

```
┌─────────┐     ┌─────────┐     ┌──────────┐     ┌─────────┐     ┌─────────┐
│  User   │────▶│   PHP   │────▶│ Message  │────▶│  Rust   │────▶│ Object  │
│ Browser │     │ Backend │     │   Bus    │     │  Media  │     │ Storage │
└─────────┘     └─────────┘     └──────────┘     └─────────┘     └─────────┘
     │                                                                    │
     │                                                                    │
     └────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
                         ┌─────────┐
                         │ Elixir  │
                         │ Phoenix │
                         └─────────┘
                              │
                              ▼
                         ┌─────────┐
                         │  Users  │
                         │ (WS)    │
                         └─────────┘
```

**Detailed Steps:**

1. **Upload Initiation**
   - User requests upload → PHP generates presigned URL
   - User uploads directly to object storage

2. **Event Publication**
   - PHP publishes `media.uploaded` event to message bus
   - Event includes: `media_id`, `user_id`, `file_path`, `metadata`

3. **Media Processing**
   - Rust Media Processor consumes event
   - Validates file, starts FFmpeg transcoding
   - Generates multiple bitrate variants
   - Creates HLS segments
   - Generates thumbnails
   - Uploads all outputs to object storage

4. **Completion Notification**
   - Rust publishes `media.ready` event
   - Includes: `media_id`, `playback_urls`, `thumbnail_urls`

5. **Real-Time Broadcast**
   - Elixir subscribes to `media.ready`
   - Broadcasts to relevant WebSocket channels

6. **CDN Delivery**
   - Akamai CDN serves processed segments
   - Users can start playback immediately

### Notification Flow

```
┌─────────┐     ┌─────────┐     ┌──────────┐     ┌─────────┐     ┌─────────┐
│  Event  │────▶│   PHP   │────▶│ Message  │────▶│  Rust   │────▶│   FCM   │
│ Trigger │     │ Backend │     │   Bus    │     │  Notif  │     │  APNS   │
└─────────┘     └─────────┘     └──────────┘     └─────────┘     └─────────┘
                                                                      │
                                                                      ▼
                                                                 ┌─────────┐
                                                                 │  User   │
                                                                 │ Device  │
                                                                 └─────────┘
```

### Real-Time Chat Flow

```
┌─────────┐     ┌─────────┐     ┌──────────┐     ┌─────────┐
│  User   │────▶│ Elixir  │────▶│  PubSub  │────▶│  Users  │
│   A     │     │ Phoenix │     │          │     │  B, C   │
└─────────┘     └─────────┘     └──────────┘     └─────────┘
```

---

## Technology Stack

### Rust Services

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Runtime** | Tokio | Async runtime |
| **HTTP Client** | reqwest | API calls |
| **FFmpeg** | ffmpeg-next | Media processing |
| **Object Storage** | aws-sdk-s3 | S3-compatible storage |
| **Message Bus** | async-nats / lapin | NATS or RabbitMQ client |
| **Serialization** | serde, serde_json | JSON handling |
| **Logging** | tracing, tracing-subscriber | Structured logging |
| **Config** | config-rs | Configuration management |

### Elixir Phoenix

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Framework** | Phoenix 1.7+ | Web framework |
| **WebSocket** | Phoenix Channels | Real-time communication |
| **PubSub** | Phoenix PubSub | Distributed pub/sub |
| **Message Bus** | Gnat / amqp | NATS or RabbitMQ client |
| **JWT** | joken | JWT validation |
| **Database** | Ecto + PostgreSQL | Optional persistence |
| **Monitoring** | Phoenix LiveDashboard | Real-time metrics |

### Infrastructure

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Message Bus** | NATS JetStream / RabbitMQ | Event streaming |
| **Object Storage** | S3 / MinIO | Media storage |
| **CDN** | Akamai | Content delivery |
| **Containerization** | Docker | Deployment |
| **Orchestration** | Kubernetes (optional) | Container orchestration |
| **Monitoring** | Structured Logging + Phoenix LiveDashboard | Log-based observability and real-time metrics |

---

## Deployment Architecture

### Production Deployment

```
┌─────────────────────────────────────────────────────────────┐
│                    Load Balancer                            │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
┌───────▼────────┐          ┌────────▼────────┐
│  Elixir Node 1 │          │  Elixir Node 2  │
│  (Phoenix)     │          │  (Phoenix)      │
└───────┬────────┘          └────────┬────────┘
        │                            │
        └──────────────┬─────────────┘
                       │
              ┌────────▼────────┐
              │  Phoenix PubSub │
              │  (Distributed)  │
              └────────┬────────┘
                       │
┌──────────────────────┴──────────────────────┐
│                                             │
│  ┌──────────────┐      ┌──────────────┐     │
│  │ Rust Worker  │      │ Rust Worker  │     │
│  │ Pool (Media) │      │ Pool (Notif) │     │
│  └──────┬───────┘      └──────┬───────┘     │
│         │                     │             │
│         └──────────┬──────────┘             │
│                    │                        │
│         ┌──────────▼──────────┐             │
│         │   Message Bus       │             │
│         │  (NATS/RabbitMQ)    │             │
│         └─────────────────────┘             │
│                                             │
└─────────────────────────────────────────────┘
```

### Container Strategy

**Rust Services:**
- Separate containers per service type
- Horizontal scaling via container replicas
- Resource limits based on workload

**Elixir Phoenix:**
- Stateless Phoenix nodes
- Shared PubSub cluster
- Session affinity via load balancer (optional)

**Message Bus:**
- NATS JetStream cluster for high availability
- Or RabbitMQ cluster with mirrored queues

---

## Scalability Strategy

### Horizontal Scaling

#### Rust Workers

- **Stateless Design**: No shared state between workers
- **Queue-Based Scaling**: Scale based on message queue depth
- **Auto-Scaling**: Kubernetes HPA or similar based on queue metrics

#### Elixir Phoenix Nodes

- **Stateless Nodes**: All nodes are identical
- **PubSub Distribution**: Phoenix PubSub handles message distribution
- **Load Balancing**: Round-robin or least-connections
- **Connection Affinity**: Optional sticky sessions for WebSocket

### Vertical Scaling

- **Rust**: Optimize for CPU and memory per worker
- **Elixir**: Optimize for connection count (lightweight processes)

### Message Bus Scaling

- **NATS JetStream**: Clustering and replication
- **RabbitMQ**: Cluster with mirrored queues
- **Partitioning**: Topic-based partitioning for high throughput

---

## Security Architecture

### Authentication & Authorization

#### JWT Flow

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│   PHP   │────▶│  JWT    │────▶│ Elixir  │
│ Backend │     │  Token  │     │ Phoenix │
└─────────┘     └─────────┘     └─────────┘
```

1. PHP backend issues JWT on login
2. Client includes JWT in WebSocket connection
3. Elixir validates JWT before accepting connection
4. JWT claims include: `user_id`, `exp`, `iat`, `roles`

#### Event Authorization

- Events include `user_id` and `source` metadata
- Rust services validate event metadata
- Authorization checks based on user roles

### Network Security

- **TLS/SSL**: All external communications encrypted
- **Internal Network**: Private network for service-to-service communication
- **Firewall Rules**: Restrict access to message bus and databases

### Secrets Management

- **Environment Variables**: For configuration
- **Secret Management**: HashiCorp Vault, AWS Secrets Manager, or similar
- **No Hardcoded Secrets**: All secrets externalized

---

## Monitoring and Observability

### Metrics

#### Rust Services

- **Processing Metrics**: Jobs processed, success/failure rates, processing time
- **Resource Metrics**: CPU, memory, thread pool utilization
- **Message Bus Metrics**: Events consumed, events published, queue depth

#### Elixir Phoenix

- **Connection Metrics**: Active WebSocket connections, connection rate
- **Channel Metrics**: Messages broadcast, channel subscriptions
- **System Metrics**: BEAM VM metrics (process count, memory)

### Logging

- **Structured Logging**: JSON format for all services
- **Log Aggregation**: ELK stack, Loki, or cloud logging service
- **Log Levels**: DEBUG, INFO, WARN, ERROR

### Tracing

- **Distributed Tracing**: OpenTelemetry for cross-service tracing
- **Request IDs**: Propagate request IDs through events
- **Performance Tracing**: Identify bottlenecks

### Alerting

- **Critical Alerts**: Service down, high error rates
- **Performance Alerts**: High latency, queue depth thresholds
- **Resource Alerts**: CPU, memory, disk usage

---

## Error Handling and Resilience

### Rust Services

#### Retry Strategy

- **Exponential Backoff**: Retry failed operations with backoff
- **Max Retries**: Configurable retry limits
- **Dead Letter Queue**: Failed events after max retries

#### Error Types

- **Transient Errors**: Network issues, temporary service unavailability
- **Permanent Errors**: Invalid data, authentication failures
- **Processing Errors**: FFmpeg failures, storage errors

### Elixir Phoenix

#### OTP Supervision

- **Supervision Trees**: Automatic process restart on failure
- **Circuit Breakers**: Prevent cascading failures
- **Graceful Degradation**: Continue operating with reduced functionality

#### Channel Error Handling

- **Connection Errors**: Automatic reconnection with exponential backoff
- **Message Errors**: Log and notify, don't crash channel
- **Rate Limiting**: Prevent abuse and overload

### Message Bus Resilience

- **Event Persistence**: NATS JetStream or RabbitMQ persistence
- **At-Least-Once Delivery**: Ensure events are processed
- **Idempotency**: Handle duplicate events gracefully

---

## Future Considerations

### Potential Enhancements

1. **GraphQL API**: Unified API layer for clients
2. **gRPC Services**: High-performance inter-service communication
3. **Event Sourcing**: Full event sourcing for audit and replay
4. **CQRS**: Separate read/write models for complex queries
5. **Multi-Region**: Global deployment with regional message bus clusters
6. **Edge Computing**: Deploy Elixir nodes closer to users
7. **AI/ML Integration**: Enhanced AI workflows and real-time inference
8. **Blockchain Integration**: For content verification and NFTs

### Performance Optimizations

1. **Rust SIMD**: Vectorized operations for media processing
2. **Elixir NIFs**: Native code for performance-critical paths
3. **Caching Layer**: Redis for frequently accessed data
4. **Database Optimization**: Read replicas, connection pooling

### Operational Improvements

1. **Blue-Green Deployments**: Zero-downtime deployments
2. **Canary Releases**: Gradual rollout of new features
3. **Chaos Engineering**: Test system resilience
4. **Automated Testing**: Comprehensive integration tests

---

## Conclusion

Armoricore's hybrid Rust/Elixir architecture provides:

- **Performance**: Rust for CPU-intensive tasks
- **Concurrency**: Elixir for millions of WebSocket connections
- **Scalability**: Horizontal scaling of all components
- **Resilience**: Fault tolerance and error recovery
- **Flexibility**: Event-driven architecture enables independent evolution

This architecture supports high-performance media processing and real-time communication at scale, with clear separation of concerns and robust communication patterns.

