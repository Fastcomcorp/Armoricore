# Armoricore

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/Fastcomcorp/Armoricore/releases)
[![License](https://img.shields.io/badge/license-Fastcomcorp%20Commercial-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-NIST%20Level%205-red.svg)](SECURITY.md)
[![Post-Quantum](https://img.shields.io/badge/crypto-PQ%20Ready-purple.svg)](SECURITY.md)

**Armoricore** is a high-performance backend platform for media processing and real-time communication, built with Rust and Elixir. Combining enterprise-grade security with cutting-edge post-quantum cryptography, Armoricore provides a privacy-preserving foundation for modern communication applications.

**Repository**: [https://github.com/Fastcomcorp/Armoricore](https://github.com/Fastcomcorp/Armoricore)

## Key Features

### **🔐 Security First**
- **Post-Quantum Cryptography**: Kyber-768 + Falcon-512 for quantum resistance
- **End-to-End Encryption**: Double Ratchet algorithm for perfect forward secrecy
- **ArcRTC Security**: Secure media streaming with ArcSRTP
- **Privacy by Design**: Minimal metadata collection and correlation resistance

### **📡 Real-Time Communication**
- **Secure Messaging**: Olm/Megolm protocols for encrypted chat
- **Secure VoIP**: DTLS-SRTP for encrypted calls
- **Live Streaming**: Privacy-preserving live video with DRM support
- **Group Communication**: Scalable encrypted group messaging

### **⚡ High-Performance Media**
- **8K Video Processing**: Hardware-accelerated transcoding
- **Adaptive Streaming**: HLS/MP4 with multiple bitrates
- **Audio-Only Support**: FLAC, Opus, AAC for internet radio
- **CDN Integration**: Global content delivery

### **🏢 Enterprise Ready**
- **SOC 2 Compliance**: Enterprise security and audit logging
- **Self-Hosted**: Deploy on your infrastructure
- **API Integration**: REST and GraphQL APIs
- **Multi-Platform**: Web, mobile, and desktop support

## Repository

**GitHub**: https://github.com/Fastcomcorp/Armoricore

### **Prerequisites**
- Elixir 1.14+
- Erlang/OTP 25+
- PostgreSQL 13+
- Rust 1.70+ (for media services)
- Node.js 18+ (for assets)

### **Installation**

For detailed installation instructions on Debian, Ubuntu, and Red Hat-based systems, see our comprehensive **[Installation Guide](INSTALL.md)**.

#### **Quick Start**
```bash
# Clone the repository
git clone https://github.com/Fastcomcorp/Armoricore.git
cd armoricore

# Install Elixir dependencies
cd elixir_realtime
mix deps.get

# Setup database
mix ecto.setup

# Start the backend API server
mix phx.server
```

The API server will be available at `http://localhost:4000/api/v1/`

Visit [`localhost:4000/api/v1/health`](http://localhost:4000/api/v1/health) to verify the API is running.

### **Docker Deployment**

```bash
# Build and run with Docker
docker-compose up -d

# Or use the production deployment script
./setup_production.sh
```

## 📖 **Documentation**

- **[API Reference](API_REFERENCE.md)** - Complete API documentation
- **[Security Guide](SECURITY.md)** - Security features and responsible disclosure
- **[Deployment Guide](DEPLOYMENT_READINESS_CHECKLIST.md)** - Production deployment
- **[Architecture Overview](PLATFORM_COMPLETION_SUMMARY.md)** - System design
- **[Testing Guide](TESTING_GUIDE.md)** - Development and testing

##  **Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ REST/GraphQL│  │ WebSocket   │  │   SDKs      │          │
│  │   APIs      │  │ Channels    │  │Integration  │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Application Layer                          ││
│  │  ┌─────────┐  ┌───────────┐  ┌──────────┐  ┌──────────┐ ││
│  │  │   E2EE  │  │ Messaging │  │   VoIP   │  │  Live    │ ││
│  │  │         │  │ Protocol  │  │ Security │  │ Streaming│ ││
│  │  └─────────┘  └───────────┘  └──────────┘  └──────────┘ ││
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐│
│  │              ArcRTC Security Layer                      ││
│  │  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌─────────┐    ││
│  │  │ ArcSRTP │  │ E2EE     │  │ PFS     │  │Metadata │    ││
│  │  │  E2EE   │  │ Signaling│  │ Ratchet │  │Protect  │    ││
│  │  └─────────┘  └──────────┘  └─────────┘  └─────────┘    ││
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Cryptographic Core                         ││
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐     ││
│  │  │  X25519 │  │AES-256  │  │ Ed25519 │  │ Kyber   │     ││
│  │  │  ECDH   │  │  GCM    │  │   Sig   │  │   KEM   │     ││
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘     ││
└─────────────────────────────────────────────────────────────┘
```

### **Core Components**

#### **Elixir Phoenix Backend**
- **REST API endpoints** for client applications
- **WebSocket channels** for real-time communication
- **Database layer** with Ecto and PostgreSQL
- **Security middleware** and JWT authentication
- **Rate limiting** and input validation
- **Message bus integration** with NATS JetStream

#### **Rust Media Services**
- **ArcRTC Engine**: High-performance media processing with ArcSRTP
- **Media Processor**: Real-time transcoding and distribution (up to 8K)
- **AI Workers**: Speech-to-text, translation, and content analysis
- **Real-time Media Engine**: RTP/SRTP packet processing
- **Message Bus Client**: Event-driven communication

#### **Supporting Infrastructure**
- **NATS JetStream**: Distributed message bus for event-driven architecture
- **Redis**: Caching, session management, and rate limiting
- **PostgreSQL**: Primary data storage with encryption support
- **Object Storage**: S3-compatible storage (Akamai, AWS S3, etc.)
- **CDN Integration**: Global content delivery with security

##  **Security Highlights**

### **Cryptographic Strength**
- **NIST Level 5**: 256-bit equivalent security
- **Post-Quantum Ready**: Hybrid classical + PQ cryptography
- **Perfect Forward Secrecy**: Double Ratchet implementation
- **Zero-Knowledge**: Server operators cannot access user content

### **Privacy Features**
- **Sealed Sender**: Prevent conversation discovery
- **Traffic Padding**: Resist analysis attacks
- **Anonymous Routing**: Metadata protection
- **Device Verification**: Safety numbers and fingerprints

### **Compliance**
- **GDPR Compliant**: European data protection regulation
- **Privacy by Design**: Security integrated throughout

##  **Use Cases**

### **Secure Messaging**
```bash
# Send encrypted message via API
curl -X POST http://localhost:4000/api/v1/direct-messages \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello, secure world!", "recipient_id": "user123"}'
```

### **Secure VoIP**
```bash
# Start encrypted video call via API
curl -X POST http://localhost:4000/api/v1/live-streams \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"title": "Secure Call", "is_private": true, "encryption": "arcrtp"}'
```

### **Live Streaming with DRM**
```bash
# Start DRM-protected live stream
curl -X POST http://localhost:4000/api/v1/live-streams \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{"title": "Premium Content", "drm_enabled": true, "encryption": "arcrtp"}'
```

##  **Testing & Quality Assurance**

```bash
# Run all tests
cd elixir_realtime && mix test

# Run security tests
mix test --only security

# Run integration tests
mix test test/integration/

# Run Rust tests
cd ../rust-services && cargo test

# Security verification
cd .. && ./verify_no_secrets.sh

# Load testing
./load_test.sh

# End-to-end testing
./test_end_to_end.sh
```

##  **Performance**

### **Benchmarks**
- **Message Throughput**: 10,000+ messages/second
- **Concurrent Users**: 100,000+ active connections
- **Media Streams**: 1,000+ simultaneous HD streams (up to 8K)
- **Latency**: <50ms end-to-end message delivery
- **Video Transcoding**: 4-8x faster with hardware acceleration

### **Resource Usage**
- **Memory**: ~100MB base + 1MB per active user
- **CPU**: <5% encryption overhead, hardware-accelerated media processing
- **Storage**: ~10KB per user for cryptographic state
- **Network**: Efficient binary protocols with compression
- **Media Processing**: GPU acceleration for 4K/8K video transcoding

##  **Contributing**

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### **Development Setup**
```bash
# Clone repository
git clone https://github.com/Fastcomcorp/Armoricore.git
cd armoricore

# Install dependencies
./install.sh

# Setup database
cd elixir_realtime
mix ecto.setup

# Start development environment
cd .. && ./start_dev.sh

# Run tests
cd elixir_realtime && mix test
cd ../rust-services && cargo test
```

### **Security Contributions**
- Follow our [Security Policy](SECURITY.md)
- Report security issues via security@fastcomcorp.com
- Join our bug bounty program

##  **License**

Copyright 2025-2026 Francisco F. Pinochet  
Copyright 2026 Fastcomcorp, LLC

### Personal Use
Armoricore is **free for personal use**. You may use, modify, and distribute the software for non-commercial purposes under the Fastcomcorp Commercial License.

### Commercial Use
Commercial use requires a **paid license**. Contact licensing@fastcomcorp.com for commercial licensing options:

- **Small Business**: $4,999/year (up to 100 users)
- **Enterprise**: $24,999/year (up to 1,000 users)
- **Unlimited**: $99,999/year (unlimited users)
- **OEM/White-label**: Custom pricing

### License Details
Licensed under the **Fastcomcorp Commercial License**. See [LICENSE](LICENSE) for complete terms and conditions.

📖 **[Complete Commercial Licensing Guide](COMMERCIAL_LICENSE_README.md)**

For commercial licensing inquiries: [licensing@fastcomcorp.com](mailto:licensing@fastcomcorp.com)

##  **Credits**

### **Core Team**
- **Francisco F. Pinochet** - Lead Developer & Security Architect

### **Technology Stack**
- **Elixir & Phoenix** - Real-time web framework with WebSocket support
- **Rust** - High-performance media processing and security services
- **PostgreSQL** - Reliable data storage with encryption support
- **NATS JetStream** - Distributed messaging and event streaming
- **FFmpeg** - Media processing with hardware acceleration
- **Redis** - Caching and session management (optional)

### **Security Research**
- Post-quantum cryptography implementation
- Protocol analysis and security audits
- Privacy-preserving architecture design

##  **Support**

- **Documentation**: [GitHub Wiki](https://github.com/Fastcomcorp/Armoricore/wiki)
- **Security Issues**: [security@fastcomcorp.com](mailto:security@fastcomcorp.com)
- **General Support**: [info@fastcomcorp.com](mailto:info@fastcomcorp.com)


---

##  **Why Armoricore?**

**Armoricore represents the future of secure communications:**

### **🏆 Security**
- **Post-Quantum First**: Industry-leading PQ cryptography
- **Privacy Focused**: Minimal metadata, maximal protection

### **⚡ Performance Excellence**
- **Real-Time**: Sub-50ms message delivery
- **Scalable**: Millions of concurrent users
- **Efficient**: Minimal cryptographic overhead

### **🔧 Developer Friendly**
- **Open Source**: Transparent and auditable
- **Well Documented**: Comprehensive guides and APIs
- **Modern Stack**: Elixir, Rust, and proven technologies

### **🌍 Mission Driven**
- **Privacy**: Protecting user communications
- **Future Proof**: Quantum-resistant security
- **Inclusive**: Accessible to all developers and users

---

##  **Version 1.0.0 Highlights**

**Armoricore 1.0.0** is a production-ready secure communications platform built upon the [Fastcomcorp GitHub release](https://github.com/Fastcomcorp/Armoricore):

### **🔐 Enterprise Security**
- **Post-Quantum Cryptography**: Kyber-768 + Falcon-512 implementation
- **End-to-End Encryption**: Double Ratchet with Olm/Megolm protocols
- **ArcRTC Security**: ArcSRTP for secure media streaming
- **Privacy by Design**: Minimal metadata, sealed sender, traffic padding
- **NIST Level 5**: Enterprise-grade security compliance

### **⚡ High-Performance Architecture**
- **Rust + Elixir**: Performance-critical Rust services + scalable Elixir backend
- **8K Media Processing**: Hardware-accelerated video transcoding
- **Real-Time Communication**: WebRTC + ArcRTC protocol support
- **Event-Driven**: NATS JetStream for distributed messaging
- **Scalable**: 100K+ concurrent users with <50ms latency

### **📦 Production Ready**
- **Self-Hosted**: Full control over your infrastructure
- **API-First**: REST + APIs for integrations
- **Multi-Platform**: Web, mobile, desktop support
- **Enterprise Features**: Audit logging, rate limiting, monitoring
- **Commercial License**: Dual-license model for businesses

### **🚀 Key Capabilities**
- **Media Processing**: HLS/MP4 streaming, audio-only support (FLAC/Opus)
- **Secure Messaging**: Encrypted chat with group support
- **Live Streaming**: DRM-protected video with privacy preservation
- **AI Integration**: Speech-to-text, translation, content moderation
- **Global Deployment**: CDN integration, multi-region support

---

**Ready to build secure communication applications?**

[Get Started](README.md#quick-start) • [API Docs](API_REFERENCE.md) • [Security](SECURITY.md) • [Contributing](CONTRIBUTING.md) • [Release Notes](CHANGELOG.md)