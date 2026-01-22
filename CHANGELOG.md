# Changelog

All notable changes to Armoricore will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-22

### 🎉 **Major Release: Secure Communications Platform**

Armoricore 1.0.0 transforms from not just a live streaming platform but also a comprehensive **secure communications platform** with enterprise-grade security features. This release introduces post-quantum cryptography, end-to-end encryption, and privacy-preserving protocols.

### ✨ **Added**

#### **Core Security Features**
- **Post-Quantum Cryptography**: Complete implementation of Kyber (KEM) and Falcon-512 (signatures)
- **End-to-End Encryption (E2EE)**: Double Ratchet algorithm for perfect forward secrecy
- **ArcRTC Security**: Enhanced ArcRTC with ArcSRTP for secure media streaming
- **Secure Messaging**: Olm and Megolm protocols for group encryption
- **Secure VoIP**: DTLS-SRTP and ArcSRTP for encrypted audio/video calls

#### **Privacy Protection**
- **Metadata Protection**: Sealed sender, traffic padding, and anonymous routing
- **Device Synchronization**: Multi-device secure key synchronization
- **Encrypted Storage**: Local encrypted storage for messages and keys
- **Anti-Censorship**: Domain fronting and pluggable transport support

#### **Cryptographic Primitives**
- **X25519/ECDH**: Elliptic curve key exchange
- **Ed25519**: Digital signatures
- **AES-256-GCM**: Authenticated encryption
- **HKDF**: Key derivation function
- **Argon2id**: Password hashing
- **HMAC-SHA256**: Message authentication

#### **Security Infrastructure**
- **Security Headers**: CSP, HSTS, X-Frame-Options, and comprehensive headers
- **Rate Limiting**: Request throttling to prevent abuse
- **Input Validation**: XSS sanitization and comprehensive input validation
- **Security Audit Logging**: Tamper-proof logging and incident response
- **JWT Authentication**: Secure token validation with configurable secrets

#### **ArcRTC Enhancements**
- **ArcSRTP**: Secure RTP with E2EE media streams
- **Secure Signaling**: E2EE WebRTC signaling with device verification
- **Media Engine Integration**: Rust-based media processing with security
- **Adaptive Bitrate**: Quality optimization with security preservation
- **CDN Integration**: Secure content delivery network support

#### **Platform Features**
- **Live Streaming**: Complete streaming platform with security
- **Social Features**: Rooms, comments, and engagement with privacy
- **Content Management**: Secure video content management
- **Analytics**: Privacy-preserving stream analytics
- **API**: Comprehensive REST and GraphQL APIs

### 🔒 **Security**

#### **Cryptographic Security**
- NIST Level 5 security with hybrid classical + post-quantum schemes capabilities
- Perfect forward secrecy through Double Ratchet
- Quantum-resistant signatures with Falcon-512
- Hardware-backed key storage support

#### **Privacy Features**
- Zero-knowledge architecture for content delivery
- Metadata minimization and correlation resistance
- Sealed sender implementation
- Traffic analysis resistance through padding

#### **Compliance**
- Audit logging
- Enterprise security controls
- Privacy-by-design architecture

### 🚀 **Performance**

#### **Optimizations**
- **Mobile Performance**: Battery-efficient cryptography
- **Memory Pooling**: Efficient resource management
- **Network Batching**: Reduced API calls
- **Progressive Security**: Adaptive security levels

#### **Scalability**
- **Horizontal Scaling**: Distributed architecture support
- **CDN Integration**: Global content delivery
- **Database Optimization**: Production-ready indexes and queries
- **Caching**: Redis integration for performance

### 🛠 **Technical Improvements**

#### **Architecture**
- **Microservices**: Modular Rust services integration
- **Event-Driven**: NATS JetStream message bus
- **Real-Time**: Phoenix Channels for live features
- **Database**: PostgreSQL with optimized schemas

#### **Developer Experience**
- **Comprehensive Documentation**: API references and guides
- **Testing Suite**: Extensive unit and integration tests
- **Development Tools**: Hot reloading and debugging support
- **Deployment Scripts**: Production-ready deployment automation

### 📊 **Breaking Changes**

#### **API Changes**
- Enhanced authentication with JWT validation
- New security headers required for all requests
- Updated WebRTC signaling protocol
- Modified channel authentication flow

#### **Configuration**
- New security configuration requirements
- Database schema updates for security features
- Environment variable changes for production deployment

### 🐛 **Fixed**
- Database connection issues with Aiven Cloud
- Health check failures with MessageBus integration
- JWT token validation security vulnerabilities
- XSS vulnerabilities in search functionality
- Race conditions in channel presence tracking

### 📚 **Documentation**
- **Security Documentation**: Comprehensive security guide
- **API Reference**: Complete API documentation
- **Deployment Guide**: Production deployment instructions
- **Architecture Overview**: System design documentation
- **Privacy Policy**: User privacy and data handling

### 🔧 **Dependencies**
- Updated cryptographic libraries for security
- Added post-quantum cryptography support
- Enhanced Rust services for media processing
- Database optimization libraries

### 🙏 **Credits**
- **Core Team**: Francisco F. Pinochet & Fastcomcorp
- **Security Research**: Post-quantum cryptography implementation
- **Architecture**: Secure communications platform design
- **Community**: Open source contributions and feedback


---

## [0.9.0] - 2026-01-01

### Added
- Initial ArcRTC implementation
- Basic live streaming functionality
- WebRTC signaling
- Phoenix Channels integration
- Database schema for content and users

### Security
- Basic authentication
- Input validation
- Rate limiting foundation

---

## [0.1.0] - 2025-01-01

### Added
- Initial Phoenix application setup
- Basic user authentication
- Database integration
- API foundation

---

[1.0.0]: https://github.com/Fastcomcorp/Armoricore/releases/tag/v1.0.0
[0.9.0]: https://github.com/Fastcomcorp/Armoricore/releases/tag/v0.9.0
[0.1.0]: https://github.com/Fastcomcorp/Armoricore/releases/tag/v0.1.0