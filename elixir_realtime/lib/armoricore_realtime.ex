# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# Licensed under the Fastcomcorp Commercial License.
# See LICENSE file for complete terms and conditions.
#
# For commercial licensing: licensing@fastcomcorp.com
# For personal use: Free under Fastcomcorp Commercial License terms

defmodule ArmoricoreRealtime do
@moduledoc """
Armoricore Real-time Platform - Main Application Module

This module serves as the main entry point and documentation hub for the
Armoricore Real-time Platform. Armoricore is a cutting-edge real-time
communication platform that bridges WebRTC with ArcRTC technology for
ultra-low latency applications.

## Architecture Overview

Armoricore follows a modular architecture with clear separation of concerns:

### Core Contexts
- **Accounts**: User management, authentication, and authorization
- **Content**: Video management, categories, and media processing
- **Rooms**: Real-time communication spaces and chat functionality
- **Messaging**: Direct messages, group chats, and message management
- **Social**: Likes, comments, subscriptions, and social interactions
- **Analytics**: Usage metrics, performance monitoring, and insights
- **Audit**: Security event logging and compliance tracking

### Infrastructure Modules
- **MessageBus**: NATS-based pub/sub messaging with JetStream persistence
- **MediaEngineClient**: gRPC client for Rust-based media processing
- **ArcRtcBridge**: Protocol translation between WebRTC and ArcRTC
- **Redis**: Distributed caching and session management
- **KeyManager**: Encryption key management for E2EE features

### Web Layer
- **Controllers**: REST API endpoints and JSON responses
- **Channels**: Phoenix Channels for real-time WebSocket communication
- **LiveViews**: Server-rendered reactive UI components

## Key Features

- **Ultra-Low Latency**: <50ms communication via ArcRTC technology
- **WebRTC Compatible**: Seamless bridging for existing web applications
- **Enterprise Security**: JWT auth, rate limiting, E2EE messaging
- **Scalable Architecture**: Built for millions of concurrent users
- **Real-time Analytics**: Live metrics and performance monitoring
- **Multi-Platform**: Web, mobile, desktop, and IoT support

## Getting Started

1. **Installation**: Follow the setup guide in the main README
2. **Configuration**: Configure environment variables and database
3. **Development**: Run `mix phx.server` for the development server
4. **Production**: Use the deployment scripts for production setup

## API Documentation

- **REST API**: See `API_REFERENCE.md` for complete API documentation
- **Real-time Channels**: WebSocket-based real-time communication
- **SDKs**: Client libraries for JavaScript, iOS, Android, and more

## Monitoring & Maintenance

- **Health Checks**: `GET /api/v1/health` for system status
- **Metrics**: Real-time performance and business metrics
- **Logs**: Structured logging with configurable levels
- **Backups**: Automated database and file backups
- **Updates**: Rolling deployments with zero-downtime

## Contributing

See the main README and CONTRIBUTING.md for development guidelines,
coding standards, and contribution workflows.

## License

Copyright 2025 Francisco F. Pinochet, Fastcomcorp

Licensed under the Apache License, Version 2.0. See LICENSE file for details.
"""
end
