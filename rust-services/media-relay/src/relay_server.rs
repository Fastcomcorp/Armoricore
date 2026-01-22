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

//! Media relay server
//!
//! Main server for relaying media packets when direct peer-to-peer
//! connections are not possible.
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


use crate::error::{RelayError, RelayResult};
use crate::stun_turn_handler::StunTurnHandler;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::{UdpSocket, TcpListener};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Relay server configuration
#[derive(Debug, Clone)]
pub struct RelayServerConfig {
    /// UDP listen address
    pub udp_listen_addr: SocketAddr,
    /// TCP listen address
    pub tcp_listen_addr: SocketAddr,
    /// Server public address (for STUN responses)
    pub public_addr: SocketAddr,
    /// Relay address pool
    pub relay_addresses: Vec<SocketAddr>,
    /// Enable UDP relay
    pub enable_udp: bool,
    /// Enable TCP relay
    pub enable_tcp: bool,
}

impl Default for RelayServerConfig {
    fn default() -> Self {
        RelayServerConfig {
            udp_listen_addr: "0.0.0.0:3478".parse().unwrap(),
            tcp_listen_addr: "0.0.0.0:3478".parse().unwrap(),
            public_addr: "127.0.0.1:3478".parse().unwrap(),
            relay_addresses: vec![],
            enable_udp: true,
            enable_tcp: false,
        }
    }
}

/// Relay connection
#[derive(Debug, Clone)]
pub struct RelayConnection {
    /// Connection ID
    pub connection_id: Uuid,
    /// Client address
    pub client_addr: SocketAddr,
    /// Allocation ID (if TURN allocation exists)
    pub allocation_id: Option<Uuid>,
    /// Last activity timestamp
    pub last_activity: std::time::Instant,
}

/// Relay server
pub struct RelayServer {
    /// Configuration
    config: RelayServerConfig,
    /// STUN/TURN handler
    stun_turn_handler: RwLock<StunTurnHandler>,
    /// Active connections
    connections: RwLock<HashMap<SocketAddr, RelayConnection>>,
    /// UDP socket
    udp_socket: Option<UdpSocket>,
    /// TCP listener
    tcp_listener: Option<TcpListener>,
}

impl RelayServer {
    /// Create a new relay server
    pub fn new(config: RelayServerConfig) -> Self {
        let stun_turn_handler = StunTurnHandler::new(
            config.public_addr,
            config.relay_addresses.clone(),
        );

        RelayServer {
            config,
            stun_turn_handler: RwLock::new(stun_turn_handler),
            connections: RwLock::new(HashMap::new()),
            udp_socket: None,
            tcp_listener: None,
        }
    }

    /// Start the relay server
    pub async fn start(&mut self) -> RelayResult<()> {
        // Start UDP server
        if self.config.enable_udp {
            let socket = UdpSocket::bind(&self.config.udp_listen_addr).await
                .map_err(|e| RelayError::NetworkError(format!("Failed to bind UDP: {}", e)))?;
            self.udp_socket = Some(socket);
        }

        // Start TCP server
        if self.config.enable_tcp {
            let listener = TcpListener::bind(&self.config.tcp_listen_addr).await
                .map_err(|e| RelayError::NetworkError(format!("Failed to bind TCP: {}", e)))?;
            self.tcp_listener = Some(listener);
        }

        Ok(())
    }

    /// Handle incoming UDP packet
    pub async fn handle_udp_packet(
        &self,
        data: &[u8],
        from: SocketAddr,
    ) -> RelayResult<Option<Vec<u8>>> {
        // Check if this is a STUN/TURN message
        if self.is_stun_message(data) {
            return self.handle_stun_turn_message(data, from).await;
        }

        // Otherwise, treat as relayed media packet
        self.handle_relayed_packet(data, from).await
    }

    /// Handle STUN/TURN message
    async fn handle_stun_turn_message(
        &self,
        _data: &[u8],
        _from: SocketAddr,
    ) -> RelayResult<Option<Vec<u8>>> {
        // Parse STUN message (simplified - in production would use proper STUN parser)
        // For now, we'll handle basic cases

        // Check if this is a TURN allocation request
        // In production, would parse actual STUN/TURN protocol
        // For now, return None (no response)
        Ok(None)
    }

    /// Handle relayed media packet
    async fn handle_relayed_packet(
        &self,
        _data: &[u8],
        from: SocketAddr,
    ) -> RelayResult<Option<Vec<u8>>> {
        // Find connection
        let connections = self.connections.read().await;
        if let Some(connection) = connections.get(&from) {
            if let Some(_allocation_id) = connection.allocation_id {
                // Relay through allocation
                // In production, would determine destination from packet
                // For now, just acknowledge
                let _handler = self.stun_turn_handler.write().await;
                // Would call handler.relay_data() here with actual destination
                return Ok(None);
            }
        }

        Err(RelayError::InvalidRequest(
            "No allocation for this connection".to_string()
        ))
    }

    /// Check if data is a STUN message
    fn is_stun_message(&self, data: &[u8]) -> bool {
        // STUN messages start with 0x00 or 0x01 in first byte
        // and have specific structure
        if data.len() < 20 {
            return false;
        }

        // Check STUN magic cookie (0x2112A442)
        let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        magic == 0x2112A442
    }

    /// Get server statistics
    pub async fn get_stats(&self) -> RelayStats {
        let connections = self.connections.read().await;
        let handler = self.stun_turn_handler.read().await;
        
        RelayStats {
            active_connections: connections.len(),
            active_allocations: handler.allocation_count(),
        }
    }

    /// Cleanup expired connections and allocations
    pub async fn cleanup(&self) -> usize {
        let mut handler = self.stun_turn_handler.write().await;
        let expired_allocations = handler.cleanup_expired();

        // Cleanup connections without allocations
        let mut connections = self.connections.write().await;
        let initial_count = connections.len();
        
        // Get list of valid allocation IDs
        let valid_allocations: std::collections::HashSet<Uuid> = handler
            .get_active_allocations()
            .iter()
            .map(|a| a.allocation_id)
            .collect();
        
        connections.retain(|_, conn| {
            if let Some(allocation_id) = conn.allocation_id {
                valid_allocations.contains(&allocation_id)
            } else {
                true // Keep connections without allocations for now
            }
        });

        expired_allocations + (initial_count - connections.len())
    }
}

/// Relay server statistics
#[derive(Debug, Clone)]
pub struct RelayStats {
    /// Active connections
    pub active_connections: usize,
    /// Active allocations
    pub active_allocations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_stun_message() {
        let config = RelayServerConfig::default();
        let server = RelayServer::new(config);

        // Valid STUN message (simplified - would need proper STUN format)
        let mut stun_data = vec![0u8; 20];
        stun_data[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        assert!(server.is_stun_message(&stun_data));

        // Invalid message
        let invalid_data = vec![0u8; 10];
        assert!(!server.is_stun_message(&invalid_data));
    }
}

