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

//! STUN/TURN protocol handler
//!
//! Implements STUN (Session Traversal Utilities for NAT) and TURN
//! (Traversal Using Relays around NAT) protocols for NAT traversal.
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


use crate::allocation::{AllocationInfo, AllocationManager};
use crate::error::{RelayError, RelayResult};
use bytes::Bytes;
use std::net::SocketAddr;
use uuid::Uuid;

/// STUN message
#[derive(Debug, Clone)]
pub struct StunMessage {
    /// Message type (request, response, etc.)
    pub message_type: StunMessageType,
    /// Transaction ID
    pub transaction_id: [u8; 12],
    /// Attributes
    pub attributes: Vec<StunAttribute>,
}

/// STUN message type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMessageType {
    /// Binding request
    BindingRequest,
    /// Binding response
    BindingResponse,
    /// Binding error response
    BindingErrorResponse,
    /// Shared secret request
    SharedSecretRequest,
    /// Shared secret response
    SharedSecretResponse,
}

/// STUN attribute
#[derive(Debug, Clone)]
pub struct StunAttribute {
    /// Attribute type
    pub attribute_type: u16,
    /// Attribute value
    pub value: Bytes,
}

/// TURN allocation request
#[derive(Debug, Clone)]
pub struct TurnRequest {
    /// Requested lifetime in seconds
    pub lifetime: u32,
    /// Requested bandwidth (bytes per second, 0 = unlimited)
    pub bandwidth: u64,
    /// Transport protocol (UDP, TCP)
    pub transport: TransportProtocol,
}

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProtocol {
    /// UDP
    Udp,
    /// TCP
    Tcp,
}

/// TURN allocation
#[derive(Debug, Clone)]
pub struct Allocation {
    /// Allocation ID
    pub allocation_id: Uuid,
    /// Relay address
    pub relay_addr: SocketAddr,
    /// Lifetime in seconds
    pub lifetime: u32,
}

/// STUN/TURN handler
pub struct StunTurnHandler {
    /// Allocation manager
    allocation_manager: AllocationManager,
    /// Server public address
    server_public_addr: SocketAddr,
    /// Server relay address pool
    relay_addresses: Vec<SocketAddr>,
    /// Current relay address index
    relay_index: usize,
}

impl StunTurnHandler {
    /// Create a new STUN/TURN handler
    pub fn new(
        server_public_addr: SocketAddr,
        relay_addresses: Vec<SocketAddr>,
    ) -> Self {
        StunTurnHandler {
            allocation_manager: AllocationManager::new(
                std::time::Duration::from_secs(3600), // 1 hour default
                1000, // Max 1000 allocations
            ),
            server_public_addr,
            relay_addresses,
            relay_index: 0,
        }
    }

    /// Handle STUN binding request
    pub async fn handle_stun_request(
        &mut self,
        request: &StunMessage,
        client_addr: SocketAddr,
    ) -> RelayResult<StunMessage> {
        if request.message_type != StunMessageType::BindingRequest {
            return Err(RelayError::StunTurnError(
                "Expected binding request".to_string()
            ));
        }

        // Create binding response with mapped address
        let mut attributes = Vec::new();
        
        // MAPPED-ADDRESS attribute (client's public IP as seen by server)
        let mapped_addr_bytes = self.encode_address(client_addr);
        attributes.push(StunAttribute {
            attribute_type: 0x0001, // MAPPED-ADDRESS
            value: Bytes::from(mapped_addr_bytes),
        });

        // XOR-MAPPED-ADDRESS attribute (RFC 5389)
        let xor_mapped_addr_bytes = self.encode_xor_address(client_addr, &request.transaction_id);
        attributes.push(StunAttribute {
            attribute_type: 0x0020, // XOR-MAPPED-ADDRESS
            value: Bytes::from(xor_mapped_addr_bytes),
        });

        Ok(StunMessage {
            message_type: StunMessageType::BindingResponse,
            transaction_id: request.transaction_id,
            attributes,
        })
    }

    /// Handle TURN allocation request
    pub async fn handle_turn_allocation(
        &mut self,
        request: &TurnRequest,
        client_addr: SocketAddr,
    ) -> RelayResult<Allocation> {
        // Select relay address (round-robin)
        let relay_addr = if self.relay_addresses.is_empty() {
            // Use server public address if no relay addresses configured
            self.server_public_addr
        } else {
            let addr = self.relay_addresses[self.relay_index];
            self.relay_index = (self.relay_index + 1) % self.relay_addresses.len();
            addr
        };

        let lifetime = std::time::Duration::from_secs(request.lifetime as u64);

        // Create allocation
        let allocation_info = self.allocation_manager.create_allocation(
            client_addr,
            relay_addr,
            Some(lifetime),
        )?;

        Ok(Allocation {
            allocation_id: allocation_info.allocation_id,
            relay_addr: allocation_info.relay_addr,
            lifetime: allocation_info.lifetime.as_secs() as u32,
        })
    }

    /// Relay data through allocation
    pub async fn relay_data(
        &mut self,
        allocation_id: &Uuid,
        data: &[u8],
        destination: SocketAddr,
    ) -> RelayResult<()> {
        let allocation = self.allocation_manager.get_allocation_mut(allocation_id)?;

        // Check if allocation is expired
        if allocation.is_expired() {
            return Err(RelayError::AllocationExpired(allocation_id.to_string()));
        }

        // Check if destination is permitted
        if !allocation.is_permitted(&destination) {
            return Err(RelayError::PermissionDenied(
                format!("Destination {} not permitted", destination)
            ));
        }

        // Check bandwidth limit
        if allocation.bandwidth_limit > 0 {
            let current_rate = allocation.bytes_relayed / 
                allocation.created_at.elapsed().as_secs().max(1);
            if current_rate >= allocation.bandwidth_limit {
                return Err(RelayError::ServerError(
                    "Bandwidth limit exceeded".to_string()
                ));
            }
        }

        // Update relayed bytes
        allocation.bytes_relayed += data.len() as u64;

        // In production, this would actually send the data to destination
        // For now, we just track the relay operation
        Ok(())
    }

    /// Add permission for peer address
    pub async fn add_permission(
        &mut self,
        allocation_id: &Uuid,
        peer_addr: SocketAddr,
    ) -> RelayResult<()> {
        let allocation = self.allocation_manager.get_allocation_mut(allocation_id)?;
        allocation.add_permission(peer_addr);
        Ok(())
    }

    /// Refresh allocation
    pub async fn refresh_allocation(
        &mut self,
        allocation_id: &Uuid,
        lifetime: u32,
    ) -> RelayResult<()> {
        self.allocation_manager.refresh_allocation(
            allocation_id,
            std::time::Duration::from_secs(lifetime as u64),
        )
    }

    /// Delete allocation
    pub async fn delete_allocation(&mut self, allocation_id: &Uuid) -> RelayResult<()> {
        self.allocation_manager.delete_allocation(allocation_id)
    }

    /// Cleanup expired allocations
    pub fn cleanup_expired(&mut self) -> usize {
        self.allocation_manager.cleanup_expired()
    }

    /// Get allocation count
    pub fn allocation_count(&self) -> usize {
        self.allocation_manager.allocation_count()
    }

    /// Get active allocations
    pub fn get_active_allocations(&self) -> Vec<&AllocationInfo> {
        self.allocation_manager.get_active_allocations()
    }

    /// Get allocation by ID
    pub fn get_allocation(&self, allocation_id: &Uuid) -> RelayResult<&AllocationInfo> {
        self.allocation_manager.get_allocation(allocation_id)
    }

    /// Encode address for STUN MAPPED-ADDRESS attribute
    fn encode_address(&self, addr: SocketAddr) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Reserved (1 byte) + Family (1 byte) + Port (2 bytes) + Address (4 or 16 bytes)
        bytes.push(0); // Reserved
        match addr {
            SocketAddr::V4(v4) => {
                bytes.push(0x01); // IPv4
                bytes.extend_from_slice(&addr.port().to_be_bytes());
                bytes.extend_from_slice(&v4.ip().octets());
            }
            SocketAddr::V6(v6) => {
                bytes.push(0x02); // IPv6
                bytes.extend_from_slice(&addr.port().to_be_bytes());
                bytes.extend_from_slice(&v6.ip().octets());
            }
        }
        
        bytes
    }

    /// Encode XOR address for STUN XOR-MAPPED-ADDRESS attribute
    fn encode_xor_address(&self, addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut bytes = self.encode_address(addr);
        
        // XOR port with magic cookie (first 2 bytes of transaction ID)
        if bytes.len() >= 4 {
            let port_bytes = &mut bytes[2..4];
            let magic = u16::from_be_bytes([transaction_id[0], transaction_id[1]]);
            let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]) ^ magic;
            port_bytes[0] = (port >> 8) as u8;
            port_bytes[1] = port as u8;
        }
        
        // XOR address with transaction ID
        match addr {
            SocketAddr::V4(_) => {
                if bytes.len() >= 8 {
                    for i in 0..4 {
                        bytes[4 + i] ^= transaction_id[i];
                    }
                }
            }
            SocketAddr::V6(_) => {
                if bytes.len() >= 20 {
                    for i in 0..16 {
                        bytes[4 + i] ^= transaction_id[i % 12];
                    }
                }
            }
        }
        
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[tokio::test]
    async fn test_stun_binding_request() {
        let mut handler = StunTurnHandler::new(
            create_test_addr(3478),
            vec![],
        );

        let request = StunMessage {
            message_type: StunMessageType::BindingRequest,
            transaction_id: [0u8; 12],
            attributes: vec![],
        };

        let client_addr = create_test_addr(50000);
        let response = handler.handle_stun_request(&request, client_addr).await.unwrap();

        assert_eq!(response.message_type, StunMessageType::BindingResponse);
        assert_eq!(response.transaction_id, request.transaction_id);
    }

    #[tokio::test]
    async fn test_turn_allocation() {
        let mut handler = StunTurnHandler::new(
            create_test_addr(3478),
            vec![create_test_addr(50000), create_test_addr(50001)],
        );

        let request = TurnRequest {
            lifetime: 3600,
            bandwidth: 0, // Unlimited
            transport: TransportProtocol::Udp,
        };

        let client_addr = create_test_addr(50002);
        let allocation = handler.handle_turn_allocation(&request, client_addr).await.unwrap();

        assert_eq!(allocation.lifetime, 3600);
    }

    #[tokio::test]
    async fn test_relay_data() {
        let mut handler = StunTurnHandler::new(
            create_test_addr(3478),
            vec![],
        );

        let request = TurnRequest {
            lifetime: 3600,
            bandwidth: 0,
            transport: TransportProtocol::Udp,
        };

        let client_addr = create_test_addr(50000);
        let allocation = handler.handle_turn_allocation(&request, client_addr).await.unwrap();

        // Add permission for peer
        let peer_addr = create_test_addr(50001);
        handler.add_permission(&allocation.allocation_id, peer_addr).await.unwrap();

        // Relay data
        let data = b"test data";
        handler.relay_data(&allocation.allocation_id, data, peer_addr).await.unwrap();
    }
}

