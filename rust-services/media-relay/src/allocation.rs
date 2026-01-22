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

//! TURN allocation management
//!
//! Handles TURN allocations for relayed media traffic.
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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Allocation information
#[derive(Debug, Clone)]
pub struct AllocationInfo {
    /// Allocation ID
    pub allocation_id: Uuid,
    /// Client address
    pub client_addr: SocketAddr,
    /// Relay address (server's public address for this allocation)
    pub relay_addr: SocketAddr,
    /// Permissions (allowed peer addresses)
    pub permissions: Vec<SocketAddr>,
    /// Lifetime in seconds
    pub lifetime: Duration,
    /// Created timestamp
    pub created_at: Instant,
    /// Expires at
    pub expires_at: Instant,
    /// Bandwidth limit (bytes per second, 0 = unlimited)
    pub bandwidth_limit: u64,
    /// Current bandwidth usage (bytes)
    pub bytes_relayed: u64,
}

impl AllocationInfo {
    /// Check if allocation is expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Check if peer address is permitted
    pub fn is_permitted(&self, peer_addr: &SocketAddr) -> bool {
        self.permissions.iter().any(|addr| addr == peer_addr)
    }

    /// Add permission for peer address
    pub fn add_permission(&mut self, peer_addr: SocketAddr) {
        if !self.permissions.iter().any(|addr| addr == &peer_addr) {
            self.permissions.push(peer_addr);
        }
    }

    /// Remove permission for peer address
    pub fn remove_permission(&mut self, peer_addr: &SocketAddr) {
        self.permissions.retain(|addr| addr != peer_addr);
    }

    /// Refresh allocation (extend lifetime)
    pub fn refresh(&mut self, lifetime: Duration) {
        self.lifetime = lifetime;
        self.expires_at = Instant::now() + lifetime;
    }
}

/// Allocation manager
pub struct AllocationManager {
    /// Active allocations
    allocations: HashMap<Uuid, AllocationInfo>,
    /// Default allocation lifetime
    default_lifetime: Duration,
    /// Maximum allocations
    max_allocations: usize,
}

impl AllocationManager {
    /// Create a new allocation manager
    pub fn new(default_lifetime: Duration, max_allocations: usize) -> Self {
        AllocationManager {
            allocations: HashMap::new(),
            default_lifetime,
            max_allocations,
        }
    }

    /// Create a new allocation
    pub fn create_allocation(
        &mut self,
        client_addr: SocketAddr,
        relay_addr: SocketAddr,
        lifetime: Option<Duration>,
    ) -> RelayResult<AllocationInfo> {
        // Check allocation limit
        if self.allocations.len() >= self.max_allocations {
            return Err(RelayError::ServerError(
                "Maximum allocations reached".to_string()
            ));
        }

        let allocation_id = Uuid::new_v4();
        let lifetime = lifetime.unwrap_or(self.default_lifetime);
        let now = Instant::now();

        let allocation = AllocationInfo {
            allocation_id,
            client_addr,
            relay_addr,
            permissions: Vec::new(),
            lifetime,
            created_at: now,
            expires_at: now + lifetime,
            bandwidth_limit: 0, // Unlimited by default
            bytes_relayed: 0,
        };

        self.allocations.insert(allocation_id, allocation.clone());
        Ok(allocation)
    }

    /// Get allocation by ID
    pub fn get_allocation(&self, allocation_id: &Uuid) -> RelayResult<&AllocationInfo> {
        self.allocations.get(allocation_id)
            .ok_or_else(|| RelayError::AllocationNotFound(allocation_id.to_string()))
    }

    /// Get allocation mutably by ID
    pub fn get_allocation_mut(&mut self, allocation_id: &Uuid) -> RelayResult<&mut AllocationInfo> {
        self.allocations.get_mut(allocation_id)
            .ok_or_else(|| RelayError::AllocationNotFound(allocation_id.to_string()))
    }

    /// Refresh allocation (extend lifetime)
    pub fn refresh_allocation(
        &mut self,
        allocation_id: &Uuid,
        lifetime: Duration,
    ) -> RelayResult<()> {
        let allocation = self.get_allocation_mut(allocation_id)?;
        allocation.refresh(lifetime);
        Ok(())
    }

    /// Delete allocation
    pub fn delete_allocation(&mut self, allocation_id: &Uuid) -> RelayResult<()> {
        self.allocations.remove(allocation_id)
            .ok_or_else(|| RelayError::AllocationNotFound(allocation_id.to_string()))
            .map(|_| ())
    }

    /// Clean up expired allocations
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Instant::now();
        let initial_count = self.allocations.len();
        
        self.allocations.retain(|_, allocation| {
            allocation.expires_at > now
        });

        initial_count - self.allocations.len()
    }

    /// Get all active allocations
    pub fn get_active_allocations(&self) -> Vec<&AllocationInfo> {
        let now = Instant::now();
        self.allocations.values()
            .filter(|alloc| alloc.expires_at > now)
            .collect()
    }

    /// Get allocation count
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_create_allocation() {
        let mut manager = AllocationManager::new(
            Duration::from_secs(3600),
            100,
        );

        let client_addr = create_test_addr(50000);
        let relay_addr = create_test_addr(3478);

        let allocation = manager.create_allocation(client_addr, relay_addr, None).unwrap();
        assert_eq!(allocation.client_addr, client_addr);
        assert_eq!(allocation.relay_addr, relay_addr);
        assert!(!allocation.is_expired());
    }

    #[test]
    fn test_allocation_permissions() {
        let mut manager = AllocationManager::new(
            Duration::from_secs(3600),
            100,
        );

        let client_addr = create_test_addr(50000);
        let relay_addr = create_test_addr(3478);
        let allocation = manager.create_allocation(client_addr, relay_addr, None).unwrap();
        let allocation_id = allocation.allocation_id;

        let peer_addr = create_test_addr(50001);
        let mut allocation = manager.get_allocation_mut(&allocation_id).unwrap();
        allocation.add_permission(peer_addr);

        assert!(allocation.is_permitted(&peer_addr));
        
        allocation.remove_permission(&peer_addr);
        assert!(!allocation.is_permitted(&peer_addr));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut manager = AllocationManager::new(
            Duration::from_secs(1),
            100,
        );

        let client_addr = create_test_addr(50000);
        let relay_addr = create_test_addr(3478);
        manager.create_allocation(client_addr, relay_addr, Some(Duration::from_millis(100))).unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        let cleaned = manager.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert_eq!(manager.allocation_count(), 0);
    }
}

