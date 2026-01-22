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

//! ICE (Interactive Connectivity Establishment) implementation
//!
//! Implements RFC 8445 ICE protocol for NAT traversal.
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


use crate::error::{MediaEngineError, MediaEngineResult};
use rand::RngCore;
use std::net::SocketAddr;
use uuid::Uuid;

/// ICE candidate type (RFC 8445 Section 5.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceCandidateType {
    /// Host candidate (directly connected interface)
    Host,
    /// Server reflexive candidate (via STUN server)
    ServerReflexive,
    /// Peer reflexive candidate (discovered during connectivity checks)
    PeerReflexive,
    /// Relayed candidate (via TURN server)
    Relayed,
}

/// ICE candidate (RFC 8445 Section 5.1)
#[derive(Debug, Clone)]
pub struct IceCandidate {
    /// Foundation (unique identifier for candidate pair)
    pub foundation: String,
    /// Component ID (1 for RTP, 2 for RTCP)
    pub component: u32,
    /// Transport protocol (UDP, TCP)
    pub transport: String,
    /// Priority (calculated per RFC 8445 Section 5.1.2.1)
    pub priority: u64,
    /// Candidate address
    pub address: SocketAddr,
    /// Candidate type
    pub candidate_type: IceCandidateType,
    /// Related address (for srflx/relay candidates)
    pub related_address: Option<SocketAddr>,
    /// ICE username fragment (from SDP)
    pub username_fragment: Option<String>,
    /// ICE password (from SDP)
    pub password: Option<String>,
}

/// ICE candidate pair (RFC 8445 Section 5.7)
#[derive(Debug, Clone)]
pub struct IceCandidatePair {
    /// Local candidate
    pub local: IceCandidate,
    /// Remote candidate
    pub remote: IceCandidate,
    /// Pair priority (calculated per RFC 8445 Section 6.1.2.3)
    pub priority: u64,
    /// Pair state
    pub state: IcePairState,
    /// Nominated flag
    pub nominated: bool,
}

/// ICE candidate pair state (RFC 8445 Section 6.1.2.6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcePairState {
    /// Waiting - pair created, waiting to be checked
    Waiting,
    /// In Progress - connectivity check in progress
    InProgress,
    /// Succeeded - connectivity check succeeded
    Succeeded,
    /// Failed - connectivity check failed
    Failed,
    /// Frozen - pair is frozen (not checked yet)
    Frozen,
}

/// ICE connection state (RFC 8445 Section 6.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceConnectionState {
    /// New - ICE agent created
    New,
    /// Checking - connectivity checks in progress
    Checking,
    /// Connected - at least one pair succeeded
    Connected,
    /// Completed - all pairs checked, at least one succeeded
    Completed,
    /// Failed - all pairs failed
    Failed,
    /// Disconnected - connectivity lost
    Disconnected,
    /// Closed - ICE agent closed
    Closed,
}

/// ICE agent (RFC 8445)
pub struct IceAgent {
    /// Agent ID
    pub agent_id: Uuid,
    /// Local username fragment
    pub local_ufrag: String,
    /// Local password
    pub local_password: String,
    /// Remote username fragment
    pub remote_ufrag: Option<String>,
    /// Remote password
    pub remote_password: Option<String>,
    /// Local candidates
    pub local_candidates: Vec<IceCandidate>,
    /// Remote candidates
    pub remote_candidates: Vec<IceCandidate>,
    /// Candidate pairs
    pub candidate_pairs: Vec<IceCandidatePair>,
    /// Connection state
    pub connection_state: IceConnectionState,
    /// Selected pair (if any)
    pub selected_pair: Option<IceCandidatePair>,
}

impl IceCandidate {
    /// Calculate candidate priority per RFC 8445 Section 5.1.2.1
    pub fn calculate_priority(&self) -> u64 {
        let type_preference = match self.candidate_type {
            IceCandidateType::Host => 126,
            IceCandidateType::PeerReflexive => 110,
            IceCandidateType::ServerReflexive => 100,
            IceCandidateType::Relayed => 0,
        };

        let component_preference = (256 - self.component) as u64;
        let local_preference = 65535u64; // Can be adjusted based on network interface

        (type_preference as u64) << 24 | (local_preference) << 8 | component_preference
    }

    /// Create a host candidate
    pub fn new_host(component: u32, address: SocketAddr) -> Self {
        let foundation = format!("host-{}", address.ip());
        let mut candidate = IceCandidate {
            foundation: foundation.clone(),
            component,
            transport: "udp".to_string(),
            priority: 0, // Will be calculated
            address,
            candidate_type: IceCandidateType::Host,
            related_address: None,
            username_fragment: None,
            password: None,
        };
        candidate.priority = candidate.calculate_priority();
        candidate
    }

    /// Create a server reflexive candidate (from STUN)
    pub fn new_server_reflexive(
        component: u32,
        address: SocketAddr,
        related_address: SocketAddr,
    ) -> Self {
        let foundation = format!("srflx-{}", address.ip());
        let mut candidate = IceCandidate {
            foundation: foundation.clone(),
            component,
            transport: "udp".to_string(),
            priority: 0, // Will be calculated
            address,
            candidate_type: IceCandidateType::ServerReflexive,
            related_address: Some(related_address),
            username_fragment: None,
            password: None,
        };
        candidate.priority = candidate.calculate_priority();
        candidate
    }

    /// Create a relayed candidate (from TURN)
    pub fn new_relayed(
        component: u32,
        address: SocketAddr,
        related_address: SocketAddr,
    ) -> Self {
        let foundation = format!("relay-{}", address.ip());
        let mut candidate = IceCandidate {
            foundation: foundation.clone(),
            component,
            transport: "udp".to_string(),
            priority: 0, // Will be calculated
            address,
            candidate_type: IceCandidateType::Relayed,
            related_address: Some(related_address),
            username_fragment: None,
            password: None,
        };
        candidate.priority = candidate.calculate_priority();
        candidate
    }
}

impl IceCandidatePair {
    /// Calculate pair priority per RFC 8445 Section 6.1.2.3
    pub fn calculate_priority(&self) -> u64 {
        let g = if self.local.priority > self.remote.priority {
            self.local.priority
        } else {
            self.remote.priority
        };
        let d = if self.local.priority < self.remote.priority {
            self.local.priority
        } else {
            self.remote.priority
        };

        if g > d {
            (2 * g) | 1
        } else {
            2 * d
        }
    }

    /// Create a new candidate pair
    pub fn new(local: IceCandidate, remote: IceCandidate) -> Self {
        let priority = Self::calculate_pair_priority(&local, &remote);
        IceCandidatePair {
            local,
            remote,
            priority,
            state: IcePairState::Frozen,
            nominated: false,
        }
    }

    /// Calculate pair priority (static method)
    fn calculate_pair_priority(local: &IceCandidate, remote: &IceCandidate) -> u64 {
        let g = local.priority.max(remote.priority);
        let d = local.priority.min(remote.priority);

        if g > d {
            (2 * g) | 1
        } else {
            2 * d
        }
    }
}

impl IceAgent {
    /// Create a new ICE agent
    pub fn new(agent_id: Uuid) -> Self {
        // Generate username fragment and password per RFC 8445 Section 5.4
        let mut rng = rand::thread_rng();
        let mut ufrag_bytes = [0u8; 8];
        rng.try_fill_bytes(&mut ufrag_bytes).unwrap();
        let local_ufrag = hex::encode(ufrag_bytes);
        
        let mut pwd_bytes = [0u8; 16];
        rng.try_fill_bytes(&mut pwd_bytes).unwrap();
        let local_password = hex::encode(pwd_bytes);

        IceAgent {
            agent_id,
            local_ufrag,
            local_password,
            remote_ufrag: None,
            remote_password: None,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            candidate_pairs: Vec::new(),
            connection_state: IceConnectionState::New,
            selected_pair: None,
        }
    }

    /// Add local candidate
    pub fn add_local_candidate(&mut self, candidate: IceCandidate) {
        self.local_candidates.push(candidate);
    }

    /// Add remote candidate
    pub fn add_remote_candidate(&mut self, candidate: IceCandidate) {
        self.remote_candidates.push(candidate);
        // Form candidate pairs per RFC 8445 Section 6.1.2.1
        self.form_candidate_pairs();
    }

    /// Form candidate pairs per RFC 8445 Section 6.1.2.1
    fn form_candidate_pairs(&mut self) {
        self.candidate_pairs.clear();

        for local in &self.local_candidates {
            for remote in &self.remote_candidates {
                // Only pair candidates with same component and transport
                if local.component == remote.component && local.transport == remote.transport {
                    let pair = IceCandidatePair::new(local.clone(), remote.clone());
                    self.candidate_pairs.push(pair);
                }
            }
        }

        // Sort by priority (highest first)
        self.candidate_pairs.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Start ICE connectivity checks per RFC 8445 Section 6.1.2.4
    pub fn start_connectivity_checks(&mut self) -> MediaEngineResult<()> {
        if self.remote_ufrag.is_none() || self.remote_password.is_none() {
            return Err(MediaEngineError::ConfigError(
                "Remote ICE credentials not set".to_string()
            ));
        }

        self.connection_state = IceConnectionState::Checking;

        // Unfreeze pairs and start checks (simplified - actual implementation
        // would send STUN binding requests)
        for pair in &mut self.candidate_pairs {
            if pair.state == IcePairState::Frozen {
                pair.state = IcePairState::Waiting;
            }
        }

        Ok(())
    }

    /// Handle successful connectivity check
    pub fn handle_check_success(&mut self, pair_index: usize) -> MediaEngineResult<()> {
        if pair_index >= self.candidate_pairs.len() {
            return Err(MediaEngineError::ConfigError(
                "Invalid pair index".to_string()
            ));
        }

        let pair = &mut self.candidate_pairs[pair_index];
        pair.state = IcePairState::Succeeded;

        // Update connection state
        match self.connection_state {
            IceConnectionState::New | IceConnectionState::Checking => {
                self.connection_state = IceConnectionState::Connected;
            }
            _ => {}
        }

        // If nominated, select this pair
        if pair.nominated {
            self.selected_pair = Some(pair.clone());
            self.connection_state = IceConnectionState::Completed;
        }

        Ok(())
    }

    /// Handle failed connectivity check
    pub fn handle_check_failure(&mut self, pair_index: usize) -> MediaEngineResult<()> {
        if pair_index >= self.candidate_pairs.len() {
            return Err(MediaEngineError::ConfigError(
                "Invalid pair index".to_string()
            ));
        }

        let pair = &mut self.candidate_pairs[pair_index];
        pair.state = IcePairState::Failed;

        // Check if all pairs failed
        let all_failed = self.candidate_pairs.iter()
            .all(|p| p.state == IcePairState::Failed);

        if all_failed {
            self.connection_state = IceConnectionState::Failed;
        }

        Ok(())
    }

    /// Set remote ICE credentials
    pub fn set_remote_credentials(&mut self, ufrag: String, password: String) {
        self.remote_ufrag = Some(ufrag);
        self.remote_password = Some(password);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_ice_candidate_priority() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let host_candidate = IceCandidate::new_host(1, addr);
        
        assert!(host_candidate.priority > 0);
        assert_eq!(host_candidate.candidate_type, IceCandidateType::Host);
    }

    #[test]
    fn test_ice_candidate_pair_priority() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5001);
        
        let local = IceCandidate::new_host(1, local_addr);
        let remote = IceCandidate::new_host(1, remote_addr);
        
        let pair = IceCandidatePair::new(local, remote);
        assert!(pair.priority > 0);
    }
}

