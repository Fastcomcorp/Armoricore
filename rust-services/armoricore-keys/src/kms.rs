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

//! KMS (Key Management Service) interface for future HSM/KMS integration
//!
//! This module provides a trait-based interface for key management that can be
//! implemented by different backends:
//! - Local encrypted storage (current implementation)
//! - AWS KMS
//! - Azure Key Vault
//! - HashiCorp Vault
//! - Hardware Security Modules (HSM)
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


use crate::error::KeyResult;
use crate::key_types::{KeyId, KeyMetadata, KeyType, KeyVersion};
use async_trait::async_trait;

/// Trait for Key Management Service backends
#[async_trait]
pub trait KeyManagementService: Send + Sync {
    /// Store a new key
    async fn store_key(
        &self,
        key_id: &KeyId,
        key_type: KeyType,
        key_value: &[u8],
        metadata: Option<&str>,
    ) -> KeyResult<()>;

    /// Retrieve the active version of a key
    async fn get_key(&self, key_id: &KeyId) -> KeyResult<Vec<u8>>;

    /// Retrieve a specific version of a key
    async fn get_key_version(&self, key_id: &KeyId, version: u32) -> KeyResult<Vec<u8>>;

    /// Get key metadata
    async fn get_metadata(&self, key_id: &KeyId) -> KeyResult<KeyMetadata>;

    /// Rotate a key (create new version)
    async fn rotate_key(
        &self,
        key_id: &KeyId,
        new_key_value: &[u8],
    ) -> KeyResult<KeyVersion>;

    /// Delete a key (and all versions)
    async fn delete_key(&self, key_id: &KeyId) -> KeyResult<()>;

    /// List all key IDs
    async fn list_keys(&self) -> KeyResult<Vec<KeyId>>;

    /// Check if a key exists
    async fn key_exists(&self, key_id: &KeyId) -> bool;
}

