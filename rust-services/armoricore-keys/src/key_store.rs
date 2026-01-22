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

//! High-level key store interface
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


use crate::error::{KeyError, KeyResult};
use crate::key_types::{KeyId, KeyMetadata, KeyType};
use crate::kms::KeyManagementService;
use std::sync::Arc;
use tracing::info;

/// High-level key store that wraps a KMS backend
pub struct KeyStore {
    backend: Arc<dyn KeyManagementService>,
}

impl KeyStore {
    /// Create a new key store with a KMS backend
    pub fn new(backend: Arc<dyn KeyManagementService>) -> Self {
        Self { backend }
    }

    /// Store a JWT secret
    pub async fn store_jwt_secret(&self, key_id: &KeyId, secret: &str) -> KeyResult<()> {
        self.backend
            .store_key(key_id, KeyType::JwtSecret, secret.as_bytes(), None)
            .await
    }

    /// Get JWT secret
    pub async fn get_jwt_secret(&self, key_id: &KeyId) -> KeyResult<String> {
        let bytes = self.backend.get_key(key_id).await?;
        String::from_utf8(bytes)
            .map_err(|e| KeyError::InvalidFormat(format!("Invalid UTF-8: {}", e)))
    }

    /// Store an API key
    pub async fn store_api_key(
        &self,
        key_id: &KeyId,
        api_key: &str,
        metadata: Option<&str>,
    ) -> KeyResult<()> {
        self.backend
            .store_key(key_id, KeyType::ApiKey, api_key.as_bytes(), metadata)
            .await
    }

    /// Get API key
    pub async fn get_api_key(&self, key_id: &KeyId) -> KeyResult<String> {
        let bytes = self.backend.get_key(key_id).await?;
        String::from_utf8(bytes)
            .map_err(|e| KeyError::InvalidFormat(format!("Invalid UTF-8: {}", e)))
    }

    /// Store object storage credentials
    pub async fn store_object_storage_credentials(
        &self,
        access_key_id: &KeyId,
        access_key: &str,
        secret_key_id: &KeyId,
        secret_key: &str,
    ) -> KeyResult<()> {
        self.backend
            .store_key(
                access_key_id,
                KeyType::ObjectStorageKey,
                access_key.as_bytes(),
                None,
            )
            .await?;
        self.backend
            .store_key(
                secret_key_id,
                KeyType::ObjectStorageSecret,
                secret_key.as_bytes(),
                None,
            )
            .await?;
        Ok(())
    }

    /// Rotate a key
    pub async fn rotate_key(&self, key_id: &KeyId, new_value: &str) -> KeyResult<()> {
        info!("Rotating key: {}", key_id);
        self.backend
            .rotate_key(key_id, new_value.as_bytes())
            .await?;
        Ok(())
    }

    /// Get key metadata
    pub async fn get_metadata(&self, key_id: &KeyId) -> KeyResult<KeyMetadata> {
        self.backend.get_metadata(key_id).await
    }

    /// List all keys
    pub async fn list_keys(&self) -> KeyResult<Vec<KeyId>> {
        self.backend.list_keys().await
    }

    /// Check if key exists
    pub async fn key_exists(&self, key_id: &KeyId) -> bool {
        self.backend.key_exists(key_id).await
    }

    /// Delete a key
    pub async fn delete_key(&self, key_id: &KeyId) -> KeyResult<()> {
        self.backend.delete_key(key_id).await
    }

    /// Store an encryption key
    pub async fn store_encryption_key(
        &self,
        key_id: &KeyId,
        key_value: &[u8],
    ) -> KeyResult<()> {
        self.backend
            .store_key(key_id, KeyType::EncryptionKey, key_value, None)
            .await
    }

    /// Get encryption key
    pub async fn get_encryption_key(&self, key_id: &KeyId) -> KeyResult<Vec<u8>> {
        self.backend.get_key(key_id).await
    }
}

