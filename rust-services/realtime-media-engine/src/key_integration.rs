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

//! Integration with armoricore-keys for SRTP key management
//!
//! Provides secure key storage and retrieval for SRTP sessions.
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
use crate::srtp_pipeline::{SrtpConfig, SrtpPipeline};
use armoricore_keys::{KeyId, KeyStore};
use std::sync::Arc;
use uuid::Uuid;

/// SRTP key manager that integrates with armoricore-keys
pub struct SrtpKeyManager {
    key_store: Arc<KeyStore>,
}

impl SrtpKeyManager {
    /// Create a new SRTP key manager
    pub fn new(key_store: Arc<KeyStore>) -> Self {
        SrtpKeyManager { key_store }
    }

    /// Generate and store SRTP keys for a session
    pub async fn create_session_keys(
        &self,
        session_id: &Uuid,
        _ssrc: u32,
    ) -> MediaEngineResult<(KeyId, KeyId)> {
        use rand::RngCore;

        // Generate master key (16 bytes for AES-128)
        let mut master_key = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut master_key);

        // Generate master salt (14 bytes)
        let mut master_salt = vec![0u8; 14];
        rand::thread_rng().fill_bytes(&mut master_salt);

        // Create key IDs
        let key_id = KeyId::from(format!("srtp:master_key:{}", session_id));
        let salt_id = KeyId::from(format!("srtp:master_salt:{}", session_id));

        // Store keys
        self.key_store
            .store_encryption_key(&key_id, &master_key)
            .await
            .map_err(|e| MediaEngineError::KeyError(e.to_string()))?;

        self.key_store
            .store_encryption_key(&salt_id, &master_salt)
            .await
            .map_err(|e| MediaEngineError::KeyError(e.to_string()))?;

        Ok((key_id, salt_id))
    }

    /// Retrieve SRTP keys for a session
    pub async fn get_session_keys(
        &self,
        session_id: &Uuid,
    ) -> MediaEngineResult<(Vec<u8>, Vec<u8>)> {
        let key_id = KeyId::from(format!("srtp:master_key:{}", session_id));
        let salt_id = KeyId::from(format!("srtp:master_salt:{}", session_id));

        let master_key = self
            .key_store
            .get_encryption_key(&key_id)
            .await
            .map_err(|e| MediaEngineError::KeyError(e.to_string()))?;

        let master_salt = self
            .key_store
            .get_encryption_key(&salt_id)
            .await
            .map_err(|e| MediaEngineError::KeyError(e.to_string()))?;

        // Validate key sizes
        if master_key.len() != 16 {
            return Err(MediaEngineError::KeyError(
                format!("Invalid master key size: {} (expected 16)", master_key.len())
            ));
        }
        if master_salt.len() != 14 {
            return Err(MediaEngineError::KeyError(
                format!("Invalid master salt size: {} (expected 14)", master_salt.len())
            ));
        }

        Ok((master_key, master_salt))
    }

    /// Create SRTP pipeline from stored keys
    pub async fn create_srtp_pipeline(
        &self,
        session_id: &Uuid,
        ssrc: u32,
        roc: u32,
    ) -> MediaEngineResult<SrtpPipeline> {
        let (master_key, master_salt) = self.get_session_keys(session_id).await?;

        let config = SrtpConfig {
            master_key,
            master_salt,
            ssrc,
            roc,
        };

        SrtpPipeline::new(config)
    }

    /// Delete session keys (cleanup)
    pub async fn delete_session_keys(&self, session_id: &Uuid) -> MediaEngineResult<()> {
        let key_id = KeyId::from(format!("srtp:master_key:{}", session_id));
        let salt_id = KeyId::from(format!("srtp:master_salt:{}", session_id));

        // Delete keys (ignore errors if they don't exist)
        let _ = self.key_store.delete_key(&key_id).await;
        let _ = self.key_store.delete_key(&salt_id).await;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use armoricore_keys::{local_store::LocalKeyStore, KeyStore};
    use std::path::PathBuf;
    use tempfile::TempDir;

    async fn create_test_key_store() -> (Arc<KeyStore>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage_path = temp_dir.path().to_path_buf();
        
        let local_store = LocalKeyStore::new(&storage_path, None).await.unwrap();
        let key_store = Arc::new(KeyStore::new(Arc::new(local_store)));
        
        (key_store, temp_dir)
    }

    #[tokio::test]
    async fn test_create_and_retrieve_session_keys() {
        let (key_store, _temp_dir) = create_test_key_store().await;
        let manager = SrtpKeyManager::new(key_store);
        let session_id = Uuid::new_v4();

        // Create keys
        let (key_id, salt_id) = manager.create_session_keys(&session_id, 12345).await.unwrap();
        assert!(!key_id.to_string().is_empty());
        assert!(!salt_id.to_string().is_empty());

        // Retrieve keys
        let (master_key, master_salt) = manager.get_session_keys(&session_id).await.unwrap();
        assert_eq!(master_key.len(), 16);
        assert_eq!(master_salt.len(), 14);
    }

    #[tokio::test]
    async fn test_create_srtp_pipeline() {
        let (key_store, _temp_dir) = create_test_key_store().await;
        let manager = SrtpKeyManager::new(key_store);
        let session_id = Uuid::new_v4();

        // Create keys
        manager.create_session_keys(&session_id, 12345).await.unwrap();

        // Create pipeline
        let pipeline = manager.create_srtp_pipeline(&session_id, 12345, 0).await.unwrap();
        assert_eq!(pipeline.current_roc(), 0);
    }
}

