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

//! Local encrypted key storage implementation
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
use crate::key_types::{KeyId, KeyMetadata, KeyType, KeyVersion};
use crate::kms::KeyManagementService;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info, warn};

/// Master key for encrypting stored keys
type MasterKey = [u8; 32];

/// Local encrypted key store
pub struct LocalKeyStore {
    /// Storage directory
    storage_path: PathBuf,
    /// Master encryption key (derived from master key or environment)
    master_key: MasterKey,
    /// In-memory cache of key metadata
    metadata_cache: tokio::sync::RwLock<HashMap<KeyId, KeyMetadata>>,
}

impl LocalKeyStore {
    /// Create a new local key store
    ///
    /// # Arguments
    /// * `storage_path` - Directory where encrypted keys will be stored
    /// * `master_key` - Optional master key (if None, will derive from environment or generate)
    pub async fn new<P: AsRef<Path>>(
        storage_path: P,
        master_key: Option<&[u8]>,
    ) -> KeyResult<Self> {
        let storage_path = storage_path.as_ref().to_path_buf();
        
        // Create storage directory if it doesn't exist
        fs::create_dir_all(&storage_path).await?;
        
        // Derive or use master key
        let master_key = if let Some(key) = master_key {
            if key.len() != 32 {
                return Err(KeyError::Configuration(
                    "Master key must be exactly 32 bytes".to_string(),
                ));
            }
            let mut mk = [0u8; 32];
            mk.copy_from_slice(key);
            mk
        } else {
            Self::derive_master_key()?
        };

        let store = Self {
            storage_path,
            master_key,
            metadata_cache: tokio::sync::RwLock::new(HashMap::new()),
        };

        // Load existing metadata
        store.load_metadata().await?;

        Ok(store)
    }

    /// Derive master key from environment variable or generate a new one
    fn derive_master_key() -> KeyResult<MasterKey> {
        // Try to get from environment
        if let Ok(key_str) = std::env::var("ARMORICORE_MASTER_KEY") {
            // If it's a hex string, decode it
            if let Ok(key_bytes) = hex::decode(&key_str) {
                if key_bytes.len() == 32 {
                    let mut mk = [0u8; 32];
                    mk.copy_from_slice(&key_bytes);
                    return Ok(mk);
                }
            }
            // Otherwise, derive from string using SHA256
            let hash = Sha256::digest(key_str.as_bytes());
            let mut mk = [0u8; 32];
            mk.copy_from_slice(&hash);
            return Ok(mk);
        }

        // Generate a new master key (should be set in production!)
        warn!("No ARMORICORE_MASTER_KEY found, generating a new one. This should be set in production!");
        let mut master_key = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut master_key);
        Ok(master_key)
    }

    /// Encrypt key value
    fn encrypt_key(&self, key_value: &[u8]) -> KeyResult<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.master_key.into());
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        let ciphertext = cipher
            .encrypt(&nonce, key_value)
            .map_err(|e| KeyError::Encryption(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt key value
    fn decrypt_key(&self, encrypted: &[u8]) -> KeyResult<Vec<u8>> {
        if encrypted.len() < 12 {
            return Err(KeyError::Decryption("Encrypted data too short".to_string()));
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new(&self.master_key.into());

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| KeyError::Decryption(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }

    /// Get path for key file
    fn key_path(&self, key_id: &KeyId) -> PathBuf {
        // Sanitize key_id for filesystem
        let sanitized = key_id.replace('/', "_").replace('\\', "_");
        self.storage_path.join(format!("{}.key", sanitized))
    }

    /// Get path for metadata file
    fn metadata_path(&self, key_id: &KeyId) -> PathBuf {
        let sanitized = key_id.replace('/', "_").replace('\\', "_");
        self.storage_path.join(format!("{}.meta", sanitized))
    }

    /// Load metadata from disk
    async fn load_metadata(&self) -> KeyResult<()> {
        let mut cache = self.metadata_cache.write().await;
        cache.clear();

        let mut entries = fs::read_dir(&self.storage_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "meta" {
                    if let Some(key_id) = path.file_stem().and_then(|s| s.to_str()) {
                        match fs::read_to_string(&path).await {
                            Ok(content) => {
                                match serde_json::from_str::<KeyMetadata>(&content) {
                                    Ok(metadata) => {
                                        cache.insert(key_id.to_string(), metadata);
                                    }
                                    Err(e) => {
                                        warn!("Failed to parse metadata for {}: {}", key_id, e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to read metadata for {}: {}", key_id, e);
                            }
                        }
                    }
                }
            }
        }

        debug!("Loaded {} key metadata entries", cache.len());
        Ok(())
    }

    /// Save metadata to disk
    async fn save_metadata(&self, metadata: &KeyMetadata) -> KeyResult<()> {
        let path = self.metadata_path(&metadata.id);
        let json = serde_json::to_string_pretty(metadata)?;
        fs::write(&path, json).await?;
        
        // Update cache
        let mut cache = self.metadata_cache.write().await;
        cache.insert(metadata.id.clone(), metadata.clone());
        
        Ok(())
    }

    /// Save encrypted key to disk
    async fn save_key(&self, key_id: &KeyId, encrypted_key: &[u8]) -> KeyResult<()> {
        let path = self.key_path(key_id);
        fs::write(&path, encrypted_key).await?;
        Ok(())
    }

    /// Load encrypted key from disk
    async fn load_key(&self, key_id: &KeyId) -> KeyResult<Vec<u8>> {
        let path = self.key_path(key_id);
        let encrypted = fs::read(&path).await?;
        Ok(encrypted)
    }
}

#[async_trait]
impl KeyManagementService for LocalKeyStore {
    async fn store_key(
        &self,
        key_id: &KeyId,
        key_type: KeyType,
        key_value: &[u8],
        metadata: Option<&str>,
    ) -> KeyResult<()> {
        // Check if key already exists
        if self.key_exists(key_id).await {
            return Err(KeyError::AlreadyExists(key_id.clone()));
        }

        info!("Storing new key: {} (type: {:?})", key_id, key_type);

        // Create metadata
        let mut key_metadata = KeyMetadata::new(key_id.clone(), key_type);
        if let Some(meta) = metadata {
            if let Ok(parsed) = serde_json::from_str::<HashMap<String, String>>(meta) {
                key_metadata.metadata = parsed;
            }
        }

        // Encrypt and save key
        let encrypted = self.encrypt_key(key_value)?;
        self.save_key(key_id, &encrypted).await?;

        // Save metadata
        self.save_metadata(&key_metadata).await?;

        debug!("Key stored successfully: {}", key_id);
        Ok(())
    }

    async fn get_key(&self, key_id: &KeyId) -> KeyResult<Vec<u8>> {
        let metadata = self.get_metadata(key_id).await?;
        let version = metadata.current_version;
        self.get_key_version(key_id, version).await
    }

    async fn get_key_version(&self, key_id: &KeyId, version: u32) -> KeyResult<Vec<u8>> {
        // Load encrypted key
        let encrypted = self.load_key(key_id).await?;

        // Decrypt
        let decrypted = self.decrypt_key(&encrypted)?;

        // Verify version matches (in a real implementation, we'd store versions separately)
        let metadata = self.get_metadata(key_id).await?;
        if metadata.current_version != version {
            warn!(
                "Requested version {} but current is {} for key {}",
                version, metadata.current_version, key_id
            );
        }

        Ok(decrypted)
    }

    async fn get_metadata(&self, key_id: &KeyId) -> KeyResult<KeyMetadata> {
        let cache = self.metadata_cache.read().await;
        cache
            .get(key_id)
            .cloned()
            .ok_or_else(|| KeyError::NotFound(key_id.clone()))
    }

    async fn rotate_key(
        &self,
        key_id: &KeyId,
        new_key_value: &[u8],
    ) -> KeyResult<KeyVersion> {
        // Get current metadata
        let mut metadata = self.get_metadata(key_id).await?;

        // Create new version
        let new_version_num = metadata.current_version + 1;
        let new_version = KeyVersion::new(new_version_num);

        // Set expiration for old version (optional - keep for rollback)
        if let Some(old_version) = metadata.versions.last_mut() {
            // Keep old version for 30 days for rollback
            old_version.expires_at = Some(
                chrono::Utc::now().timestamp() + (30 * 24 * 60 * 60)
            );
        }

        info!("Rotating key {} to version {}", key_id, new_version_num);

        // Encrypt and save new key
        let encrypted = self.encrypt_key(new_key_value)?;
        self.save_key(key_id, &encrypted).await?;

        // Update metadata
        metadata.add_version(new_version.clone());
        self.save_metadata(&metadata).await?;

        Ok(new_version)
    }

    async fn delete_key(&self, key_id: &KeyId) -> KeyResult<()> {
        info!("Deleting key: {}", key_id);

        // Remove files
        let key_path = self.key_path(key_id);
        let meta_path = self.metadata_path(key_id);

        if key_path.exists() {
            fs::remove_file(&key_path).await?;
        }

        if meta_path.exists() {
            fs::remove_file(&meta_path).await?;
        }

        // Remove from cache
        let mut cache = self.metadata_cache.write().await;
        cache.remove(key_id);

        Ok(())
    }

    async fn list_keys(&self) -> KeyResult<Vec<KeyId>> {
        let cache = self.metadata_cache.read().await;
        Ok(cache.keys().cloned().collect())
    }

    async fn key_exists(&self, key_id: &KeyId) -> bool {
        let cache = self.metadata_cache.read().await;
        cache.contains_key(key_id)
    }
}
