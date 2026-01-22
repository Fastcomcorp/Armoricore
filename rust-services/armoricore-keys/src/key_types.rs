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

//! Key type definitions
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


use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unique identifier for a key
pub type KeyId = String;

/// Key type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// JWT signing secret
    JwtSecret,
    /// API key (FCM, SMTP, etc.)
    ApiKey,
    /// Encryption key for data at rest
    EncryptionKey,
    /// Object storage access key
    ObjectStorageKey,
    /// Object storage secret key
    ObjectStorageSecret,
    /// APNS key
    ApnsKey,
    /// Generic secret
    Secret,
}

impl KeyType {
    /// Get default rotation period in days for this key type
    pub fn default_rotation_period_days(&self) -> u32 {
        match self {
            KeyType::JwtSecret => 90,
            KeyType::ApiKey => 180,
            KeyType::EncryptionKey => 365,
            KeyType::ObjectStorageKey => 180,
            KeyType::ObjectStorageSecret => 180,
            KeyType::ApnsKey => 365,
            KeyType::Secret => 180,
        }
    }
}

/// Key version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersion {
    /// Version number (incremental)
    pub version: u32,
    /// When this version was created
    pub created_at: i64,
    /// When this version expires (optional)
    pub expires_at: Option<i64>,
    /// Whether this is the active version
    pub is_active: bool,
    /// Key metadata
    pub metadata: HashMap<String, String>,
}

impl KeyVersion {
    pub fn new(version: u32) -> Self {
        Self {
            version,
            created_at: chrono::Utc::now().timestamp(),
            expires_at: None,
            is_active: true,
            metadata: HashMap::new(),
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            chrono::Utc::now().timestamp() > expires_at
        } else {
            false
        }
    }
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key identifier
    pub id: KeyId,
    /// Key type
    pub key_type: KeyType,
    /// Current active version
    pub current_version: u32,
    /// All versions of this key
    pub versions: Vec<KeyVersion>,
    /// When the key was created
    pub created_at: i64,
    /// When the key was last updated
    pub updated_at: i64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl KeyMetadata {
    pub fn new(id: KeyId, key_type: KeyType) -> Self {
        let now = chrono::Utc::now().timestamp();
        let initial_version = KeyVersion::new(1);
        
        Self {
            id,
            key_type,
            current_version: 1,
            versions: vec![initial_version],
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }

    pub fn get_active_version(&self) -> Option<&KeyVersion> {
        self.versions.iter().find(|v| v.is_active)
    }

    pub fn add_version(&mut self, version: KeyVersion) {
        // Deactivate all previous versions
        for v in &mut self.versions {
            v.is_active = false;
        }
        
        let version_num = version.version;
        self.versions.push(version);
        self.current_version = version_num;
        self.updated_at = chrono::Utc::now().timestamp();
    }
}

