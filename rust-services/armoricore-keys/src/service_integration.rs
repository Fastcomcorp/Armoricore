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

//! Service integration helpers for using key management in services
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


use crate::key_store::KeyStore;
use crate::local_store::LocalKeyStore;
use crate::error::KeyResult;
use std::env;
use std::sync::Arc;
use tracing::{info, warn};

/// Initialize key store for a service
pub async fn init_key_store(storage_path: Option<&str>) -> KeyResult<Arc<KeyStore>> {
    let path = storage_path
        .map(|p| p.to_string())
        .or_else(|| env::var("KEY_STORAGE_PATH").ok())
        .unwrap_or_else(|| "./keys".to_string());

    info!(path = %path, "Initializing key store");

    let local_store = LocalKeyStore::new(&path, None).await?;
    let backend = Arc::new(local_store);
    let key_store = Arc::new(KeyStore::new(backend));

    Ok(key_store)
}

/// Get a key from key store with fallback to environment variable
pub async fn get_key_with_fallback(
    key_store: &KeyStore,
    key_id: &str,
    env_var: &str,
) -> Option<String> {
    // Try key store first
    match key_store.get_api_key(&key_id.to_string()).await {
        Ok(key) => {
            info!(key_id = key_id, "Retrieved key from key store");
            return Some(key);
        }
        Err(e) => {
            warn!(
                key_id = key_id,
                error = %e,
                "Key not found in key store, trying environment variable"
            );
        }
    }

    // Fallback to environment variable
    if let Ok(key) = env::var(env_var) {
        warn!(
            env_var = env_var,
            "Using key from environment variable (consider migrating to key store)"
        );
        return Some(key);
    }

    None
}

/// Get JWT secret with fallback
pub async fn get_jwt_secret(key_store: &KeyStore) -> Option<String> {
    get_key_with_fallback(key_store, "jwt.secret", "JWT_SECRET").await
}

/// Get FCM API key with fallback
pub async fn get_fcm_api_key(key_store: &KeyStore) -> Option<String> {
    get_key_with_fallback(key_store, "fcm.api_key", "FCM_API_KEY").await
}

/// Get APNS key ID with fallback
pub async fn get_apns_key_id(key_store: &KeyStore) -> Option<String> {
    get_key_with_fallback(key_store, "apns.key_id", "APNS_KEY_ID").await
}

/// Get APNS team ID with fallback
pub async fn get_apns_team_id(key_store: &KeyStore) -> Option<String> {
    get_key_with_fallback(key_store, "apns.team_id", "APNS_TEAM_ID").await
}

/// Get APNS bundle ID with fallback
pub async fn get_apns_bundle_id(key_store: &KeyStore) -> Option<String> {
    get_key_with_fallback(key_store, "apns.bundle_id", "APNS_BUNDLE_ID").await
}

/// Get SMTP username with fallback
pub async fn get_smtp_username(key_store: &KeyStore) -> Option<String> {
    get_key_with_fallback(key_store, "smtp.username", "SMTP_USERNAME").await
}

/// Get SMTP password with fallback
pub async fn get_smtp_password(key_store: &KeyStore) -> Option<String> {
    get_key_with_fallback(key_store, "smtp.password", "SMTP_PASSWORD").await
}

/// Get object storage access key with fallback
pub async fn get_object_storage_access_key(key_store: &KeyStore) -> Option<String> {
    get_key_with_fallback(
        key_store,
        "object_storage.access_key",
        "OBJECT_STORAGE_ACCESS_KEY",
    )
    .await
}

/// Get object storage secret key with fallback
pub async fn get_object_storage_secret_key(key_store: &KeyStore) -> Option<String> {
    get_key_with_fallback(
        key_store,
        "object_storage.secret_key",
        "OBJECT_STORAGE_SECRET_KEY",
    )
    .await
}

