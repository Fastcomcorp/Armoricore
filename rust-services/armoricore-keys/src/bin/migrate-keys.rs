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

//! Migration script to import environment variables into KeyManager (Rust)
//!
//! Usage:
//!   cargo run --bin migrate-keys --package armoricore-keys
//!
//! This script reads environment variables and stores them in the KeyManager
//! for secure key management.
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


use armoricore_keys::{init_key_store, KeyStore};
use std::env;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🔐 Key Migration Script");
    println!("{}", "=".repeat(50));
    println!();

    // Initialize key store
    let key_store = init_key_store(None).await?;

    let mut migrated = 0;
    let mut skipped = 0;
    let mut errors = 0;

    // JWT Secret
    let (m, s, e) = migrate_key(&key_store, "JWT_SECRET", "jwt.secret").await;
    migrated += m;
    skipped += s;
    errors += e;

    // FCM API Key
    let (m, s, e) = migrate_key(&key_store, "FCM_API_KEY", "fcm.api_key").await;
    migrated += m;
    skipped += s;
    errors += e;

    // APNS Keys
    let (m, s, e) = migrate_key(&key_store, "APNS_KEY_ID", "apns.key_id").await;
    migrated += m;
    skipped += s;
    errors += e;

    let (m, s, e) = migrate_key(&key_store, "APNS_TEAM_ID", "apns.team_id").await;
    migrated += m;
    skipped += s;
    errors += e;

    let (m, s, e) = migrate_key(&key_store, "APNS_BUNDLE_ID", "apns.bundle_id").await;
    migrated += m;
    skipped += s;
    errors += e;

    // SMTP Credentials
    let (m, s, e) = migrate_key(&key_store, "SMTP_USERNAME", "smtp.username").await;
    migrated += m;
    skipped += s;
    errors += e;

    let (m, s, e) = migrate_key(&key_store, "SMTP_PASSWORD", "smtp.password").await;
    migrated += m;
    skipped += s;
    errors += e;

    // Object Storage Credentials
    let (m, s, e) = migrate_key(
        &key_store,
        "OBJECT_STORAGE_ACCESS_KEY",
        "object_storage.access_key",
    )
    .await;
    migrated += m;
    skipped += s;
    errors += e;

    let (m, s, e) = migrate_key(
        &key_store,
        "OBJECT_STORAGE_SECRET_KEY",
        "object_storage.secret_key",
    )
    .await;
    migrated += m;
    skipped += s;
    errors += e;

    println!();
    println!("{}", "=".repeat(50));
    println!("Migration Summary:");
    println!("  ✅ Migrated: {}", migrated);
    println!("  ⏭️  Skipped: {}", skipped);
    println!("  ❌ Errors: {}", errors);
    println!();
    println!("✅ Migration complete!");
    println!();
    println!("Next steps:");
    println!("  1. Verify keys are stored");
    println!("  2. Test key retrieval");
    println!("  3. Once verified, you can remove environment variables");

    Ok(())
}

async fn migrate_key(
    key_store: &KeyStore,
    env_var: &str,
    key_id: &str,
) -> (usize, usize, usize) {
    match env::var(env_var) {
        Ok(value) => {
            // Check if key already exists
            if key_store.key_exists(&key_id.to_string()).await {
                warn!("{} -> {}: Already exists, skipping", env_var, key_id);
                (0, 1, 0)
            } else {
                match key_store.store_api_key(&key_id.to_string(), &value, None).await {
                    Ok(_) => {
                        info!("{} -> {}: Migrated successfully", env_var, key_id);
                        (1, 0, 0)
                    }
                    Err(e) => {
                        warn!("{} -> {}: Error - {}", env_var, key_id, e);
                        (0, 0, 1)
                    }
                }
            }
        }
        Err(_) => {
            warn!("{}: Not set, skipping", env_var);
            (0, 1, 0)
        }
    }
}

