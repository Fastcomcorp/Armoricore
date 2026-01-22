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

// Simple script to publish a test media upload event to NATS
use async_nats::jetstream;
use bytes::Bytes;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nats_url = std::env::var("MESSAGE_BUS_URL")
        .unwrap_or_else(|_| "nats://localhost:4222".to_string());

    println!("🔌 Connecting to NATS: {}", nats_url);
    let client = async_nats::connect(&nats_url).await?;
    let jetstream = jetstream::new(client);

    // Ensure stream exists
    let stream_name = "armoricore-events";
    let _ = jetstream
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: stream_name.to_string(),
            subjects: vec!["armoricore.>".to_string()],
            max_age: std::time::Duration::from_secs(86400 * 7), // 7 days
            storage: async_nats::jetstream::stream::StorageType::File,
            ..Default::default()
        })
        .await;

    // Create test event
    let media_id = uuid::Uuid::new_v4().to_string();
    let event = json!({
        "event_type": "media.uploaded",
        "payload": {
            "media_id": media_id,
            "user_id": "00000000-0000-0000-0000-000000000000",
            "url": "https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/BigBuckBunny.mp4",
            "content_type": "video/mp4",
            "filename": "test-video.mp4",
            "file_size": 1000000
        }
    });

    println!("📤 Publishing media upload event...");
    println!("   Media ID: {}", media_id);
    println!("   Subject: armoricore.media_uploaded");

    let subject = "armoricore.media_uploaded";
    let event_bytes: Bytes = serde_json::to_vec(&event)?.into();
    jetstream
        .publish(subject, event_bytes)
        .await?;

    println!("✅ Event published successfully!");
    println!("");
    println!("📝 Next steps:");
    println!("   1. Check Media Processor logs: tail -f logs/media-processor.log");
    println!("   2. Check database: SELECT * FROM media WHERE id = '{}'", media_id);
    println!("   3. Check bucket: Verify files in your object storage (configure OBJECT_STORAGE_BUCKET)");
    println!("   4. Expected path: media/{}/", media_id);

    Ok(())
}
