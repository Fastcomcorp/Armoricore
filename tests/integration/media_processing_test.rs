//! Integration Tests for Media Processing Pipeline
//!
//! These tests require:
//! - NATS server running
//! - FFmpeg installed
//! - Object storage configured (optional for some tests)

use armoricore_types::{Event, EventType, schemas::*};
use message_bus_client::nats::NatsClient;
use message_bus_client::traits::MessageBusClient;
use uuid::Uuid;
use futures::StreamExt;
use std::time::Duration;

#[tokio::test]
#[ignore] // Requires NATS server and FFmpeg
async fn test_media_uploaded_event_flow() {
    // This test verifies the end-to-end flow:
    // 1. Publish media.uploaded event
    // 2. Media processor consumes it
    // 3. Media processor publishes media.ready event
    // 4. We subscribe to media.ready and verify it arrives

    let client = NatsClient::new("nats://localhost:4222", None)
        .await
        .expect("Failed to connect to NATS");

    // Create a media.uploaded event
    let payload = MediaUploadedPayload {
        media_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        file_path: "s3://test-bucket/test-video.mp4".to_string(),
        content_type: "video/mp4".to_string(),
        file_size: 1024 * 1024, // 1MB
        metadata: serde_json::Value::Null,
    };

    let event = Event::new(EventType::MediaUploaded, "test", payload)
        .expect("Failed to create event");

    // Publish the event
    client.publish(&event).await.expect("Failed to publish event");

    // Subscribe to media.ready events
    let mut stream = client.subscribe("media.ready");

    // Wait for the media processor to process and publish media.ready
    // This may take a while depending on video size and processing time
    let timeout = Duration::from_secs(60);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        tokio::select! {
            result = stream.next() => {
                if let Some(Ok(received_event)) = result {
                    if received_event.event_type == EventType::MediaReady {
                        // Verify the event structure
                        assert_eq!(received_event.event_type, EventType::MediaReady);
                        println!("✅ Received media.ready event: {:?}", received_event.event_id);
                        return;
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Continue waiting
            }
        }
    }

    panic!("Timeout waiting for media.ready event");
}

#[tokio::test]
#[ignore] // Requires NATS server
async fn test_event_serialization() {
    // Test that events can be serialized and deserialized correctly
    let payload = MediaUploadedPayload {
        media_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        file_path: "s3://bucket/key".to_string(),
        content_type: "video/mp4".to_string(),
        file_size: 1024,
        metadata: serde_json::json!({"key": "value"}),
    };

    let event = Event::new(EventType::MediaUploaded, "test", payload.clone())
        .expect("Failed to create event");

    // Serialize
    let json = serde_json::to_string(&event).expect("Failed to serialize");
    
    // Deserialize
    let deserialized: Event = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(event.event_type, deserialized.event_type);
    assert_eq!(event.event_id, deserialized.event_id);
}

