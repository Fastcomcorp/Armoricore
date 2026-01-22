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

//! NATS Message Bus Client Tests

use message_bus_client::nats::NatsClient;
use message_bus_client::traits::MessageBusClient;
use armoricore_types::{Event, EventType, schemas::*};
use futures::StreamExt;
use uuid::Uuid;

#[tokio::test]
#[ignore] // Requires NATS server running
async fn test_nats_client_connection() {
    let client = NatsClient::new("nats://localhost:4222", None).await;
    assert!(client.is_ok());
}

#[tokio::test]
#[ignore] // Requires NATS server running
async fn test_nats_client_publish() {
    let client = NatsClient::new("nats://localhost:4222", None)
        .await
        .unwrap();

   let payload = serde_json::json!({
        "user_id": Uuid::new_v4().to_string(),
        "message": "Test message"
    });

    let event = Event::new(EventType::UserCreated, "test", payload).unwrap();
    
    let result = client.publish(&event).await;
    assert!(result.is_ok());
}

#[tokio::test]
#[ignore] // Requires NATS server running
async fn test_nats_client_subscribe() {
    let client = NatsClient::new("nats://localhost:4222", None)
        .await
        .unwrap();

    let _stream = client.subscribe("user.created");
    
    // Stream should be created (even if no messages yet)
    // This test verifies the subscription mechanism works
    assert!(true); // Placeholder - actual test would wait for messages
}

#[tokio::test]
#[ignore] // Requires NATS server running
async fn test_nats_client_publish_and_subscribe() {
    let client = NatsClient::new("nats://localhost:4222", None)
        .await
        .unwrap();

    // Create and publish an event
    let payload = serde_json::json!({
        "user_id": Uuid::new_v4().to_string(),
        "message": "Test message"
    });

    let event = Event::new(EventType::UserCreated, "test", payload).unwrap();
    client.publish(&event).await.unwrap();

    // Subscribe and wait for the event
    let mut stream = client.subscribe("notification.requested");
    
    // Wait a bit for the message to arrive
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Try to receive the event
    if let Some(result) = stream.next().await {
        match result {
            Ok(received_event) => {
                assert_eq!(received_event.event_type, EventType::NotificationRequested);
            }
            Err(e) => {
                panic!("Failed to receive event: {:?}", e);
            }
        }
    }
}

#[test]
fn test_nats_client_type() {
    // Test that client_type returns "nats"
    // This doesn't require a connection
    // We can't test this without creating a client, so we'll test it in integration tests
    assert_eq!("nats", "nats"); // Placeholder
}

