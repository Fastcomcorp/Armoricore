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

//! NATS JetStream implementation of the message bus client
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


use async_nats::jetstream::{self, Context};
use armoricore_types::Event;
use async_trait::async_trait;
use futures::Stream;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tracing::{error, info};

use crate::error::{MessageBusError, Result};
use crate::traits::MessageBusClient;

/// NATS JetStream message bus client
pub struct NatsClient {
    client: Arc<async_nats::Client>,
    jetstream: Arc<Context>,
    #[allow(dead_code)]
    stream_name: String,
    subject_prefix: String,
}

impl NatsClient {
    /// Create a new NATS client
    pub async fn new(url: &str, stream_name: Option<String>) -> Result<Self> {
        info!(url = url, "Connecting to NATS server");

        let client = async_nats::connect(url)
            .await
            .map_err(|e| MessageBusError::Connection(e.to_string()))?;

        let client_arc = Arc::new(client.clone());
        let jetstream = jetstream::new(client);

        let stream_name = stream_name.unwrap_or_else(|| "armoricore-events".to_string());
        let subject_prefix = "armoricore".to_string();

        // Ensure the stream exists
        let _ = Self::ensure_stream(&jetstream, &stream_name, &subject_prefix).await;

        info!(
            stream = stream_name,
            "NATS client initialized"
        );

        Ok(Self {
            client: client_arc,
            jetstream: Arc::new(jetstream),
            stream_name,
            subject_prefix,
        })
    }

    /// Ensure the JetStream stream exists
    async fn ensure_stream(
        jetstream: &Context,
        stream_name: &str,
        subject_prefix: &str,
    ) -> Result<()> {
        let _stream_manager = jetstream.get_or_create_stream(jetstream::stream::Config {
            name: stream_name.to_string(),
            subjects: vec![format!("{}.>", subject_prefix)],
            max_age: std::time::Duration::from_secs(86400 * 7), // 7 days retention
            storage: jetstream::stream::StorageType::File,
            ..Default::default()
        })
        .await
        .map_err(|e| MessageBusError::Connection(format!("Failed to create stream: {}", e)))?;

        info!(
            stream = stream_name,
            "Stream ensured"
        );

        Ok(())
    }

    /// Get the subject for an event type
    fn subject_for_event_type(&self, event_type: &str) -> String {
        format!("{}.{}", self.subject_prefix, event_type.replace(".", "_"))
    }

    #[allow(dead_code)]
    /// Get event type from subject
    fn event_type_from_subject(&self, subject: &str) -> String {
        subject
            .strip_prefix(&format!("{}.", self.subject_prefix))
            .unwrap_or(subject)
            .replace("_", ".")
    }
}

#[async_trait]
impl MessageBusClient for NatsClient {
    async fn publish(&self, event: &Event) -> Result<()> {
        let subject = self.subject_for_event_type(&format!("{:?}", event.event_type));
        let subject_for_log = subject.clone();
        
        let payload = serde_json::to_vec(event)
            .map_err(MessageBusError::Serialization)?;

        self.jetstream
            .publish(subject.clone(), payload.into())
            .await
            .map_err(|e| MessageBusError::Publish(e.to_string()))?;

        info!(
            event_type = ?event.event_type,
            event_id = %event.event_id,
            subject = subject_for_log,
            "Event published"
        );

        Ok(())
    }

    fn subscribe(
        &self,
        event_type: &str,
    ) -> Pin<Box<dyn Stream<Item = std::result::Result<Event, MessageBusError>> + Send + '_>> {
        let subject = self.subject_for_event_type(event_type);
        
        info!(
            subject = subject,
            event_type = event_type,
            "Subscribing to events"
        );

        let (tx, rx) = tokio::sync::mpsc::channel::<std::result::Result<Event, MessageBusError>>(100);
        let subject_clone = subject.clone();
        let client = Arc::clone(&self.client);
        
        // Spawn a task to handle the subscription
        tokio::spawn(async move {
            match client.subscribe(subject_clone.clone()).await {
                Ok(mut consumer) => {
                    info!(
                        subject = subject_clone,
                        "Subscription created, waiting for messages"
                    );

                    while let Some(nats_msg) = consumer.next().await {
                        match serde_json::from_slice::<Event>(&nats_msg.payload) {
                            Ok(event) => {
                                // For regular NATS (non-JetStream), we don't need to ack
                                // For JetStream, ack would be needed but requires different API
                                
                                if tx.send(Ok(event)).await.is_err() {
                                    error!("Receiver dropped, stopping subscription");
                                    break;
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to deserialize event");
                                let _ = tx.send(Err(MessageBusError::Serialization(e))).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to create subscription");
                    let _ = tx.send(Err(MessageBusError::Subscribe(e.to_string()))).await;
                }
            }
        });

        Box::pin(ReceiverStream::new(rx))
    }

    async fn is_connected(&self) -> bool {
        // NATS client connection status is checked implicitly
        // For now, we assume connected if the client exists
        true
    }

    fn client_type(&self) -> &str {
        "nats"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use armoricore_types::{Event, EventType, schemas::*};
    use uuid::Uuid;

    #[tokio::test]
    #[ignore] // Requires NATS server
    async fn test_publish_and_subscribe() {
        let client = NatsClient::new("nats://localhost:4222", None)
            .await
            .unwrap();

        // Create a test event
        let payload = NotificationRequestedPayload {
            user_id: Uuid::new_v4(),
            notification_type: NotificationType::Push,
            title: "Test".to_string(),
            body: "Test body".to_string(),
            data: serde_json::Value::Null,
        };

        let event = Event::new(EventType::NotificationRequested, "test", payload).unwrap();

        // Publish
        client.publish(&event).await.unwrap();

        // Subscribe
        let mut stream = client.subscribe("notification.requested");
        
        // Should receive the event
        let received = stream.next().await;
        assert!(received.is_some());
    }
}

