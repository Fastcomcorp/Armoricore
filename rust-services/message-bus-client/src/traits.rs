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

//! Traits for message bus operations
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


use async_trait::async_trait;
use armoricore_types::Event;
use std::pin::Pin;
use futures::Stream;

/// Trait for message bus clients
#[async_trait]
pub trait MessageBusClient: Send + Sync {
    /// Publish an event to the message bus
    async fn publish(&self, event: &Event) -> Result<(), crate::error::MessageBusError>;

    /// Subscribe to events of a specific type
    /// Returns a stream of events
    fn subscribe(
        &self,
        event_type: &str,
    ) -> Pin<Box<dyn Stream<Item = std::result::Result<Event, crate::error::MessageBusError>> + Send + '_>>;

    /// Check if the client is connected
    async fn is_connected(&self) -> bool;

    /// Get the client type name
    fn client_type(&self) -> &str;
}

