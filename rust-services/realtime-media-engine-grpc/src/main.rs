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

//! gRPC server for realtime-media-engine
//!
//! Provides a gRPC interface for Elixir/Phoenix to interact with the Rust media engine.
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


// Include generated proto code
pub mod armoricore_media_engine {
    tonic::include_proto!("armoricore.media_engine");
}

mod service;

use service::MediaEngineService;
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = "0.0.0.0:50051".parse()?;
    info!("Starting gRPC server on {}", addr);

    let service = MediaEngineService::new().await?;

    Server::builder()
        .add_service(crate::armoricore_media_engine::media_engine_server::MediaEngineServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}

