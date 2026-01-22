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

//! Media Processor Library
//!
//! This library provides media processing functionality including:
//! - Video transcoding to multiple bitrates
//! - HLS segmentation
//! - Thumbnail generation
//! - Remote file download
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


pub mod arcrtp_distributor;
pub mod cdn_uploader;
pub mod downloader;
pub mod encryption;
pub mod live_transcoder;
pub mod live_worker;
pub mod processor;
pub mod storage;
pub mod worker;
pub mod retry;

// Re-export encryption types for convenience
pub use encryption::{ContentEncryption, EncryptionMetadata};
// Re-export codec types for convenience
pub use processor::{VideoCodec, AudioCodec};

