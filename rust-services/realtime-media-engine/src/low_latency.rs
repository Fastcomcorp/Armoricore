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

//! Low-Latency Optimizations
//!
//! Implements zero-copy processing, batch operations, and other optimizations
//! to achieve sub-50ms latency targets.
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


use crate::error::{MediaEngineError, MediaEngineResult};
use crate::rtp_handler::RtpPacket;
use bytes::Bytes;
use std::collections::VecDeque;

/// Zero-copy packet buffer
pub struct ZeroCopyBuffer {
    /// Buffer of packets (using Bytes for zero-copy)
    packets: VecDeque<Bytes>,
    /// Maximum buffer size
    max_size: usize,
}

impl ZeroCopyBuffer {
    /// Create a new zero-copy buffer
    pub fn new(max_size: usize) -> Self {
        ZeroCopyBuffer {
            packets: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    /// Push packet (zero-copy if possible)
    pub fn push(&mut self, packet: Bytes) -> MediaEngineResult<()> {
        if self.packets.len() >= self.max_size {
            return Err(MediaEngineError::ConfigError(
                "Buffer full".to_string()
            ));
        }

        self.packets.push_back(packet);
        Ok(())
    }

    /// Pop packet (zero-copy)
    pub fn pop(&mut self) -> Option<Bytes> {
        self.packets.pop_front()
    }

    /// Get buffer size
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

/// Batch processor for packets
pub struct BatchProcessor {
    /// Batch size
    batch_size: usize,
    /// Current batch
    current_batch: Vec<RtpPacket>,
}

impl BatchProcessor {
    /// Create a new batch processor
    pub fn new(batch_size: usize) -> Self {
        BatchProcessor {
            batch_size,
            current_batch: Vec::with_capacity(batch_size),
        }
    }

    /// Add packet to batch
    pub fn add_packet(&mut self, packet: RtpPacket) -> Option<Vec<RtpPacket>> {
        self.current_batch.push(packet);

        if self.current_batch.len() >= self.batch_size {
            let batch = std::mem::take(&mut self.current_batch);
            self.current_batch.reserve(self.batch_size);
            Some(batch)
        } else {
            None
        }
    }

    /// Flush current batch (even if not full)
    pub fn flush(&mut self) -> Vec<RtpPacket> {
        std::mem::take(&mut self.current_batch)
    }

    /// Process batch of packets
    pub fn process_batch<F>(&mut self, mut processor: F) -> MediaEngineResult<()>
    where
        F: FnMut(&[RtpPacket]) -> MediaEngineResult<()>,
    {
        if !self.current_batch.is_empty() {
            processor(&self.current_batch)?;
            self.current_batch.clear();
        }
        Ok(())
    }
}

/// Optimized packet router with zero-copy
pub struct OptimizedPacketRouter {
    /// Zero-copy buffers per stream
    buffers: std::collections::HashMap<uuid::Uuid, ZeroCopyBuffer>,
    /// Batch processors per stream
    batch_processors: std::collections::HashMap<uuid::Uuid, BatchProcessor>,
}

impl OptimizedPacketRouter {
    /// Create a new optimized packet router
    pub fn new() -> Self {
        OptimizedPacketRouter {
            buffers: std::collections::HashMap::new(),
            batch_processors: std::collections::HashMap::new(),
        }
    }

    /// Route packet with zero-copy optimization
    pub fn route_packet_zero_copy(
        &mut self,
        stream_id: uuid::Uuid,
        packet: RtpPacket,
    ) -> MediaEngineResult<Option<Bytes>> {
        // Serialize packet once
        let serialized = Bytes::from(packet.serialize());
        
        // Store in zero-copy buffer
        let buffer = self.buffers.entry(stream_id).or_insert_with(|| {
            ZeroCopyBuffer::new(100) // Max 100 packets per stream
        });

        buffer.push(serialized.clone())?;

        // Return serialized packet (zero-copy if possible)
        Ok(Some(serialized))
    }

    /// Process batch of packets
    pub fn process_batch(
        &mut self,
        stream_id: uuid::Uuid,
        packets: Vec<RtpPacket>,
    ) -> MediaEngineResult<()> {
        // Get or create batch processor
        let processor = self.batch_processors.entry(stream_id).or_insert_with(|| {
            BatchProcessor::new(10) // Batch size of 10
        });

        // Collect batches to process
        let mut batches_to_process = Vec::new();

        // Add packets to batch
        for packet in packets {
            if let Some(batch) = processor.add_packet(packet) {
                batches_to_process.push(batch);
            }
        }

        // Process all batches
        for batch in batches_to_process {
            self.process_batch_internal(&batch)?;
        }

        Ok(())
    }

    /// Internal batch processing
    fn process_batch_internal(&mut self, batch: &[RtpPacket]) -> MediaEngineResult<()> {
        // Process all packets in batch together
        // This reduces per-packet overhead
        for packet in batch {
            // Route packet (simplified)
            let _ = packet.serialize();
        }
        Ok(())
    }

    /// Get buffer for stream
    pub fn get_buffer(&mut self, stream_id: uuid::Uuid) -> &mut ZeroCopyBuffer {
        self.buffers.entry(stream_id).or_insert_with(|| {
            ZeroCopyBuffer::new(100)
        })
    }
}

impl Default for OptimizedPacketRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Hardware timestamping support
pub struct HardwareTimestamp {
    /// Enable hardware timestamping
    pub enabled: bool,
    /// Timestamp offset (if hardware clock differs)
    pub offset: i64,
}

impl HardwareTimestamp {
    /// Create new hardware timestamp
    pub fn new(enabled: bool) -> Self {
        HardwareTimestamp {
            enabled,
            offset: 0,
        }
    }

    /// Get current timestamp (hardware if available)
    pub fn now_nanos(&self) -> u64 {
        if self.enabled {
            // In production, would use hardware timestamp
            // For now, use system time
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        } else {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_buffer() {
        let mut buffer = ZeroCopyBuffer::new(10);
        let data = Bytes::from("test");
        
        buffer.push(data.clone()).unwrap();
        assert_eq!(buffer.len(), 1);
        
        let popped = buffer.pop().unwrap();
        assert_eq!(popped, data);
    }

    #[test]
    fn test_batch_processor() {
        let mut processor = BatchProcessor::new(3);
        
        // Add 2 packets (shouldn't trigger batch)
        let packet1 = create_test_packet(1);
        let packet2 = create_test_packet(2);
        
        assert!(processor.add_packet(packet1).is_none());
        assert!(processor.add_packet(packet2).is_none());
        
        // Add 3rd packet (should trigger batch)
        let packet3 = create_test_packet(3);
        let batch = processor.add_packet(packet3);
        assert!(batch.is_some());
        assert_eq!(batch.unwrap().len(), 3);
    }

    fn create_test_packet(seq: u16) -> RtpPacket {
        RtpPacket {
            header: crate::rtp_handler::RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 96,
                sequence_number: seq,
                timestamp: 1000,
                ssrc: 12345,
                csrc: vec![],
                extension_header: None,
            },
            payload: Bytes::from("test"),
        }
    }
}

