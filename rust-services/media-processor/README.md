# Media Processor

The Media Processor consumes `media.uploaded` events from the message bus and processes media files:
- Transcodes video to multiple bitrates (5K, 4K, 1440p, 1080p, 720p, 480p, 360p)
- Creates HLS segments for adaptive streaming
- Supports multiple audio codecs (AAC, Opus, MP3, Vorbis)
- Generates thumbnails
- Uploads processed files to object storage (S3-compatible)
- Publishes `media.ready` events

## Features

- ✅ Consumes `media.uploaded` events from NATS
- ✅ Media processing pipeline (mock implementation)
- ✅ Object storage integration (mock implementation)
- ✅ Publishes `media.ready` events on completion
- ✅ Graceful shutdown on Ctrl+C
- ✅ Structured logging

## Prerequisites

### Required
- NATS server running (default: `nats://localhost:4222`)
- Object storage credentials configured

### Optional (for actual processing)
- **FFmpeg** - For video transcoding and thumbnail generation
  ```bash
  brew install ffmpeg
  ```
- **Rust 1.88+** - For AWS SDK S3 integration (or use rusoto_s3 alternative)

## Usage

### Configuration

Set the following environment variables:

```bash
MESSAGE_BUS_URL=nats://localhost:4222
MESSAGE_BUS_STREAM_NAME=armoricore-events

# Object Storage (Required) - Akamai Object Storage (S3-compatible)
OBJECT_STORAGE_ENDPOINT=https://your-bucket.akamai.com
# Or use: OBJECT_STORAGE_ENDPOINT=s3://your-bucket
OBJECT_STORAGE_ACCESS_KEY=your-akamai-access-key
OBJECT_STORAGE_SECRET_KEY=your-akamai-secret-key
OBJECT_STORAGE_BUCKET=your-bucket-name
OBJECT_STORAGE_REGION=akamai  # Optional, defaults to "akamai"

# Video Codec (Optional, defaults to H.264)
# Options: h264, vp9, av1
VIDEO_CODEC=h264

# Audio Codec (Optional, defaults to AAC)
# Options: aac, opus, mp3, vorbis, flac
AUDIO_CODEC=aac

# Upload Retry Configuration (Optional)
UPLOAD_MAX_RETRIES=3
UPLOAD_RETRY_INITIAL_DELAY=1
UPLOAD_RETRY_MAX_DELAY=60
UPLOAD_RETRY_MULTIPLIER=2.0

LOG_LEVEL=info
```

### Running

```bash
# From the rust-services directory
cargo run --bin media-processor
```

## Architecture

```
┌──────────────┐
│ Message Bus  │
│  (NATS)      │
└──────┬───────┘
       │
       │ media.uploaded
       ▼
┌──────────────────┐
│ Media Processor   │
├──────────────────┤
│ 1. Consume event │
│ 2. Process media │
│    - Transcode   │
│    - Segment     │
│    - Thumbnails  │
│ 3. Upload to S3  │
│ 4. Publish result│
└──────────────────┘
       │
       ├─► media.ready (success)
```

## Processing Pipeline

1. **Receive Event**: Consume `media.uploaded` event
2. **Download Source**: Download media file from source location (S3/HTTP/HTTPS)
3. **Extract Metadata**: Get video duration and resolution
4. **Determine Resolutions**: Automatically select appropriate bitrates (up to 5K)
5. **Transcode**: Convert to multiple bitrates with selected audio codec
6. **Segment**: Create HLS segments (.m3u8, .ts files) for each variant
7. **Master Playlist**: Generate master playlist referencing all variants
8. **Thumbnails**: Extract frames for thumbnails
9. **Upload**: Upload all processed files (variants, segments, thumbnails) to Akamai
10. **Publish**: Publish `media.ready` event with playback URLs

## Current Implementation Status

### ✅ Implemented
- Event consumption from NATS
- Event publishing (`media.ready`)
- Worker architecture
- Error handling and logging
- Configuration management

### ✅ Implemented
- **FFmpeg Processing**: Full FFmpeg integration
  - Video transcoding to HLS format with multiple bitrates
    - **8K (4320p)** @ 50 Mbps
    - **5K (2880p)** @ 25 Mbps
    - **4K (2160p)** @ 15 Mbps
    - **1440p (QHD)** @ 8 Mbps
    - **1080p (Full HD)** @ 5 Mbps
    - **720p (HD)** @ 2.5 Mbps
    - **480p (SD)** @ 1 Mbps
    - **360p** @ 600 kbps
  - Automatic resolution selection based on source
  - Master HLS playlist for adaptive streaming
  - **MP4 Generation** ✅ (NEW)
    - Generates MP4 files for each resolution variant
    - H.264 video codec (libx264)
    - Progressive download support (faststart)
    - Optimized for streaming
    - One MP4 file per resolution (e.g., `1080p.mp4`, `720p.mp4`)
  - **Multiple Audio Codecs:**
    - **AAC** (default) - Best compatibility, lossy
    - **Opus** - Better quality, modern browsers, lossy
    - **MP3** - Legacy support, lossy
    - **Vorbis** - WebM support, lossy
    - **FLAC** - Lossless, high quality, larger files
  - Thumbnail generation
  - Metadata extraction (duration, resolution)
  - Uses command-line FFmpeg (reliable and flexible)
  
- **Akamai Object Storage Integration**: Full S3-compatible client using rusoto_s3
  - Supports custom endpoints for Akamai
  - Handles credentials and region configuration
  - Uploads master and variant HLS playlists, segments, and thumbnails
  - Uploads MP4 files for each resolution
  - Generates public CDN URLs
  
- **Remote File Download**: Full support for S3 and HTTP/HTTPS downloads
  - Downloads from `s3://bucket/key` URLs
  - Downloads from `http://` and `https://` URLs
  - Progress logging for large files
  - Automatic temporary file management

### ✅ Implemented
- **Remote File Download**: Full support for S3 and HTTP/HTTPS downloads
  - Downloads from `s3://bucket/key` URLs
  - Downloads from `http://` and `https://` URLs
  - Progress logging for large files
  - Automatic temporary file management

### 📋 TODO
- [ ] Add retry logic for failed uploads
- [ ] Add progress tracking
- [ ] Add metrics and monitoring
- [ ] Support multiple codecs (H.264, VP9, AV1)
- [x] **Audio-Only Processing** - ✅ Implemented (FLAC, MP3, AAC, Opus, Vorbis)
- [x] **MP4 Generation** - ✅ Implemented
- [ ] **DASH manifest generation** - Architecture ready, implementation pending
- [ ] **Live Streaming** - Architecture designed, implementation pending
- [ ] **CDN Edge Hooks** - Architecture designed, implementation pending
- [ ] Add GPU acceleration support

## Testing

You can test the worker by publishing a `media.uploaded` event to NATS:

```json
{
  "event_type": "media.uploaded",
  "event_id": "uuid",
  "timestamp": "2025-01-01T00:00:00Z",
  "source": "php-backend",
  "payload": {
    "media_id": "uuid",
    "user_id": "uuid",
    "file_path": "s3://bucket/original/video.mp4",
    "content_type": "video/mp4",
    "file_size": 1048576,
    "metadata": {}
  }
}
```

## Production Deployment

### Requirements
1. **FFmpeg**: Install on the server
2. **Rust 1.88+**: For AWS SDK, or use rusoto_s3
3. **Object Storage**: S3-compatible storage configured
4. **Resources**: CPU-intensive workload, scale accordingly

### Scaling
- Scale horizontally based on queue depth
- Each worker processes one media file at a time
- Consider GPU acceleration for faster transcoding

## Future Enhancements

- GPU-accelerated transcoding (NVENC, VideoToolbox)
- Real-time streaming processing
- Multiple format support (MP4, WebM, etc.)
- Audio processing and normalization
- Content analysis and metadata extraction
- Automatic quality optimization

