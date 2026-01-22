# Video Resolutions and Audio Codecs

## Supported Video Resolutions

The Media Processor automatically determines which resolutions to generate based on the source video resolution. It supports resolutions up to **8K (4320p)**.

### Resolution Ladder

| Resolution | Dimensions | Bitrate | Use Case |
|------------|------------|---------|----------|
| **8K** | 7680×4320 | 50 Mbps | Ultra-ultra-high quality, professional cinema, future-proof content |
| **5K** | 5120×2880 | 25 Mbps | Ultra-high quality, professional content |
| **4K (UHD)** | 3840×2160 | 15 Mbps | High-end streaming, premium content |
| **1440p (QHD)** | 2560×1440 | 8 Mbps | High-quality desktop streaming |
| **1080p (Full HD)** | 1920×1080 | 5 Mbps | Standard high-definition |
| **720p (HD)** | 1280×720 | 2.5 Mbps | Standard definition |
| **480p (SD)** | 854×480 | 1 Mbps | Mobile/low bandwidth |
| **360p** | 640×360 | 600 kbps | Very low bandwidth |

### Automatic Resolution Selection

The processor automatically selects appropriate resolutions based on source:

- **Source ≥ 4320p**: Generates 8K, 5K, 4K, 1440p, 1080p, 720p, 480p, 360p
- **Source ≥ 2880p**: Generates 5K, 4K, 1440p, 1080p, 720p, 480p, 360p
- **Source ≥ 2160p**: Generates 4K, 1440p, 1080p, 720p, 480p, 360p
- **Source ≥ 1440p**: Generates 1440p, 1080p, 720p, 480p, 360p
- **Source ≥ 1080p**: Generates 1080p, 720p, 480p, 360p
- **Source ≥ 720p**: Generates 720p, 480p, 360p
- **Source ≥ 480p**: Generates 480p, 360p
- **Source < 480p**: Generates source resolution

### Example: 8K Source Video

For an 8K (7680×4320) source video, the processor will generate:
1. **8K variant** @ 50 Mbps
2. **5K variant** @ 25 Mbps
3. **4K variant** @ 15 Mbps
4. **1440p variant** @ 8 Mbps
5. **1080p variant** @ 5 Mbps
6. **720p variant** @ 2.5 Mbps
7. **480p variant** @ 1 Mbps
8. **360p variant** @ 600 kbps

### Example: 4K Source Video

For a 4K (3840×2160) source video, the processor will generate:
1. **4K variant** @ 15 Mbps
2. **1440p variant** @ 8 Mbps
3. **1080p variant** @ 5 Mbps
4. **720p variant** @ 2.5 Mbps
5. **480p variant** @ 1 Mbps
6. **360p variant** @ 600 kbps

The master playlist will reference all variants, allowing players to automatically select the best quality based on available bandwidth.

---

## Supported Audio Codecs

The Media Processor supports multiple audio codecs for maximum compatibility and quality.

### Audio Codec Options

| Codec | FFmpeg Codec | Bitrate | Compatibility | Quality | Type |
|-------|--------------|---------|---------------|---------|------|
| **AAC** (default) | `aac` | 128 kbps | Excellent (all platforms) | Good | Lossy |
| **Opus** | `libopus` | 128 kbps | Modern browsers, mobile | Excellent | Lossy |
| **MP3** | `libmp3lame` | 192 kbps | Universal (legacy) | Good | Lossy |
| **Vorbis** | `libvorbis` | 128 kbps | WebM containers | Good | Lossy |
| **FLAC** | `flac` | Variable (lossless) | Good (desktop, modern browsers) | Perfect | Lossless |

### Codec Selection

**Default:** AAC (best compatibility)

**Configuration:**
```bash
# Set audio codec via environment variable
AUDIO_CODEC=aac    # Default - best compatibility
AUDIO_CODEC=opus   # Better quality, modern browsers
AUDIO_CODEC=mp3    # Legacy support
AUDIO_CODEC=vorbis # WebM support
```

### Codec Recommendations

**For Maximum Compatibility:**
- Use **AAC** (default)
- Supported on: iOS, Android, Web, Desktop players
- Industry standard for HLS

**For Best Quality:**
- Use **Opus**
- Better compression efficiency
- Lower latency
- Supported on modern browsers and mobile

**For Legacy Support:**
- Use **MP3**
- Universal compatibility
- Higher bitrate needed for same quality

**For WebM:**
- Use **Vorbis**
- Required for WebM containers
- Good for DASH streaming

**For Lossless Audio:**
- Use **FLAC**
- Perfect quality (no compression artifacts)
- Larger file sizes (typically 2-5x lossy codecs)
- Best for: Music production, archival, high-end streaming
- Note: Not all players support FLAC in HLS (check compatibility)

---

## Video Codec

Currently using **H.264 (libx264)** for all video encoding.

### H.264 Settings

- **Preset:** `medium` (balance between speed and quality)
- **CRF:** `23` (constant rate factor for quality)
- **Profile:** High profile (automatic)
- **Level:** Auto-detected based on resolution

### Future Codec Support

Planned support for:
- **VP9** - Better compression, WebM
- **AV1** - Next-generation codec, royalty-free
- **HEVC (H.265)** - Better compression for 4K+

---

## Adaptive Streaming

The system generates a **master HLS playlist** that references all resolution variants. Players automatically:

1. **Detect bandwidth** - Measure available connection speed
2. **Select variant** - Choose appropriate resolution
3. **Switch dynamically** - Adjust quality as bandwidth changes
4. **Buffer management** - Optimize playback experience

### Master Playlist Example

```m3u8
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-STREAM-INF:BANDWIDTH=50000000,RESOLUTION=7680x4320
8K/playlist.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=25000000,RESOLUTION=5120x2880
5K/playlist.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=15000000,RESOLUTION=3840x2160
4K/playlist.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=8000000,RESOLUTION=2560x1440
1440p/playlist.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080
1080p/playlist.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2500000,RESOLUTION=1280x720
720p/playlist.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=1000000,RESOLUTION=854x480
480p/playlist.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=600000,RESOLUTION=640x360
360p/playlist.m3u8
```

---

## Performance Considerations

### 4K and 5K Processing

**CPU Requirements:**
- 4K transcoding: ~4-8 CPU cores recommended
- 5K transcoding: ~8-16 CPU cores recommended
- Processing time: 2-4x real-time (depends on hardware)

**Storage Requirements:**
- 4K video: ~15-20 GB per hour of content
- 5K video: ~25-30 GB per hour of content
- 8K video: ~50-60 GB per hour of content
- Multiple variants multiply storage needs

**Network Requirements:**
- 4K streaming: Minimum 15 Mbps connection
- 5K streaming: Minimum 25 Mbps connection
- 8K streaming: Minimum 50 Mbps connection
- CDN delivery strongly recommended (Akamai) for 8K

### Optimization Tips

1. **GPU Acceleration**: Use hardware encoding when available
   - NVIDIA: NVENC
   - AMD: AMF
   - Intel: QuickSync
   - Apple: VideoToolbox

2. **Parallel Processing**: Process multiple variants concurrently
3. **Storage Tiering**: Use different storage classes for variants
4. **CDN Caching**: Leverage Akamai CDN for global delivery

---

## Configuration Examples

### High-Quality Setup (4K/5K/8K)
```bash
# Process up to 8K
# Use Opus for best audio quality
AUDIO_CODEC=opus
```

### Compatibility-Focused Setup
```bash
# Standard resolutions
# Use AAC for maximum compatibility
AUDIO_CODEC=aac  # or omit for default
```

### Legacy Support Setup
```bash
# Include lower resolutions
# Use MP3 for universal support
AUDIO_CODEC=mp3
```

---

## Testing Resolutions

To test specific resolutions, you can modify the source video or use FFmpeg to create test files:

```bash
# Create 4K test video
ffmpeg -f lavfi -i testsrc2=duration=10:size=3840x2160:rate=30 \
  -c:v libx264 -preset medium -crf 23 test_4k.mp4

# Create 5K test video
ffmpeg -f lavfi -i testsrc2=duration=10:size=5120x2880:rate=30 \
  -c:v libx264 -preset medium -crf 23 test_5k.mp4

# Create 8K test video
ffmpeg -f lavfi -i testsrc2=duration=10:size=7680x4320:rate=30 \
  -c:v libx264 -preset medium -crf 23 test_8k.mp4
```

---

## Future Enhancements

- [ ] GPU-accelerated encoding (NVENC, VideoToolbox)
- [ ] VP9 codec support
- [ ] AV1 codec support
- [ ] HEVC (H.265) support
- [ ] Per-variant audio codec selection
- [ ] Dynamic bitrate adjustment
- [ ] Quality-based encoding (VMAF)

---

**Last Updated:** 2025-01-XX

