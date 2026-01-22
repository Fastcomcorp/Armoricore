# Armoricore API Reference

> Complete REST API documentation for Armoricore Real-time Platform

## Base URL
```
https://api.domain.com/v1
```

## Authentication

All API requests require authentication using JWT tokens.

### Headers
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

### Authentication Endpoints

#### POST `/auth/register`
Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "password_confirmation": "securepassword123",
  "username": "johndoe"
}
```

**Response (201):**
```json
{
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "johndoe",
    "inserted_at": "2025-01-21T10:00:00Z"
  }
}
```

#### POST `/auth/login`
Authenticate and receive JWT token.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "johndoe"
  }
}
```

#### POST `/auth/refresh`
Refresh JWT token.

**Request Body:**
```json
{
  "token": "current_jwt_token"
}
```

#### POST `/auth/logout`
Invalidate JWT token.

---

## Videos API

### GET `/videos`
List videos with pagination and filtering.

**Query Parameters:**
- `page` (integer): Page number (default: 1)
- `limit` (integer): Items per page (default: 20, max: 100)
- `category_id` (uuid): Filter by category
- `user_id` (uuid): Filter by user
- `search` (string): Search in title and description
- `sort` (string): Sort by `created_at`, `view_count`, `duration` (default: `created_at`)
- `order` (string): Sort order `asc` or `desc` (default: `desc`)

**Response (200):**
```json
{
  "data": [
    {
      "id": "uuid",
      "title": "Sample Video",
      "description": "A sample video",
      "duration": 300,
      "view_count": 1500,
      "thumbnail_url": "https://cdn.armoricore.com/thumbnails/uuid.jpg",
      "hls_playlist_url": "https://cdn.armoricore.com/hls/uuid/playlist.m3u8",
      "user_id": "uuid",
      "category_id": "uuid",
      "inserted_at": "2025-01-21T10:00:00Z",
      "updated_at": "2025-01-21T10:00:00Z"
    }
  ],
  "meta": {
    "page": 1,
    "limit": 20,
    "total_count": 150,
    "total_pages": 8
  }
}
```

### POST `/videos`
Upload a new video.

**Content-Type:** `multipart/form-data`

**Form Data:**
- `file` (file): Video file (mp4, avi, mov, etc.)
- `title` (string): Video title (required)
- `description` (string): Video description
- `category_id` (uuid): Category ID

**Response (201):**
```json
{
  "data": {
    "id": "uuid",
    "title": "My Video",
    "description": "Video description",
    "status": "processing",
    "user_id": "uuid"
  }
}
```

### GET `/videos/{id}`
Get detailed video information.

**Response (200):**
```json
{
  "data": {
    "id": "uuid",
    "title": "Sample Video",
    "description": "A sample video",
    "duration": 300,
    "view_count": 1500,
    "thumbnail_url": "https://cdn.armoricore.com/thumbnails/uuid.jpg",
    "hls_playlist_url": "https://cdn.armoricore.com/hls/uuid/playlist.m3u8",
    "user": {
      "id": "uuid",
      "username": "johndoe",
      "avatar_url": "https://cdn.armoricore.com/avatars/uuid.jpg"
    },
    "category": {
      "id": "uuid",
      "name": "Technology",
      "slug": "technology"
    },
    "tags": ["tutorial", "elixir"],
    "inserted_at": "2025-01-21T10:00:00Z"
  }
}
```

### PUT `/videos/{id}`
Update video metadata.

**Request Body:**
```json
{
  "title": "Updated Title",
  "description": "Updated description",
  "category_id": "uuid"
}
```

### DELETE `/videos/{id}`
Delete a video.

**Response (204):** No content

### GET `/videos/search`
Search videos with full-text search.

**Query Parameters:**
- `q` (string): Search query (required)
- `limit` (integer): Results limit (default: 20)

**Response (200):**
```json
{
  "data": [
    {
      "id": "uuid",
      "title": "Search Result",
      "description": "Matching description",
      "score": 0.8
    }
  ],
  "meta": {
    "query": "search term",
    "total_results": 25
  }
}
```

---

## Categories API

### GET `/categories`
List all categories.

**Response (200):**
```json
{
  "data": [
    {
      "id": "uuid",
      "name": "Technology",
      "slug": "technology",
      "description": "Tech tutorials and reviews",
      "parent_id": null,
      "video_count": 150
    }
  ]
}
```

### GET `/categories/{id}`
Get category details with subcategories.

### POST `/categories`
Create a new category (admin only).

---

## User Management API

### GET `/users/me`
Get current user profile.

**Response (200):**
```json
{
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "username": "johndoe",
    "full_name": "John Doe",
    "bio": "Software developer",
    "avatar_url": "https://cdn.armoricore.com/avatars/uuid.jpg",
    "website": "https://johndoe.com",
    "location": "San Francisco, CA",
    "joined_at": "2025-01-21T10:00:00Z",
    "stats": {
      "videos_count": 25,
      "followers_count": 150,
      "following_count": 75,
      "total_views": 50000
    }
  }
}
```

### PUT `/users/me`
Update user profile.

### GET `/users/{id}`
Get public user profile.

### GET `/users/me/videos`
Get user's videos.

---

## Rooms & Chat API

### GET `/rooms`
List available rooms.

**Query Parameters:**
- `type` (string): `public`, `private`, `my` (default: `public`)
- `limit` (integer): Results limit

**Response (200):**
```json
{
  "data": [
    {
      "id": "uuid",
      "name": "General Discussion",
      "description": "General chat room",
      "is_private": false,
      "member_count": 25,
      "last_message_at": "2025-01-21T10:30:00Z",
      "created_by": {
        "id": "uuid",
        "username": "admin"
      }
    }
  ]
}
```

### POST `/rooms`
Create a new room.

**Request Body:**
```json
{
  "name": "My Room",
  "description": "Room description",
  "is_private": false
}
```

### GET `/rooms/{id}`
Get room details.

### POST `/rooms/{id}/join`
Join a room.

### POST `/rooms/{id}/leave`
Leave a room.

### GET `/rooms/{id}/messages`
Get room messages.

**Query Parameters:**
- `before` (datetime): Get messages before this time
- `limit` (integer): Message limit (default: 50)

**Response (200):**
```json
{
  "data": [
    {
      "id": "uuid",
      "content": "Hello everyone!",
      "user_id": "uuid",
      "room_id": "uuid",
      "inserted_at": "2025-01-21T10:30:00Z",
      "user": {
        "username": "johndoe",
        "avatar_url": "https://..."
      }
    }
  ]
}
```

---

## Live Streaming API

### GET `/live-streams`
List active live streams.

### POST `/live-streams`
Start a new live stream.

**Request Body:**
```json
{
  "title": "My Live Stream",
  "description": "Live streaming description",
  "category_id": "uuid",
  "quality_profile": "high"
}
```

**Response (201):**
```json
{
  "data": {
    "id": "uuid",
    "title": "My Live Stream",
    "stream_key": "live_abc123def456",
    "rtmp_url": "rtmp://stream.armoricore.com/live",
    "hls_url": "https://cdn.armoricore.com/hls/live/uuid/playlist.m3u8",
    "status": "starting"
  }
}
```

### GET `/live-streams/{id}`
Get live stream details.

### PUT `/live-streams/{id}`
Update live stream metadata.

### DELETE `/live-streams/{id}`
End live stream.

---

## Analytics API

### GET `/analytics/videos/{video_id}`
Get video analytics.

**Response (200):**
```json
{
  "data": {
    "video_id": "uuid",
    "total_views": 1500,
    "unique_viewers": 1200,
    "average_watch_time": 180,
    "completion_rate": 0.75,
    "views_by_day": [
      {"date": "2025-01-20", "views": 100},
      {"date": "2025-01-21", "views": 150}
    ],
    "views_by_country": [
      {"country": "US", "views": 800},
      {"country": "UK", "views": 300}
    ]
  }
}
```

### GET `/analytics/users/me`
Get user analytics.

### GET `/analytics/platform`
Get platform-wide analytics (admin only).

---

## Social Features API

### POST `/videos/{id}/like`
Like a video.

### DELETE `/videos/{id}/like`
Unlike a video.

### GET `/videos/{id}/likes`
Get video likes.

### POST `/comments`
Create a comment.

**Request Body:**
```json
{
  "video_id": "uuid",
  "content": "Great video!",
  "parent_id": "uuid"  // For replies
}
```

### GET `/videos/{id}/comments`
Get video comments with threading.

### POST `/users/{id}/follow`
Follow a user.

### DELETE `/users/{id}/follow`
Unfollow a user.

---

## Real-time WebSocket Channels

### ArcRTC Channel
**Topic:** `arcrtc:{session_id}`

**Messages:**
```javascript
// Connect to ArcRTC session
{"event": "arc_connect", "payload": {
  "sdp": "v=0\r\no=- 123...",
  "ice_candidates": [],
  "capabilities": {"audio_codecs": ["opus"], "video_codecs": ["VP9"]}
}}

// Start media stream
{"event": "arc_stream_start", "payload": {
  "config": {"type": "both", "quality": "high"}
}}

// Stop stream
{"event": "arc_stream_stop", "payload": {"stream_id": "uuid"}}
```

### Chat Channel
**Topic:** `room:{room_id}`

**Messages:**
```javascript
// Send message
{"event": "message", "payload": {"content": "Hello!"}}

// Join room
{"event": "phx_join", "payload": {}}
```

### Comments Channel
**Topic:** `comments:{video_id}`

**Messages:**
```javascript
// New comment
{"event": "comment", "payload": {
  "content": "Great video!",
  "video_id": "uuid"
}}
```

---

## Error Responses

All API errors follow this format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input parameters",
    "details": {
      "field": "email",
      "reason": "invalid_format"
    }
  }
}
```

### Common Error Codes

- `UNAUTHORIZED` (401): Invalid or missing authentication
- `FORBIDDEN` (403): Insufficient permissions
- `NOT_FOUND` (404): Resource not found
- `VALIDATION_ERROR` (422): Invalid input data
- `RATE_LIMITED` (429): Too many requests
- `INTERNAL_ERROR` (500): Server error

---

## Rate Limiting

API requests are rate limited to prevent abuse:

- **Authenticated requests**: 1000 per hour per user
- **Video uploads**: 5 per hour per user
- **Search requests**: 100 per minute per IP
- **Real-time messages**: 100 per minute per user

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1642761600
```

---

## Webhooks

Armoricore supports webhooks for real-time notifications:

### Video Processing Webhooks
```json
{
  "event": "video.processed",
  "data": {
    "video_id": "uuid",
    "status": "completed",
    "duration": 300,
    "thumbnail_url": "https://...",
    "hls_playlist_url": "https://..."
  }
}
```

### Live Stream Webhooks
```json
{
  "event": "stream.started",
  "data": {
    "stream_id": "uuid",
    "user_id": "uuid",
    "viewer_count": 0
  }
}
```

### Configure webhooks in your dashboard or via API.

---

## SDKs & Libraries

### JavaScript SDK
```bash
npm install @armoricore/sdk
```

### Mobile SDKs
- **iOS**: `pod 'ArmoricoreRTC'`
- **Android**: `implementation 'com.armoricore:arbrtc:1.0.0'`

### API Clients
- **Python**: `pip install armoricore-api`
- **Ruby**: `gem install armoricore`
- **Go**: `go get github.com/Fastcomcorp/Armoricore/api-client`

---

## Changelog

### v1.0.0 (Current)
- Initial public API release
- Full ArcRTC integration
- Complete video management
- Real-time chat and rooms
- Live streaming support
- Comprehensive analytics

---

For more detailed information, visit our [API Documentation]contact support@fastcomcorp.com.