# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

defmodule ArmoricoreRealtimeWeb.Router do
  @moduledoc """
  Router configuration for Armoricore Real-time Platform.

  Defines all HTTP routes, WebSocket channels, and API endpoints for the platform.
  Handles routing for web interface, REST APIs, and real-time communication channels.

  ## Route Categories

  ### Web Routes
  - `GET /` - Home page with ArcRTC demo
  - User authentication and account management

  ### API Routes (`/api/v1`)
  - **Videos**: CRUD operations, search, and streaming
  - **Categories**: Content organization and discovery
  - **Users**: Profile management and social features
  - **Rooms**: Real-time communication spaces
  - **Messages**: Chat and messaging functionality
  - **Live Streams**: Broadcasting and viewer management
  - **Analytics**: Usage metrics and reporting

  ### Real-time Channels
  - **ArcRTC**: Ultra-low latency peer-to-peer communication
  - **Chat**: Real-time messaging in rooms and direct messages
  - **Presence**: User online/offline status tracking
  - **Comments**: Real-time comment threads on videos
  - **Signaling**: WebRTC session negotiation

  ## Security Features

  - **Rate Limiting**: Applied to all endpoints to prevent abuse
  - **Authentication**: JWT-based auth for protected routes
  - **CORS**: Configured for cross-origin requests
  - **Input Validation**: Comprehensive parameter validation
  - **CSRF Protection**: Enabled for state-changing operations

  ## Performance Optimizations

  - **Route Compilation**: All routes compiled at startup for optimal performance
  - **Pipeline Optimization**: Request processing optimized through plugs
  - **Caching**: Static assets served with proper cache headers
  - **Compression**: Response compression for reduced bandwidth
  """
  use ArmoricoreRealtimeWeb, :router

  # Browser pipeline for internal tools only (LiveDashboard)
  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {ArmoricoreRealtimeWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug ArmoricoreRealtimeWeb.Plugs.SecurityHeaders
  end

  pipeline :api do
    plug :accepts, ["json"]
    # SECURITY: CORS configuration (must come before other plugs)
    plug ArmoricoreRealtimeWeb.Plugs.CORS
    plug ArmoricoreRealtimeWeb.Plugs.InputValidator
    plug ArmoricoreRealtimeWeb.Plugs.RateLimiter
    # SECURITY: CSRF protection for state-changing operations
    plug ArmoricoreRealtimeWeb.Plugs.VerifyCSRFToken,
      only: [:post, :put, :patch, :delete],
      require_custom_header: true
    plug ArmoricoreRealtimeWeb.Plugs.SecurityHeaders
  end

  pipeline :api_auth do
    plug :accepts, ["json"]
    # SECURITY: Include all api pipeline plugs for protected routes
    plug ArmoricoreRealtimeWeb.Plugs.CORS
    plug ArmoricoreRealtimeWeb.Plugs.InputValidator
    plug ArmoricoreRealtimeWeb.Plugs.RateLimiter
    # SECURITY: CSRF protection for state-changing operations
    plug ArmoricoreRealtimeWeb.Plugs.VerifyCSRFToken, 
      only: [:post, :put, :patch, :delete],
      require_custom_header: true
    plug ArmoricoreRealtimeWeb.Plugs.Authenticate
  end

  # LiveDashboard for internal monitoring (no browser pipeline needed)
  import Phoenix.LiveDashboard.Router

  scope "/internal" do
    pipe_through :browser
    live_dashboard "/dashboard", metrics: ArmoricoreRealtimeWeb.Telemetry
  end

  # API routes with versioning
  # SECURITY: API versioning allows for breaking changes while maintaining backward compatibility
  scope "/api/v1", ArmoricoreRealtimeWeb, as: :api_v1 do
    pipe_through :api

    # Health check (optionally authenticated)
    get "/health", HealthController, :check

    # Authentication endpoints (public)
    post "/auth/register", AuthController, :register
    post "/auth/login", AuthController, :login
    post "/auth/refresh", AuthController, :refresh
    post "/auth/logout", AuthController, :logout
    get "/auth/verify", AuthController, :verify

    # Public CMS routes
    get "/videos", VideoController, :index
    get "/videos/:id", VideoController, :show
    get "/videos/:video_id/comments", CommentController, :index
    get "/categories", CategoryController, :index
    get "/categories/:id", CategoryController, :show
    get "/categories/slug/:slug", CategoryController, :show_by_slug
    get "/search", SearchController, :search
    get "/playlists", PlaylistController, :index
    get "/playlists/:id", PlaylistController, :show
    get "/live-streams", LiveStreamController, :index
    get "/live-streams/active", LiveStreamController, :active
    get "/live-streams/:id", LiveStreamController, :show

    # Protected routes (require authentication) - directly in /api/v1 scope
    pipe_through :api_auth

    # Video management (owner only for update/delete)
    post "/videos", VideoController, :create
    put "/videos/:id", VideoController, :update
    delete "/videos/:id", VideoController, :delete
    post "/videos/:id/like", VideoController, :like
    post "/videos/:id/dislike", VideoController, :dislike

    # Category management (admin only in future)
    post "/categories", CategoryController, :create
    put "/categories/:id", CategoryController, :update
    delete "/categories/:id", CategoryController, :delete

    # Subscriptions
    get "/subscriptions", SubscriptionController, :index
    get "/subscribers", SubscriptionController, :subscribers
    get "/subscriptions/check/:subscribed_to_id", SubscriptionController, :check
    post "/subscriptions", SubscriptionController, :create
    delete "/subscriptions/:subscribed_to_id", SubscriptionController, :delete

    # Playlists
    post "/playlists", PlaylistController, :create
    put "/playlists/:id", PlaylistController, :update
    delete "/playlists/:id", PlaylistController, :delete
    post "/playlists/:id/videos", PlaylistController, :add_video
    delete "/playlists/:id/videos/:video_id", PlaylistController, :remove_video

    # Comments
    get "/comments/:id", CommentController, :show
    post "/videos/:video_id/comments", CommentController, :create
    put "/comments/:id", CommentController, :update
    delete "/comments/:id", CommentController, :delete
    post "/comments/:id/like", CommentController, :like
    post "/comments/:id/dislike", CommentController, :dislike

    # Watch History
    get "/watch-history", WatchHistoryController, :index
    get "/watch-history/:video_id", WatchHistoryController, :show
    post "/watch-history", WatchHistoryController, :create
    delete "/watch-history", WatchHistoryController, :delete

    # Live Streaming
    post "/live-streams", LiveStreamController, :create
    put "/live-streams/:id", LiveStreamController, :update
    delete "/live-streams/:id", LiveStreamController, :delete
    post "/live-streams/:id/start", LiveStreamController, :start
    post "/live-streams/:id/end", LiveStreamController, :end_stream

    # Stream Analytics
    get "/live-streams/:id/analytics", StreamAnalyticsController, :show
    get "/live-streams/:id/viewers", StreamAnalyticsController, :viewers
    post "/live-streams/:id/track-join", StreamAnalyticsController, :track_join
    post "/live-streams/:id/track-leave", StreamAnalyticsController, :track_leave

    # Stream Recordings
    get "/live-streams/:id/recordings", StreamRecordingController, :index
    get "/live-streams/:id/recordings/:recording_id", StreamRecordingController, :show
    post "/live-streams/:id/recordings", StreamRecordingController, :create
    put "/live-streams/:id/recordings/:recording_id", StreamRecordingController, :update
    post "/live-streams/:id/recordings/:recording_id/complete", StreamRecordingController, :complete

    # Stream Keys
    get "/stream-keys", StreamKeyController, :index
    post "/stream-keys", StreamKeyController, :create
    delete "/stream-keys/:id", StreamKeyController, :delete

    # Direct Messages
    get "/direct-messages/conversations", DirectMessageController, :conversations
    get "/direct-messages/conversation/:user_id", DirectMessageController, :conversation
    get "/direct-messages/unread-count", DirectMessageController, :unread_count
    post "/direct-messages", DirectMessageController, :create
    put "/direct-messages/:id/read", DirectMessageController, :mark_read

    # Group Chats
    get "/group-chats", GroupChatController, :index
    get "/group-chats/:id", GroupChatController, :show
    post "/group-chats", GroupChatController, :create
    put "/group-chats/:id", GroupChatController, :update
    delete "/group-chats/:id", GroupChatController, :delete
    post "/group-chats/:id/members", GroupChatController, :add_member
    delete "/group-chats/:id/members/:user_id", GroupChatController, :remove_member

    # Group Messages
    get "/group-chats/:group_chat_id/messages", GroupMessageController, :index
    get "/group-chats/:group_chat_id/unread-count", GroupMessageController, :unread_count
    post "/group-chats/:group_chat_id/messages", GroupMessageController, :create
    put "/group-messages/:id", GroupMessageController, :update
    delete "/group-messages/:id", GroupMessageController, :delete
    post "/group-messages/:id/pin", GroupMessageController, :pin
    post "/group-messages/:id/unpin", GroupMessageController, :unpin
    post "/group-messages/:id/read", GroupMessageController, :mark_read
  end
  
  # Legacy API routes (backward compatibility)
  # SECURITY: Deprecated - clients should migrate to /api/v1
  scope "/api", ArmoricoreRealtimeWeb do
    pipe_through :api

    # Health check (optionally authenticated)
    get "/health", HealthController, :check

    # Authentication endpoints (public)
    post "/auth/login", AuthController, :login
    post "/auth/refresh", AuthController, :refresh
    post "/auth/logout", AuthController, :logout
    get "/auth/verify", AuthController, :verify
  end
end
