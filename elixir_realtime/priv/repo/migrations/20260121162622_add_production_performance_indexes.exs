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

defmodule ArmoricoreRealtime.Repo.Migrations.AddProductionPerformanceIndexes do
  use Ecto.Migration

  def change do
    # Performance indexes for production deployment
    # These indexes are designed to optimize common query patterns and improve database performance

    # Users table indexes
    create index(:users, [:email])
    create index(:users, [:inserted_at])
    create index(:users, [:updated_at])

    # Videos table indexes - critical for content discovery and search
    create index(:videos, [:user_id])
    create index(:videos, [:inserted_at])
    create index(:videos, [:updated_at])
    create index(:videos, [:deleted_at])  # For filtering deleted content
    create index(:videos, [:view_count])  # For popular content queries
    create index(:videos, [:duration])    # For duration-based filtering

    # Composite indexes for common queries
    create index(:videos, [:user_id, :inserted_at])  # User's recent videos
    create index(:videos, [:inserted_at, :view_count])  # Popular recent videos
    create index(:videos, [:deleted_at, :inserted_at])  # Active videos by date

    # Full-text search optimization
    create index(:videos, ["(to_tsvector('english', title || ' ' || description))"],
                  name: :videos_search_vector_idx,
                  using: :gin)

    # Categories table indexes
    create index(:categories, [:parent_id])  # For category hierarchy queries
    create index(:categories, [:inserted_at])

    # Video categories junction table
    create index(:video_categories, [:video_id])
    create index(:video_categories, [:category_id])
    create index(:video_categories, [:video_id, :category_id])  # Composite for joins

    # Rooms and room memberships - critical for real-time features
    create index(:rooms, [:created_by_id])
    create index(:rooms, [:inserted_at])
    create index(:rooms, [:is_private])  # For public room filtering

    create index(:room_memberships, [:user_id])
    create index(:room_memberships, [:room_id])
    create index(:room_memberships, [:joined_at])
    create index(:room_memberships, [:user_id, :room_id])  # Composite for membership checks
    create index(:room_memberships, [:room_id, :joined_at])  # Room member activity

    # Messages - critical for chat performance
    create index(:messages, [:room_id])
    create index(:messages, [:user_id])
    create index(:messages, [:inserted_at])
    create index(:messages, [:room_id, :inserted_at])  # Room message history
    create index(:messages, [:user_id, :inserted_at])  # User's message history

    # Group messages and related tables
    create index(:group_messages, [:group_chat_id])
    create index(:group_messages, [:user_id])
    create index(:group_messages, [:inserted_at])
    create index(:group_messages, [:group_chat_id, :inserted_at])

    create index(:group_chats, [:created_by_id])
    create index(:group_chats, [:inserted_at])

    create index(:group_chat_memberships, [:group_chat_id])
    create index(:group_chat_memberships, [:user_id])
    create index(:group_chat_memberships, [:joined_at])

    # Stream analytics - for monitoring and reporting
    create index(:stream_analytics, [:stream_id])
    create index(:stream_analytics, [:user_id])
    create index(:stream_analytics, [:timestamp])
    create index(:stream_analytics, [:stream_id, :timestamp])  # Time-series queries
    create index(:stream_analytics, [:event_type, :timestamp])  # Event type analysis

    # Watch history - for user engagement tracking
    create index(:watch_history, [:user_id])
    create index(:watch_history, [:video_id])
    create index(:watch_history, [:watched_at])
    create index(:watch_history, [:user_id, :watched_at])  # User's watch history
    create index(:watch_history, [:video_id, :watched_at])  # Video popularity

    # Playlists and social features
    create index(:playlists, [:user_id])
    create index(:playlists, [:inserted_at])
    create index(:playlists, [:is_public])

    create index(:playlist_videos, [:playlist_id])
    create index(:playlist_videos, [:video_id])
    create index(:playlist_videos, [:position])

    # Comments and reactions - for social engagement
    create index(:comments, [:video_id])
    create index(:comments, [:user_id])
    create index(:comments, [:inserted_at])
    create index(:comments, [:parent_id])  # For nested comments
    create index(:comments, [:video_id, :inserted_at])  # Video comment timeline

    create index(:comment_reactions, [:comment_id])
    create index(:comment_reactions, [:user_id])
    create index(:comment_reactions, [:reaction_type])

    # Live streams - critical for real-time streaming
    create index(:live_streams, [:user_id])
    create index(:live_streams, [:inserted_at])
    create index(:live_streams, [:started_at])
    create index(:live_streams, [:ended_at])
    create index(:live_streams, [:is_live])  # Active streams filter

    # Stream keys - for security
    create index(:stream_keys, [:user_id])
    create index(:stream_keys, [:key_hash], unique: true)  # Unique constraint
    create index(:stream_keys, [:expires_at])  # Expiration cleanup

    # Subscriptions - for monetization
    create index(:subscriptions, [:subscriber_id])
    create index(:subscriptions, [:creator_id])
    create index(:subscriptions, [:status])
    create index(:subscriptions, [:expires_at])
    create index(:subscriptions, [:subscriber_id, :creator_id])  # Unique subscriptions

    # Notifications - for user engagement
    create index(:notifications, [:user_id])
    create index(:notifications, [:inserted_at])
    create index(:notifications, [:read_at])
    create index(:notifications, [:user_id, :read_at])  # Unread notifications

    # Rate limiting (if using database for rate limiting)
    # Note: Primary rate limiting is done in ETS/Redis, but these indexes
    # support any database-based rate limiting fallback
    create index(:rate_limits, [:identifier])
    create index(:rate_limits, [:expires_at])

    # Partial indexes for better performance on filtered queries
    create index(:videos, [:inserted_at],
                  where: "deleted_at IS NULL",
                  name: :videos_active_inserted_at_idx)

    create index(:users, [:inserted_at],
                  where: "email_confirmed_at IS NOT NULL",
                  name: :users_confirmed_inserted_at_idx)

    create index(:live_streams, [:started_at],
                  where: "is_live = true",
                  name: :live_streams_active_started_at_idx)

    # JSONB indexes for metadata fields (if using PostgreSQL advanced features)
    # These can be added if the application uses JSONB fields extensively
    # create index(:videos, [:metadata], using: :gin)
    # create index(:users, [:preferences], using: :gin)

    # Note: These indexes should be created with CONCURRENTLY in production
    # to avoid blocking writes during migration. In a production environment,
    # you would run these as separate operations:
    #
    # CREATE INDEX CONCURRENTLY idx_videos_user_created ON videos (user_id, inserted_at);
    # etc.
  end
end
