# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp
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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateEngagementTables do
  use Ecto.Migration

  def change do
    # Video likes/dislikes (user-specific, tracks individual user actions)
    create table(:video_likes, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :video_id, references(:videos, type: :uuid, on_delete: :delete_all), null: false
      add :action, :string, null: false  # "like" or "dislike"
      
      timestamps(type: :utc_datetime)
    end

    # User subscriptions (subscribe to channels/users)
    create table(:user_subscriptions, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :subscriber_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :subscribed_to_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :notifications_enabled, :boolean, default: true, null: false
      
      timestamps(type: :utc_datetime)
    end

    # Playlists
    create table(:playlists, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :name, :string, null: false, size: 255
      add :description, :string
      add :visibility, :string, null: false, default: "public"  # public, unlisted, private
      add :video_count, :integer, default: 0, null: false
      
      timestamps(type: :utc_datetime)
    end

    # Playlist videos (many-to-many)
    create table(:playlist_videos, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :playlist_id, references(:playlists, type: :uuid, on_delete: :delete_all), null: false
      add :video_id, references(:videos, type: :uuid, on_delete: :delete_all), null: false
      add :position, :integer, null: false, default: 0  # Order in playlist
      add :added_at, :utc_datetime, null: false, default: fragment("NOW()")
      
      timestamps(type: :utc_datetime)
    end

    # Watch history (tracks user viewing progress)
    create table(:watch_history, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :video_id, references(:videos, type: :uuid, on_delete: :delete_all), null: false
      add :watch_progress, :integer, default: 0, null: false  # Seconds watched
      add :watch_percentage, :float, default: 0.0, null: false  # 0.0 to 1.0
      add :completed, :boolean, default: false, null: false  # Watched to end
      add :last_watched_at, :utc_datetime, null: false
      
      timestamps(type: :utc_datetime)
    end

    # Comments (persistent storage for comments channel)
    create table(:comments, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :video_id, references(:videos, type: :uuid, on_delete: :delete_all), null: false
      add :content, :text, null: false
      add :likes, :integer, default: 0, null: false
      add :dislikes, :integer, default: 0, null: false
      add :parent_id, references(:comments, type: :uuid, on_delete: :nilify_all)  # For threaded comments
      add :is_pinned, :boolean, default: false, null: false
      add :is_deleted, :boolean, default: false, null: false
      
      timestamps(type: :utc_datetime)
    end

    # Comment likes/dislikes (user-specific)
    create table(:comment_likes, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :comment_id, references(:comments, type: :uuid, on_delete: :delete_all), null: false
      add :action, :string, null: false  # "like" or "dislike"
      
      timestamps(type: :utc_datetime)
    end

    # Indexes for video_likes
    create unique_index(:video_likes, [:user_id, :video_id], name: :video_likes_user_video_unique)
    create index(:video_likes, [:video_id])
    create index(:video_likes, [:user_id])
    create index(:video_likes, [:action])

    # Indexes for user_subscriptions
    create unique_index(:user_subscriptions, [:subscriber_id, :subscribed_to_id], name: :subscriptions_unique)
    create index(:user_subscriptions, [:subscriber_id])
    create index(:user_subscriptions, [:subscribed_to_id])

    # Indexes for playlists
    create index(:playlists, [:user_id])
    create index(:playlists, [:visibility])
    create index(:playlists, [:inserted_at])

    # Indexes for playlist_videos
    create unique_index(:playlist_videos, [:playlist_id, :video_id], name: :playlist_videos_unique)
    create index(:playlist_videos, [:playlist_id])
    create index(:playlist_videos, [:video_id])
    create index(:playlist_videos, [:position])

    # Indexes for watch_history
    create unique_index(:watch_history, [:user_id, :video_id], name: :watch_history_user_video_unique)
    create index(:watch_history, [:user_id])
    create index(:watch_history, [:video_id])
    create index(:watch_history, [:last_watched_at])
    create index(:watch_history, [:completed])

    # Indexes for comments
    create index(:comments, [:video_id])
    create index(:comments, [:user_id])
    create index(:comments, [:parent_id])
    create index(:comments, [:inserted_at])
    create index(:comments, [:is_pinned])
    create index(:comments, [:is_deleted])
    create index(:comments, [:video_id, :inserted_at])  # For fetching comments by video

    # Indexes for comment_likes
    create unique_index(:comment_likes, [:user_id, :comment_id], name: :comment_likes_user_comment_unique)
    create index(:comment_likes, [:comment_id])
    create index(:comment_likes, [:action])
  end
end

