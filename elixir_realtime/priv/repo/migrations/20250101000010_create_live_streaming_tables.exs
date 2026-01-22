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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateLiveStreamingTables do
  use Ecto.Migration

  def change do
    # Live streams
    create table(:live_streams, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :title, :string, null: false, size: 255
      add :description, :string
      add :stream_key, :string, null: false, size: 255
      add :rtmp_url, :string  # RTMP ingest URL
      add :hls_url, :string  # HLS playback URL
      add :dash_url, :string  # DASH playback URL
      add :status, :string, null: false, default: "scheduled"  # scheduled, live, ended, failed
      add :ingest_protocol, :string, default: "rtmp"  # rtmp, srt, webrtc
      add :is_recording_enabled, :boolean, default: false, null: false
      add :is_chat_enabled, :boolean, default: true, null: false
      add :is_comments_enabled, :boolean, default: true, null: false
      add :scheduled_start_at, :utc_datetime
      add :started_at, :utc_datetime
      add :ended_at, :utc_datetime
      add :duration_seconds, :integer, default: 0
      add :peak_viewers, :integer, default: 0, null: false
      add :current_viewers, :integer, default: 0, null: false
      add :total_views, :bigint, default: 0, null: false
      add :category_id, references(:categories, type: :uuid, on_delete: :nilify_all)
      
      timestamps(type: :utc_datetime)
    end

    # Stream keys (for authentication)
    create table(:stream_keys, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :stream_key, :string, null: false, size: 255
      add :name, :string, size: 255  # User-friendly name for the key
      add :is_active, :boolean, default: true, null: false
      add :last_used_at, :utc_datetime
      add :expires_at, :utc_datetime
      
      timestamps(type: :utc_datetime)
    end

    # Stream analytics (viewer tracking)
    create table(:stream_analytics, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :stream_id, references(:live_streams, type: :uuid, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :uuid, on_delete: :nilify_all)  # Null for anonymous viewers
      add :event_type, :string, null: false  # join, leave, quality_change, etc.
      add :event_data, :jsonb  # Additional event data
      add :viewer_ip, :string  # IP address (for analytics)
      add :user_agent, :string  # Browser/client info
      add :quality, :string  # Video quality (360p, 720p, 1080p, etc.)
      add :bitrate, :integer  # Bitrate in kbps
      add :timestamp, :utc_datetime, null: false
      
      timestamps(type: :utc_datetime)
    end

    # Stream recordings (for VOD conversion)
    create table(:stream_recordings, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :stream_id, references(:live_streams, type: :uuid, on_delete: :delete_all), null: false
      add :media_id, references(:media, type: :uuid, on_delete: :nilify_all)  # After VOD conversion
      add :recording_status, :string, null: false, default: "recording"  # recording, processing, ready, failed
      add :segment_count, :integer, default: 0
      add :total_size_bytes, :bigint, default: 0
      add :storage_path, :string  # Path to recorded segments
      add :started_at, :utc_datetime, null: false
      add :ended_at, :utc_datetime
      add :processed_at, :utc_datetime
      
      timestamps(type: :utc_datetime)
    end

    # Stream quality profiles (multi-bitrate configuration)
    create table(:stream_quality_profiles, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :stream_id, references(:live_streams, type: :uuid, on_delete: :delete_all), null: false
      add :quality_name, :string, null: false  # 360p, 720p, 1080p, etc.
      add :resolution_width, :integer, null: false
      add :resolution_height, :integer, null: false
      add :bitrate_kbps, :integer, null: false
      add :framerate, :integer, default: 30
      add :codec, :string, default: "h264"  # h264, h265, vp9
      add :hls_segment_url, :string  # CDN URL for HLS segments
      add :is_active, :boolean, default: true, null: false
      
      timestamps(type: :utc_datetime)
    end

    # Indexes for live_streams
    create unique_index(:live_streams, [:stream_key], name: :live_streams_stream_key_unique)
    create index(:live_streams, [:user_id])
    create index(:live_streams, [:status])
    create index(:live_streams, [:scheduled_start_at])
    create index(:live_streams, [:started_at])
    create index(:live_streams, [:category_id])
    create index(:live_streams, [:status, :started_at])  # For active streams query

    # Indexes for stream_keys
    create unique_index(:stream_keys, [:stream_key], name: :stream_keys_key_unique)
    create index(:stream_keys, [:user_id])
    create index(:stream_keys, [:is_active])
    create index(:stream_keys, [:expires_at])

    # Indexes for stream_analytics
    create index(:stream_analytics, [:stream_id])
    create index(:stream_analytics, [:user_id])
    create index(:stream_analytics, [:event_type])
    create index(:stream_analytics, [:timestamp])
    create index(:stream_analytics, [:stream_id, :timestamp])  # For stream analytics queries

    # Indexes for stream_recordings
    create index(:stream_recordings, [:stream_id])
    create index(:stream_recordings, [:recording_status])
    create index(:stream_recordings, [:media_id])

    # Indexes for stream_quality_profiles
    create index(:stream_quality_profiles, [:stream_id])
    create index(:stream_quality_profiles, [:is_active])
    create unique_index(:stream_quality_profiles, [:stream_id, :quality_name], name: :stream_quality_profiles_unique)
  end
end

