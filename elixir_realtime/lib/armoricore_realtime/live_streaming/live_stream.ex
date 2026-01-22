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

defmodule ArmoricoreRealtime.LiveStreaming.LiveStream do
  @moduledoc """
  Live stream schema.
  Represents a live streaming session.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ["scheduled", "live", "ended", "failed"]
  @ingest_protocols ["rtmp", "srt", "webrtc"]

  schema "live_streams" do
    field :title, :string
    field :description, :string
    field :stream_key, :string
    field :rtmp_url, :string
    field :hls_url, :string
    field :dash_url, :string
    field :status, :string, default: "scheduled"
    field :ingest_protocol, :string, default: "rtmp"
    field :is_recording_enabled, :boolean, default: false
    field :is_chat_enabled, :boolean, default: true
    field :is_comments_enabled, :boolean, default: true
    field :scheduled_start_at, :utc_datetime
    field :started_at, :utc_datetime
    field :ended_at, :utc_datetime
    field :duration_seconds, :integer, default: 0
    field :peak_viewers, :integer, default: 0
    field :current_viewers, :integer, default: 0
    field :total_views, :integer, default: 0
    belongs_to :user, ArmoricoreRealtime.Accounts.User
    belongs_to :category, ArmoricoreRealtime.Content.Category
    has_many :quality_profiles, ArmoricoreRealtime.LiveStreaming.StreamQualityProfile, foreign_key: :stream_id
    has_many :recordings, ArmoricoreRealtime.LiveStreaming.StreamRecording, foreign_key: :stream_id
    has_many :analytics, ArmoricoreRealtime.LiveStreaming.StreamAnalytic, foreign_key: :stream_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(live_stream, attrs) do
    live_stream
    |> cast(attrs, [
      :user_id, :title, :description, :stream_key, :rtmp_url, :hls_url, :dash_url,
      :status, :ingest_protocol, :is_recording_enabled, :is_chat_enabled,
      :is_comments_enabled, :scheduled_start_at, :started_at, :ended_at,
      :duration_seconds, :peak_viewers, :current_viewers, :total_views, :category_id
    ])
    |> validate_required([:user_id, :title, :stream_key])
    |> validate_length(:title, max: 255)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:ingest_protocol, @ingest_protocols)
    |> unique_constraint(:stream_key, name: :live_streams_stream_key_unique)
  end
end

