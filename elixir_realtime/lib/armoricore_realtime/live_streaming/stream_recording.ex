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

defmodule ArmoricoreRealtime.LiveStreaming.StreamRecording do
  @moduledoc """
  Stream recording schema.
  Tracks recording sessions for VOD conversion.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @recording_statuses ["recording", "processing", "ready", "failed"]

  schema "stream_recordings" do
    field :recording_status, :string, default: "recording"
    field :segment_count, :integer, default: 0
    field :total_size_bytes, :integer, default: 0
    field :storage_path, :string
    field :started_at, :utc_datetime
    field :ended_at, :utc_datetime
    field :processed_at, :utc_datetime
    belongs_to :stream, ArmoricoreRealtime.LiveStreaming.LiveStream, foreign_key: :stream_id
    belongs_to :media, ArmoricoreRealtime.Media.MediaFile, foreign_key: :media_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(stream_recording, attrs) do
    stream_recording
    |> cast(attrs, [
      :stream_id, :media_id, :recording_status, :segment_count, :total_size_bytes,
      :storage_path, :started_at, :ended_at, :processed_at
    ])
    |> validate_required([:stream_id, :started_at])
    |> validate_inclusion(:recording_status, @recording_statuses)
  end
end

