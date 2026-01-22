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

defmodule ArmoricoreRealtime.LiveStreaming.StreamQualityProfile do
  @moduledoc """
  Stream quality profile schema.
  Defines multi-bitrate encoding profiles for live streams.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @codecs ["h264", "h265", "vp9"]

  schema "stream_quality_profiles" do
    field :quality_name, :string
    field :resolution_width, :integer
    field :resolution_height, :integer
    field :bitrate_kbps, :integer
    field :framerate, :integer, default: 30
    field :codec, :string, default: "h264"
    field :hls_segment_url, :string
    field :is_active, :boolean, default: true
    belongs_to :stream, ArmoricoreRealtime.LiveStreaming.LiveStream, foreign_key: :stream_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(stream_quality_profile, attrs) do
    stream_quality_profile
    |> cast(attrs, [
      :stream_id, :quality_name, :resolution_width, :resolution_height,
      :bitrate_kbps, :framerate, :codec, :hls_segment_url, :is_active
    ])
    |> validate_required([:stream_id, :quality_name, :resolution_width, :resolution_height, :bitrate_kbps])
    |> validate_inclusion(:codec, @codecs)
    |> unique_constraint([:stream_id, :quality_name], name: :stream_quality_profiles_unique)
  end
end

