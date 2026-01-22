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

defmodule ArmoricoreRealtime.LiveStreaming.StreamAnalytic do
  @moduledoc """
  Stream analytics schema.
  Tracks viewer events and stream metrics.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @event_types ["join", "leave", "quality_change", "buffering_start", "buffering_end", "error"]

  schema "stream_analytics" do
    field :event_type, :string
    field :event_data, :map  # JSONB field
    field :viewer_ip, :string
    field :user_agent, :string
    field :quality, :string
    field :bitrate, :integer
    field :timestamp, :utc_datetime
    belongs_to :stream, ArmoricoreRealtime.LiveStreaming.LiveStream, foreign_key: :stream_id
    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(stream_analytic, attrs) do
    stream_analytic
    |> cast(attrs, [
      :stream_id, :user_id, :event_type, :event_data, :viewer_ip, :user_agent,
      :quality, :bitrate, :timestamp
    ])
    |> validate_required([:stream_id, :event_type, :timestamp])
    |> validate_inclusion(:event_type, @event_types)
  end
end

