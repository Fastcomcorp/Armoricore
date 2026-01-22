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

defmodule ArmoricoreRealtime.LiveStreaming.StreamKey do
  @moduledoc """
  Stream key schema.
  Authentication keys for RTMP/SRT/WebRTC ingest.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "stream_keys" do
    field :stream_key, :string
    field :name, :string
    field :is_active, :boolean, default: true
    field :last_used_at, :utc_datetime
    field :expires_at, :utc_datetime
    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(stream_key, attrs) do
    stream_key
    |> cast(attrs, [:user_id, :stream_key, :name, :is_active, :last_used_at, :expires_at])
    |> validate_required([:user_id, :stream_key])
    |> validate_length(:name, max: 255)
    |> validate_length(:stream_key, max: 255)
    |> unique_constraint(:stream_key, name: :stream_keys_key_unique)
  end
end

