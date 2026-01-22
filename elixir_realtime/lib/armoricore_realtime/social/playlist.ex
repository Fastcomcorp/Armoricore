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

defmodule ArmoricoreRealtime.Social.Playlist do
  @moduledoc """
  Playlist schema.
  User-created collections of videos.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @visibilities ["public", "unlisted", "private"]

  schema "playlists" do
    field :name, :string
    field :description, :string
    field :visibility, :string, default: "public"
    field :video_count, :integer, default: 0
    belongs_to :user, ArmoricoreRealtime.Accounts.User
    many_to_many :videos, ArmoricoreRealtime.Content.Video, join_through: "playlist_videos"

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(playlist, attrs) do
    playlist
    |> cast(attrs, [:user_id, :name, :description, :visibility])
    |> validate_required([:user_id, :name])
    |> validate_length(:name, max: 255)
    |> validate_inclusion(:visibility, @visibilities)
  end
end

