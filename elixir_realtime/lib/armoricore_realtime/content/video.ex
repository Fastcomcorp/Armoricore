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

defmodule ArmoricoreRealtime.Content.Video do
  @moduledoc """
  Video schema for CMS.
  Represents a video with metadata, linked to a media file.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @statuses ["draft", "processing", "ready", "live", "archived"]
  @visibilities ["public", "unlisted", "private"]

  schema "videos" do
    field :title, :string
    field :description, :string
    field :views, :integer, default: 0
    field :likes, :integer, default: 0
    field :dislikes, :integer, default: 0
    field :status, :string, default: "draft"
    field :visibility, :string, default: "public"
    field :published_at, :utc_datetime
    field :search_vector, :any, virtual: true  # PostgreSQL tsvector

    belongs_to :media, ArmoricoreRealtime.Media.MediaFile
    belongs_to :user, ArmoricoreRealtime.Accounts.User
    belongs_to :category, ArmoricoreRealtime.Content.Category
    many_to_many :tags, ArmoricoreRealtime.Content.Tag, join_through: "video_tags"

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(video, attrs) do
    video
    |> cast(attrs, [
      :media_id,
      :user_id,
      :title,
      :description,
      :category_id,
      :status,
      :visibility,
      :published_at,
      :views,
      :likes,
      :dislikes
    ])
    |> validate_required([:media_id, :user_id, :title, :status, :visibility])
    |> validate_length(:title, max: 255)
    |> validate_inclusion(:status, @statuses)
    |> validate_inclusion(:visibility, @visibilities)
    |> validate_published_at()
    |> unique_constraint(:media_id)
  end

  defp validate_published_at(changeset) do
    case get_change(changeset, :published_at) do
      nil ->
        changeset
      published_at ->
        if get_field(changeset, :status) == "ready" and is_nil(published_at) do
          put_change(changeset, :published_at, DateTime.utc_now())
        else
          changeset
        end
    end
  end

  @doc """
  Increment view count for a video.
  """
  def increment_views(changeset) do
    current_views = get_field(changeset, :views) || 0
    put_change(changeset, :views, current_views + 1)
  end

  @doc """
  Increment likes count for a video.
  """
  def increment_likes(changeset) do
    current_likes = get_field(changeset, :likes) || 0
    put_change(changeset, :likes, current_likes + 1)
  end

  @doc """
  Increment dislikes count for a video.
  """
  def increment_dislikes(changeset) do
    current_dislikes = get_field(changeset, :dislikes) || 0
    put_change(changeset, :dislikes, current_dislikes + 1)
  end
end

