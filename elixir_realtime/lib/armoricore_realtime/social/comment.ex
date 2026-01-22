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

defmodule ArmoricoreRealtime.Social.Comment do
  @moduledoc """
  Comment schema.
  Persistent storage for video comments.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "comments" do
    field :content, :string
    field :likes, :integer, default: 0
    field :dislikes, :integer, default: 0
    field :is_pinned, :boolean, default: false
    field :is_deleted, :boolean, default: false
    belongs_to :user, ArmoricoreRealtime.Accounts.User
    belongs_to :video, ArmoricoreRealtime.Content.Video
    belongs_to :parent, ArmoricoreRealtime.Social.Comment  # For threaded comments
    has_many :replies, ArmoricoreRealtime.Social.Comment, foreign_key: :parent_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(comment, attrs) do
    comment
    |> cast(attrs, [:user_id, :video_id, :content, :parent_id, :is_pinned])
    |> validate_required([:user_id, :video_id, :content])
    |> validate_length(:content, min: 1, max: 5000)
    |> validate_no_self_reply()
  end

  defp validate_no_self_reply(changeset) do
    parent_id = get_field(changeset, :parent_id)
    if parent_id do
      # Could add validation here to prevent self-replies if needed
      changeset
    else
      changeset
    end
  end
end

