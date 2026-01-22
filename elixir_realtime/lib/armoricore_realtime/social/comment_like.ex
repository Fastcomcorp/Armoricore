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

defmodule ArmoricoreRealtime.Social.CommentLike do
  @moduledoc """
  Comment like/dislike schema.
  Tracks individual user actions on comments.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @actions ["like", "dislike"]

  schema "comment_likes" do
    field :action, :string
    belongs_to :user, ArmoricoreRealtime.Accounts.User
    belongs_to :comment, ArmoricoreRealtime.Social.Comment

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(comment_like, attrs) do
    comment_like
    |> cast(attrs, [:user_id, :comment_id, :action])
    |> validate_required([:user_id, :comment_id, :action])
    |> validate_inclusion(:action, @actions)
    |> unique_constraint([:user_id, :comment_id], name: :comment_likes_user_comment_unique)
  end
end

