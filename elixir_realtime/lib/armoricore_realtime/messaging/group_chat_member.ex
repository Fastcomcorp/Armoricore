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

defmodule ArmoricoreRealtime.Messaging.GroupChatMember do
  @moduledoc """
  Group chat member schema.
  Tracks users in group chats and their roles.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @roles ["admin", "moderator", "member"]

  schema "group_chat_members" do
    field :role, :string, default: "member"
    field :permissions, :map  # JSONB field for custom permissions
    field :joined_at, :utc_datetime
    field :left_at, :utc_datetime
    belongs_to :group_chat, ArmoricoreRealtime.Messaging.GroupChat
    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(group_chat_member, attrs) do
    group_chat_member
    |> cast(attrs, [:group_chat_id, :user_id, :role, :permissions, :joined_at, :left_at])
    |> validate_required([:group_chat_id, :user_id])
    |> validate_inclusion(:role, @roles)
  end
end

