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

defmodule ArmoricoreRealtime.Rooms.RoomMembership do
  @moduledoc """
  Schema for room memberships.

  Tracks which users are members of which rooms, along with their role
  and permissions within that room. Supports different room types:
  - chat: Chat rooms for messaging
  - stream: Live stream comment rooms
  - presence: Presence tracking rooms
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  schema "room_memberships" do
    field :room_id, :string
    field :room_type, :string
    field :role, :string, default: "member"
    field :is_active, :boolean, default: true
    field :joined_at, :utc_datetime
    field :permissions, :map, default: %{}

    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(room_membership, attrs) do
    room_membership
    |> cast(attrs, [:user_id, :room_id, :room_type, :role, :is_active, :joined_at, :permissions])
    |> validate_required([:user_id, :room_id, :room_type])
    |> validate_inclusion(:room_type, ["chat", "stream", "presence"])
    |> validate_inclusion(:role, ["owner", "moderator", "member"])
    |> unique_constraint([:user_id, :room_id], name: :room_memberships_unique)
    |> put_change(:joined_at, DateTime.utc_now() |> DateTime.truncate(:second))
  end

  @doc """
  Creates a changeset for joining a room.
  """
  def join_changeset(attrs) do
    %__MODULE__{}
    |> changeset(attrs)
    |> put_change(:is_active, true)
  end

  @doc """
  Creates a changeset for leaving a room.
  """
  def leave_changeset(room_membership) do
    room_membership
    |> change()
    |> put_change(:is_active, false)
  end

  @doc """
  Creates a changeset for updating role.
  """
  def role_changeset(room_membership, role) do
    room_membership
    |> change()
    |> put_change(:role, role)
    |> validate_inclusion(:role, ["owner", "moderator", "member"])
  end
end