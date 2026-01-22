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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateRoomMemberships do
  use Ecto.Migration

  def change do
    # Room memberships for chat rooms and streams
    # This table tracks which users are members of which rooms
    create table(:room_memberships, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :room_id, :string, null: false  # Room identifier (e.g., "chat:video:123", "stream:456")
      add :room_type, :string, null: false  # "chat", "stream", "presence"
      add :role, :string, default: "member"  # "owner", "moderator", "member"
      add :is_active, :boolean, default: true, null: false
      add :joined_at, :utc_datetime, null: false, default: fragment("NOW()")
      add :permissions, :jsonb, default: fragment("'{}'::jsonb")  # Custom permissions for this membership

      timestamps(type: :utc_datetime)
    end

    # Indexes for room_memberships
    create index(:room_memberships, [:user_id])
    create index(:room_memberships, [:room_id])
    create index(:room_memberships, [:room_type])
    create index(:room_memberships, [:user_id, :room_id])  # For membership checks
    create index(:room_memberships, [:room_id, :is_active])  # For active member queries
    create index(:room_memberships, [:user_id, :room_type, :is_active])  # For user's rooms by type

    # Unique constraint to prevent duplicate memberships
    create unique_index(:room_memberships, [:user_id, :room_id], name: :room_memberships_unique)
  end
end