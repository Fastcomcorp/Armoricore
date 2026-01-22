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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateMessagingTables do
  use Ecto.Migration

  def change do
    # Direct messages (one-on-one conversations)
    create table(:direct_messages, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :sender_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :recipient_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :content, :text
      add :message_type, :string, null: false, default: "text"  # text, image, video, voice, file
      add :media_id, references(:media, type: :uuid, on_delete: :nilify_all)
      add :status, :string, null: false, default: "sent"  # sent, delivered, read
      add :is_encrypted, :boolean, default: false, null: false
      add :encrypted_content, :text  # For E2EE messages
      add :read_at, :utc_datetime
      
      timestamps(type: :utc_datetime)
    end

    # Group chats
    create table(:group_chats, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :name, :string, null: false, size: 255
      add :description, :string
      add :creator_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :avatar_media_id, references(:media, type: :uuid, on_delete: :nilify_all)
      add :is_encrypted, :boolean, default: false, null: false
      add :member_count, :integer, default: 0, null: false
      
      timestamps(type: :utc_datetime)
    end

    # Group chat members
    create table(:group_chat_members, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :group_chat_id, references(:group_chats, type: :uuid, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :role, :string, null: false, default: "member"  # admin, moderator, member
      add :permissions, :jsonb  # Custom permissions (mute, pin, etc.)
      add :joined_at, :utc_datetime, null: false, default: fragment("NOW()")
      add :left_at, :utc_datetime
      
      timestamps(type: :utc_datetime)
    end

    # Group messages
    create table(:group_messages, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :group_chat_id, references(:group_chats, type: :uuid, on_delete: :delete_all), null: false
      add :sender_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :content, :text
      add :message_type, :string, null: false, default: "text"  # text, image, video, voice, file
      add :media_id, references(:media, type: :uuid, on_delete: :nilify_all)
      add :reply_to_id, references(:group_messages, type: :uuid, on_delete: :nilify_all)
      add :is_encrypted, :boolean, default: false, null: false
      add :encrypted_content, :text  # For E2EE messages
      add :is_pinned, :boolean, default: false, null: false
      add :is_deleted, :boolean, default: false, null: false
      
      timestamps(type: :utc_datetime)
    end

    # Message reactions (for both DMs and group messages)
    create table(:message_reactions, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :message_type, :string, null: false  # "direct_message" or "group_message"
      add :message_id, :uuid, null: false  # References either direct_messages.id or group_messages.id
      add :emoji, :string, null: false, size: 10  # Emoji reaction
      
      timestamps(type: :utc_datetime)
    end

    # Message read receipts (for group messages)
    create table(:message_read_receipts, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :message_id, references(:group_messages, type: :uuid, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :read_at, :utc_datetime, null: false, default: fragment("NOW()")
      
      timestamps(type: :utc_datetime)
    end

    # Indexes for direct_messages
    create index(:direct_messages, [:sender_id])
    create index(:direct_messages, [:recipient_id])
    create index(:direct_messages, [:status])
    create index(:direct_messages, [:inserted_at])
    # Composite index for conversation queries
    create index(:direct_messages, [:sender_id, :recipient_id, :inserted_at])
    create index(:direct_messages, [:recipient_id, :sender_id, :inserted_at])

    # Indexes for group_chats
    create index(:group_chats, [:creator_id])
    create index(:group_chats, [:inserted_at])

    # Indexes for group_chat_members
    create unique_index(:group_chat_members, [:group_chat_id, :user_id], name: :group_chat_members_unique)
    create index(:group_chat_members, [:group_chat_id])
    create index(:group_chat_members, [:user_id])
    create index(:group_chat_members, [:role])

    # Indexes for group_messages
    create index(:group_messages, [:group_chat_id])
    create index(:group_messages, [:sender_id])
    create index(:group_messages, [:reply_to_id])
    create index(:group_messages, [:inserted_at])
    create index(:group_messages, [:is_pinned])
    create index(:group_messages, [:is_deleted])
    # Composite index for chat message queries
    create index(:group_messages, [:group_chat_id, :inserted_at])

    # Indexes for message_reactions
    create unique_index(:message_reactions, [:user_id, :message_type, :message_id, :emoji], name: :message_reactions_unique)
    create index(:message_reactions, [:message_type, :message_id])
    create index(:message_reactions, [:user_id])

    # Indexes for message_read_receipts
    create unique_index(:message_read_receipts, [:message_id, :user_id], name: :message_read_receipts_unique)
    create index(:message_read_receipts, [:message_id])
    create index(:message_read_receipts, [:user_id])
  end
end

