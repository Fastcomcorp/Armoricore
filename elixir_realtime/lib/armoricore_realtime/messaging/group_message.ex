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

defmodule ArmoricoreRealtime.Messaging.GroupMessage do
  @moduledoc """
  Group message schema.
  Messages sent in group chats.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @message_types ["text", "image", "video", "voice", "file"]

  schema "group_messages" do
    field :content, :string
    field :message_type, :string, default: "text"
    field :is_encrypted, :boolean, default: false
    field :encrypted_content, :string
    field :is_pinned, :boolean, default: false
    field :is_deleted, :boolean, default: false
    belongs_to :group_chat, ArmoricoreRealtime.Messaging.GroupChat
    belongs_to :sender, ArmoricoreRealtime.Accounts.User, foreign_key: :sender_id
    belongs_to :media, ArmoricoreRealtime.Media.MediaFile, foreign_key: :media_id
    belongs_to :reply_to, ArmoricoreRealtime.Messaging.GroupMessage, foreign_key: :reply_to_id
    has_many :reactions, ArmoricoreRealtime.Messaging.MessageReaction
    has_many :read_receipts, ArmoricoreRealtime.Messaging.MessageReadReceipt

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(group_message, attrs) do
    group_message
    |> cast(attrs, [:group_chat_id, :sender_id, :content, :message_type, :media_id, :reply_to_id, :is_encrypted, :encrypted_content, :is_pinned, :is_deleted])
    |> validate_required([:group_chat_id, :sender_id, :message_type])
    |> validate_inclusion(:message_type, @message_types)
    |> validate_content_or_media()
  end

  defp validate_content_or_media(changeset) do
    content = get_field(changeset, :content)
    encrypted_content = get_field(changeset, :encrypted_content)
    media_id = get_field(changeset, :media_id)
    message_type = get_field(changeset, :message_type)

    cond do
      # Text messages require content
      message_type == "text" && is_nil(content) && is_nil(encrypted_content) ->
        add_error(changeset, :content, "text messages require content")

      # Media messages require media_id
      message_type in ["image", "video", "voice", "file"] && is_nil(media_id) ->
        add_error(changeset, :media_id, "#{message_type} messages require media_id")

      true ->
        changeset
    end
  end
end

