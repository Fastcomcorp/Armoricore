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

defmodule ArmoricoreRealtime.Messaging.DirectMessage do
  @moduledoc """
  Direct message schema.
  One-on-one private messaging between users.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @message_types ["text", "image", "video", "voice", "file"]
  @statuses ["sent", "delivered", "read"]

  schema "direct_messages" do
    field :content, :string
    field :message_type, :string, default: "text"
    field :status, :string, default: "sent"
    field :is_encrypted, :boolean, default: false
    field :encrypted_content, :string
    field :read_at, :utc_datetime
    belongs_to :sender, ArmoricoreRealtime.Accounts.User, foreign_key: :sender_id
    belongs_to :recipient, ArmoricoreRealtime.Accounts.User, foreign_key: :recipient_id
    belongs_to :media, ArmoricoreRealtime.Media.MediaFile, foreign_key: :media_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(direct_message, attrs) do
    direct_message
    |> cast(attrs, [:sender_id, :recipient_id, :content, :message_type, :status, :media_id, :is_encrypted, :encrypted_content, :read_at])
    |> validate_required([:sender_id, :recipient_id, :message_type])
    |> validate_inclusion(:message_type, @message_types)
    |> validate_inclusion(:status, @statuses)
    |> validate_no_self_message()
    |> validate_content_or_media()
  end

  defp validate_no_self_message(changeset) do
    sender_id = get_field(changeset, :sender_id)
    recipient_id = get_field(changeset, :recipient_id)

    if sender_id && recipient_id && sender_id == recipient_id do
      add_error(changeset, :recipient_id, "cannot send message to yourself")
    else
      changeset
    end
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

