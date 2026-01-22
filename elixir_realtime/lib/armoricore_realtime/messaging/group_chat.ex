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

defmodule ArmoricoreRealtime.Messaging.GroupChat do
  @moduledoc """
  Group chat schema.
  Multi-participant group messaging.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "group_chats" do
    field :name, :string
    field :description, :string
    field :is_encrypted, :boolean, default: false
    field :member_count, :integer, default: 0
    belongs_to :creator, ArmoricoreRealtime.Accounts.User, foreign_key: :creator_id
    belongs_to :avatar_media, ArmoricoreRealtime.Media.MediaFile, foreign_key: :avatar_media_id
    has_many :members, ArmoricoreRealtime.Messaging.GroupChatMember
    has_many :messages, ArmoricoreRealtime.Messaging.GroupMessage

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(group_chat, attrs) do
    group_chat
    |> cast(attrs, [:name, :description, :creator_id, :avatar_media_id, :is_encrypted])
    |> validate_required([:name, :creator_id])
    |> validate_length(:name, max: 255)
  end
end

