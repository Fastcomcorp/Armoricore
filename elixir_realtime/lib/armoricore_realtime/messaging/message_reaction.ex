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

defmodule ArmoricoreRealtime.Messaging.MessageReaction do
  @moduledoc """
  Message reaction schema.
  Emoji reactions to messages (both DMs and group messages).
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @message_types ["direct_message", "group_message"]

  schema "message_reactions" do
    field :message_type, :string
    field :message_id, :binary_id
    field :emoji, :string
    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(message_reaction, attrs) do
    message_reaction
    |> cast(attrs, [:user_id, :message_type, :message_id, :emoji])
    |> validate_required([:user_id, :message_type, :message_id, :emoji])
    |> validate_inclusion(:message_type, @message_types)
    |> validate_length(:emoji, max: 10)
    |> unique_constraint([:user_id, :message_type, :message_id, :emoji], name: :message_reactions_unique)
  end
end

