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

defmodule ArmoricoreRealtime.Messaging.MessageReadReceipt do
  @moduledoc """
  Message read receipt schema.
  Tracks when users read group messages.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "message_read_receipts" do
    field :read_at, :utc_datetime
    belongs_to :message, ArmoricoreRealtime.Messaging.GroupMessage, foreign_key: :message_id
    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(message_read_receipt, attrs) do
    message_read_receipt
    |> cast(attrs, [:message_id, :user_id, :read_at])
    |> validate_required([:message_id, :user_id])
    |> unique_constraint([:message_id, :user_id], name: :message_read_receipts_unique)
  end
end

