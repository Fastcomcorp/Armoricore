# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
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

# Copyright 2025 Francisco F. Pinochet
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

defmodule ArmoricoreRealtime.E2EE.Key do
  @moduledoc """
  Ecto schema for E2EE keys.
  
  Stores public keys for key exchange and shared secrets for channels.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "e2ee_keys" do
    field :channel_id, :string
    field :public_key, :binary
    field :key_type, :string, default: "ecdh_p256"
    field :is_active, :boolean, default: true
    field :expires_at, :utc_datetime

    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(key, attrs) do
    key
    |> cast(attrs, [:user_id, :channel_id, :public_key, :key_type, :is_active, :expires_at])
    |> validate_required([:user_id, :public_key, :key_type])
    |> validate_inclusion(:key_type, ["ecdh_p256", "shared_secret"])
    |> validate_length(:public_key, min: 32, max: 512)
    |> unique_constraint([:user_id, :channel_id], name: :e2ee_keys_user_id_channel_id_index)
  end
end
