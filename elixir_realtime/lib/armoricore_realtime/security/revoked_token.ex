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

defmodule ArmoricoreRealtime.Security.RevokedToken do
  @moduledoc """
  Schema for revoked tokens (logout/security).
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "revoked_tokens" do
    field :token_jti, :string
    field :token_type, :string  # "access" or "refresh"
    field :revoked_at, :utc_datetime
    field :expires_at, :utc_datetime
    field :reason, :string

    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(revoked_token, attrs) do
    revoked_token
    |> cast(attrs, [:token_jti, :user_id, :token_type, :revoked_at, :expires_at, :reason])
    |> validate_required([:token_jti, :user_id, :token_type, :expires_at])
    |> validate_inclusion(:token_type, ["access", "refresh"])
    |> unique_constraint(:token_jti)
  end
end
