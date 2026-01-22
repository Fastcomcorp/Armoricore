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

defmodule ArmoricoreRealtime.Audit.Log do
  @moduledoc """
  Audit log schema.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_logs" do
    field :event_type, :string
    field :resource_type, :string
    field :resource_id, :binary_id
    field :action, :string
    field :metadata, :map, default: %{}
    field :ip_address, :string
    field :user_agent, :string
    field :success, :boolean, default: true
    field :error_message, :string

    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(log, attrs) do
    log
    |> cast(attrs, [
      :user_id,
      :event_type,
      :resource_type,
      :resource_id,
      :action,
      :metadata,
      :ip_address,
      :user_agent,
      :success,
      :error_message
    ])
    |> validate_required([:event_type, :action])
  end
end
