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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateAuditLogs do
  use Ecto.Migration

  def change do
    create table(:audit_logs, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :nilify_all)
      add :event_type, :string, null: false
      add :resource_type, :string  # "user", "media", "token", etc.
      add :resource_id, :uuid
      add :action, :string, null: false  # "create", "update", "delete", "login", "logout", etc.
      add :metadata, :jsonb, default: "{}"
      add :ip_address, :inet
      add :user_agent, :text
      add :success, :boolean, default: true, null: false
      add :error_message, :text
      
      timestamps(type: :utc_datetime)
    end

    create index(:audit_logs, [:user_id])
    create index(:audit_logs, [:event_type])
    create index(:audit_logs, [:resource_type, :resource_id])
    create index(:audit_logs, [:inserted_at])
    create index(:audit_logs, [:event_type, :inserted_at])
  end
end
