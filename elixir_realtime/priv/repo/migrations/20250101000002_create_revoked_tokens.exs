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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateRevokedTokens do
  use Ecto.Migration

  def change do
    create table(:revoked_tokens, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :token_jti, :string, null: false
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :token_type, :string, null: false  # "access" or "refresh"
      add :revoked_at, :utc_datetime, null: false, default: fragment("NOW()")
      add :expires_at, :utc_datetime, null: false
      add :reason, :string  # "logout", "refresh", "security", etc.
      
      timestamps(type: :utc_datetime)
    end

    create unique_index(:revoked_tokens, [:token_jti])
    create index(:revoked_tokens, [:user_id])
    create index(:revoked_tokens, [:expires_at])
    
    # Cleanup expired tokens periodically (can be done via cron or background job)
    # CREATE INDEX idx_revoked_tokens_expires_at ON revoked_tokens(expires_at) WHERE expires_at < NOW();
  end
end
