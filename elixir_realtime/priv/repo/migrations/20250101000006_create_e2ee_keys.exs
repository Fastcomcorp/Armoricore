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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateE2eeKeys do
  use Ecto.Migration

  def change do
    create table(:e2ee_keys, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false
      add :channel_id, :string, null: true
      add :public_key, :binary, null: false
      add :key_type, :string, null: false, default: "ecdh_p256"
      add :is_active, :boolean, default: true, null: false
      add :expires_at, :utc_datetime, null: true
      
      timestamps(type: :utc_datetime)
    end

    create index(:e2ee_keys, [:user_id])
    create index(:e2ee_keys, [:channel_id])
    create unique_index(:e2ee_keys, [:user_id, :channel_id], where: "is_active = true")
  end
end
