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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateMedia do
  use Ecto.Migration

  def change do
    create table(:media, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :original_filename, :string, null: false
      add :content_type, :string, null: false
      add :file_size, :bigint, null: false
      add :duration, :integer  # seconds
      add :resolution, :string  # "1920x1080", "4K", etc.
      add :status, :string, null: false, default: "processing"  # processing, ready, failed
      add :playback_urls, :jsonb, default: "{}"
      add :thumbnail_urls, :jsonb, default: "[]"
      add :metadata, :jsonb, default: "{}"
      add :error_message, :text
      
      timestamps(type: :utc_datetime)
    end

    create index(:media, [:user_id])
    create index(:media, [:status])
    create index(:media, [:inserted_at])
    create index(:media, [:user_id, :status])
  end
end
