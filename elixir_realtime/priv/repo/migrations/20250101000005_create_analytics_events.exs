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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateAnalyticsEvents do
  use Ecto.Migration

  def change do
    create table(:analytics_events, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :user_id, references(:users, type: :uuid, on_delete: :nilify_all)
      add :event_type, :string, null: false  # "media_uploaded", "media_processed", "notification_sent", etc.
      add :event_category, :string  # "media", "notification", "authentication", etc.
      add :properties, :jsonb, default: "{}"
      add :ip_address, :inet
      add :user_agent, :text
      
      timestamps(type: :utc_datetime)
    end

    create index(:analytics_events, [:user_id])
    create index(:analytics_events, [:event_type])
    create index(:analytics_events, [:event_category])
    create index(:analytics_events, [:inserted_at])
    create index(:analytics_events, [:event_type, :inserted_at])
    
    # Partitioning by date could be added for large-scale analytics
    # This would require additional setup for time-based partitioning
  end
end
