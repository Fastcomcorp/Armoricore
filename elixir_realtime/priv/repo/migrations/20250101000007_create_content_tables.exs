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

defmodule ArmoricoreRealtime.Repo.Migrations.CreateContentTables do
  use Ecto.Migration

  def change do
    # Categories table - must be created first since videos reference it
    create table(:categories, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :name, :string, null: false, size: 100
      add :slug, :string, null: false, size: 100
      add :description, :text
      add :parent_id, references(:categories, type: :uuid, on_delete: :nilify_all)  # For nested categories
      
      timestamps(type: :utc_datetime)
    end

    # Videos table - extends media with CMS-specific fields
    create table(:videos, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :media_id, references(:media, type: :uuid, on_delete: :delete_all), null: false
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false
      add :title, :string, null: false, size: 255
      add :description, :text
      add :category_id, references(:categories, type: :uuid, on_delete: :nilify_all)
      add :views, :bigint, default: 0, null: false
      add :likes, :bigint, default: 0, null: false
      add :dislikes, :bigint, default: 0, null: false
      add :status, :string, null: false, default: "draft"  # draft, processing, ready, live, archived
      add :visibility, :string, null: false, default: "public"  # public, unlisted, private
      add :published_at, :utc_datetime
      add :search_vector, :tsvector  # For full-text search
      
      timestamps(type: :utc_datetime)
    end

    # Tags table
    create table(:tags, primary_key: false) do
      add :id, :uuid, primary_key: true, default: fragment("gen_random_uuid()")
      add :name, :string, null: false, size: 50
      
      timestamps(type: :utc_datetime)
    end

    # Video-Tags join table (many-to-many)
    create table(:video_tags, primary_key: false) do
      add :video_id, references(:videos, type: :uuid, on_delete: :delete_all), primary_key: true
      add :tag_id, references(:tags, type: :uuid, on_delete: :delete_all), primary_key: true
      
      timestamps(type: :utc_datetime)
    end

    # Indexes for videos
    create index(:videos, [:user_id])
    create index(:videos, [:media_id])
    create index(:videos, [:category_id])
    create index(:videos, [:status])
    create index(:videos, [:visibility])
    create index(:videos, [:published_at])
    create index(:videos, [:views])
    create index(:videos, [:inserted_at])
    # Full-text search index
    create index(:videos, [:search_vector], using: "GIN")

    # Indexes for categories
    create unique_index(:categories, [:slug])
    create index(:categories, [:parent_id])
    create index(:categories, [:name])

    # Indexes for tags
    create unique_index(:tags, [:name])

    # Indexes for video_tags
    create index(:video_tags, [:video_id])
    create index(:video_tags, [:tag_id])

    # Trigger to update search_vector on video changes
    execute """
    CREATE OR REPLACE FUNCTION update_video_search_vector()
    RETURNS TRIGGER AS $$
    BEGIN
      NEW.search_vector :=
        setweight(to_tsvector('english', COALESCE(NEW.title, '')), 'A') ||
        setweight(to_tsvector('english', COALESCE(NEW.description, '')), 'B');
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """,
    """
    DROP FUNCTION IF EXISTS update_video_search_vector();
    """

    execute """
    CREATE TRIGGER update_video_search_vector_trigger
    BEFORE INSERT OR UPDATE ON videos
    FOR EACH ROW
    EXECUTE FUNCTION update_video_search_vector();
    """,
    """
    DROP TRIGGER IF EXISTS update_video_search_vector_trigger ON videos;
    """
  end
end

