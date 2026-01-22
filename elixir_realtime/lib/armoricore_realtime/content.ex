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

defmodule ArmoricoreRealtime.Content do
  @moduledoc """
  Content Management System (CMS) context.
  Provides functions for managing videos, categories, and tags.
  """

  import Ecto.Query, warn: false
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Content.{Video, Category, Tag}
  
  require MapSet

  ## Video functions

  @doc """
  Returns the list of videos.
  """
  def list_videos(opts \\ []) do
    query = from v in Video

    videos = query
    |> apply_filters(opts)
    |> apply_sorting(opts)
    |> apply_pagination(opts)
    |> Repo.all()
    
    # Preload sequentially to avoid sandbox connection issues
    Enum.map(videos, fn video ->
      video
      |> Repo.preload(:media)
      |> Repo.preload(:user)
      |> Repo.preload(:category)
      |> Repo.preload(:tags)
    end)
  end

  @doc """
  Gets a single video.
  """
  def get_video!(id) do
    video = Repo.get!(Video, id)
    # Preload sequentially to avoid sandbox connection issues
    video
    |> Repo.preload(:media)
    |> Repo.preload(:user)
    |> Repo.preload(:category)
    |> Repo.preload(:tags)
  end

  @doc """
  Gets a single video by ID (returns nil if not found).
  """
  def get_video(id), do: Repo.get(Video, id) |> maybe_preload()

  defp maybe_preload(nil), do: nil
  defp maybe_preload(video), do: Repo.preload(video, [:media, :user, :category, :tags])

  @doc """
  Creates a video.
  """
  def create_video(attrs \\ %{}) do
    case %Video{}
         |> Video.changeset(attrs)
         |> Repo.insert() do
      {:ok, video} ->
        # Update search vector after insert
        # The database trigger should handle this automatically, but we update it explicitly for test reliability
        # Use raw SQL with proper UUID encoding - video.id is already a binary UUID from Ecto
        video_id_binary = case Ecto.UUID.dump(video.id) do
          {:ok, binary} -> binary
          :error -> video.id  # Already binary
        end
        Repo.query!("""
          UPDATE videos 
          SET search_vector = to_tsvector('english', coalesce(title, '') || ' ' || coalesce(description, ''))
          WHERE id = $1::uuid
        """, [video_id_binary])
        {:ok, video}
      error -> error
    end
  end

  defp update_search_vector(%Video{} = video) do
    # Cast UUID to binary if it's a string
    video_id = case video.id do
      id when is_binary(id) and byte_size(id) == 16 -> id
      id when is_binary(id) -> Ecto.UUID.cast!(id)
      id -> id
    end
    Repo.query!("""
      UPDATE videos 
      SET search_vector = to_tsvector('english', coalesce(title, '') || ' ' || coalesce(description, ''))
      WHERE id = $1::uuid
    """, [video_id])
  end

  @doc """
  Updates a video.
  """
  def update_video(%Video{} = video, attrs) do
    case video
         |> Video.changeset(attrs)
         |> Repo.update() do
      {:ok, updated_video} ->
        # Update search vector if title or description changed
        if Map.has_key?(attrs, :title) or Map.has_key?(attrs, :description) do
          # Use raw SQL with proper UUID encoding - updated_video.id is already a binary UUID from Ecto
          video_id_binary = case Ecto.UUID.dump(updated_video.id) do
            {:ok, binary} -> binary
            :error -> updated_video.id  # Already binary
          end
          Repo.query!("""
            UPDATE videos 
            SET search_vector = to_tsvector('english', coalesce(title, '') || ' ' || coalesce(description, ''))
            WHERE id = $1::uuid
          """, [video_id_binary])
        end
        {:ok, updated_video}
      error -> error
    end
  end

  @doc """
  Deletes a video.
  """
  def delete_video(%Video{} = video) do
    Repo.delete(video)
  end

  @doc """
  Increments the view count for a video.
  """
  def increment_video_views(%Video{} = video) do
    Repo.update_all(
      from(v in Video, where: v.id == ^video.id),
      inc: [views: 1]
    )
    {:ok, Repo.get!(Video, video.id)}
  end

  @doc """
  Increments the likes count for a video.
  """
  def increment_video_likes(%Video{} = video) do
    Repo.update_all(
      from(v in Video, where: v.id == ^video.id),
      inc: [likes: 1]
    )
    {:ok, Repo.get!(Video, video.id)}
  end

  @doc """
  Increments the dislikes count for a video.
  """
  def increment_video_dislikes(%Video{} = video) do
    Repo.update_all(
      from(v in Video, where: v.id == ^video.id),
      inc: [dislikes: 1]
    )
    {:ok, Repo.get!(Video, video.id)}
  end

  @doc """
  Adds tags to a video.
  """
  def add_tags_to_video(%Video{} = video, tag_names) when is_list(tag_names) do
    tags = get_or_create_tags(tag_names)
    video = Repo.preload(video, :tags)
    
    # Get existing tag IDs
    existing_tag_ids = MapSet.new(Enum.map(video.tags, & &1.id))
    
    # Filter out tags that are already associated
    new_tags = Enum.filter(tags, fn tag -> not MapSet.member?(existing_tag_ids, tag.id) end)
    
    if Enum.empty?(new_tags) do
      {:ok, video}
    else
      # Manually insert into join table with timestamps using raw SQL
      # Convert UUIDs to binary format for Postgrex
      now = DateTime.utc_now()
      
      video_id_binary = case Ecto.UUID.dump(video.id) do
        {:ok, binary} -> binary
        :error -> Ecto.UUID.cast!(video.id) |> Ecto.UUID.dump!()
      end
      
      Enum.each(new_tags, fn tag ->
        tag_id_binary = case Ecto.UUID.dump(tag.id) do
          {:ok, binary} -> binary
          :error -> Ecto.UUID.cast!(tag.id) |> Ecto.UUID.dump!()
        end
        
        Repo.query!("""
          INSERT INTO video_tags (video_id, tag_id, inserted_at, updated_at)
          VALUES ($1::uuid, $2::uuid, $3, $4)
          ON CONFLICT DO NOTHING
        """, [video_id_binary, tag_id_binary, now, now])
      end)
      
      # Reload video with tags
      {:ok, Repo.preload(video, :tags)}
    end
  end

  @doc """
  Removes tags from a video.
  """
  def remove_tags_from_video(%Video{} = video, tag_names) when is_list(tag_names) do
    tags = get_tags_by_names(tag_names)
    video = Repo.preload(video, :tags)
    
    if Enum.empty?(tags) do
      {:ok, video}
    else
      # Get tag IDs to remove
      tag_ids = Enum.map(tags, & &1.id)
      
      # Convert to binary format for Postgrex
      tag_ids_binary = Enum.map(tag_ids, fn tag_id ->
        case Ecto.UUID.dump(tag_id) do
          {:ok, binary} -> binary
          :error -> Ecto.UUID.cast!(tag_id) |> Ecto.UUID.dump!()
        end
      end)
      
      video_id_binary = case Ecto.UUID.dump(video.id) do
        {:ok, binary} -> binary
        :error -> Ecto.UUID.cast!(video.id) |> Ecto.UUID.dump!()
      end
      
      # Delete from join table using raw SQL
      Enum.each(tag_ids_binary, fn tag_id_binary ->
        Repo.query!("""
          DELETE FROM video_tags
          WHERE video_id = $1::uuid AND tag_id = $2::uuid
        """, [video_id_binary, tag_id_binary])
      end)
      
      # Reload video with tags
      {:ok, Repo.preload(video, :tags)}
    end
  end

  ## Search functions

  @doc """
  Searches videos using PostgreSQL full-text search.
  """
  def search_videos(query_string, opts \\ []) when is_binary(query_string) do
    search_query = from v in Video,
      where: not is_nil(v.search_vector) and fragment("? @@ plainto_tsquery('english', ?)", v.search_vector, ^query_string),
      order_by: [
        desc: fragment("ts_rank(?, plainto_tsquery('english', ?))", v.search_vector, ^query_string)
      ]

    videos = search_query
    |> apply_filters(opts)
    |> apply_pagination(opts)
    |> Repo.all()
    
    # Preload sequentially to avoid sandbox connection issues
    Enum.map(videos, fn video ->
      video
      |> Repo.preload(:media)
      |> Repo.preload(:user)
      |> Repo.preload(:category)
      |> Repo.preload(:tags)
    end)
  end

  ## Category functions

  @doc """
  Returns the list of categories.
  """
  def list_categories(opts \\ []) do
    query = from c in Category

    query
    |> apply_category_filters(opts)
    |> Repo.all()
    |> Repo.preload([:parent, :children])
  end

  @doc """
  Gets a single category (raises if not found).
  """
  def get_category!(id) do
    Repo.get!(Category, id) |> Repo.preload([:parent, :children])
  end

  @doc """
  Gets a category by slug.
  """
  def get_category_by_slug(slug), do: Repo.get_by(Category, slug: slug) |> maybe_preload_category()

  defp maybe_preload_category(nil), do: nil
  defp maybe_preload_category(category), do: Repo.preload(category, [:parent, :children])

  @doc """
  Creates a category.
  """
  def create_category(attrs \\ %{}) do
    %Category{}
    |> Category.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a category.
  """
  def update_category(%Category{} = category, attrs) do
    category
    |> Category.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a category.
  """
  def delete_category(%Category{} = category) do
    Repo.delete(category)
  end

  ## Tag functions

  @doc """
  Returns the list of tags.
  """
  def list_tags(opts \\ []) do
    query = from t in Tag

    query
    |> apply_tag_filters(opts)
    |> Repo.all()
  end

  @doc """
  Gets a single tag.
  """
  def get_tag!(id), do: Repo.get!(Tag, id)

  @doc """
  Gets a tag by name.
  """
  def get_tag_by_name(name), do: Repo.get_by(Tag, name: name)

  @doc """
  Creates a tag.
  """
  def create_tag(attrs \\ %{}) do
    %Tag{}
    |> Tag.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets or creates tags by names.
  """
  def get_or_create_tags(tag_names) when is_list(tag_names) do
    tag_names
    |> Enum.map(&String.trim/1)
    |> Enum.filter(&(&1 != ""))
    |> Enum.map(fn name ->
      case get_tag_by_name(name) do
        nil -> create_tag(%{name: name})
        tag -> {:ok, tag}
      end
    end)
    |> Enum.map(fn
      {:ok, tag} -> tag
      {:error, _} -> nil
    end)
    |> Enum.filter(&(!is_nil(&1)))
  end

  defp get_tags_by_names(tag_names) do
    tag_names
    |> Enum.map(&String.trim/1)
    |> Enum.filter(&(&1 != ""))
    |> Enum.map(&get_tag_by_name/1)
    |> Enum.filter(&(!is_nil(&1)))
  end

  ## Helper functions

  defp change(%Video{} = video), do: Video.changeset(video, %{})

  defp apply_filters(query, opts) do
    query
    |> maybe_filter_by_status(opts[:status])
    |> maybe_filter_by_visibility(opts[:visibility])
    |> maybe_filter_by_user(opts[:user_id])
    |> maybe_filter_by_category(opts[:category_id])
  end

  defp maybe_filter_by_status(query, nil), do: query
  defp maybe_filter_by_status(query, status) do
    from v in query, where: v.status == ^status
  end

  defp maybe_filter_by_visibility(query, nil), do: query
  defp maybe_filter_by_visibility(query, visibility) do
    from v in query, where: v.visibility == ^visibility
  end

  defp maybe_filter_by_user(query, nil), do: query
  defp maybe_filter_by_user(query, user_id) do
    from v in query, where: v.user_id == ^user_id
  end

  defp maybe_filter_by_category(query, nil), do: query
  defp maybe_filter_by_category(query, category_id) do
    from v in query, where: v.category_id == ^category_id
  end

  defp apply_sorting(query, opts) do
    case opts[:sort] do
      :views -> from v in query, order_by: [desc: v.views]
      :likes -> from v in query, order_by: [desc: v.likes]
      :newest -> from v in query, order_by: [desc: v.inserted_at]
      :oldest -> from v in query, order_by: [asc: v.inserted_at]
      _ -> from v in query, order_by: [desc: v.inserted_at]
    end
  end

  defp apply_pagination(query, opts) do
    limit = opts[:limit] || 20
    offset = (opts[:page] || 1 - 1) * limit
    from v in query, limit: ^limit, offset: ^offset
  end

  defp apply_category_filters(query, opts) do
    query
    |> maybe_filter_by_parent(opts[:parent_id])
  end

  defp maybe_filter_by_parent(query, nil), do: query
  defp maybe_filter_by_parent(query, parent_id) do
    from c in query, where: c.parent_id == ^parent_id
  end

  defp apply_tag_filters(query, _opts), do: query
end

