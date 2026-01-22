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

defmodule ArmoricoreRealtimeWeb.VideoController do
  @moduledoc """
  Controller for video CRUD operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Content
  alias ArmoricoreRealtime.Social

  require Logger

  @doc """
  List videos (public endpoint).
  GET /api/v1/videos
  """
  def index(conn, params) do
    opts = parse_list_params(params)
    videos = Content.list_videos(opts)
    user_id = get_user_id_from_conn(conn)
    json(conn, %{
      data: Enum.map(videos, &serialize_video(&1, user_id)),
      count: length(videos)
    })
  end

  @doc """
  Get a single video (public endpoint).
  GET /api/v1/videos/:id
  """
  def show(conn, %{"id" => id}) do
    case Content.get_video(id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Video not found"})

      video ->
        # Increment view count
        {:ok, updated_video} = Content.increment_video_views(video)
        user_id = get_user_id_from_conn(conn)
        json(conn, %{data: serialize_video(updated_video, user_id)})
    end
  end

  @doc """
  Create a new video (protected endpoint).
  POST /api/v1/videos
  
  Accepts params either nested under "video" key or directly:
  - {"video": {"title": "...", "description": "..."}}
  - {"title": "...", "description": "..."}
  """
  def create(conn, %{"video" => video_params}) do
    do_create_video(conn, video_params)
  end

  def create(conn, params) when is_map(params) do
    # Handle direct params (not nested under "video")
    video_params = Map.drop(params, ["_format", "_utf8"])
    do_create_video(conn, video_params)
  end

  defp do_create_video(conn, video_params) do
    user_id = conn.assigns.current_user_id

    video_params =
      video_params
      |> Map.put("user_id", user_id)

    case Content.create_video(video_params) do
      {:ok, video} ->
        video = Content.get_video!(video.id)
        conn
        |> put_status(:created)
        |> json(%{data: serialize_video(video, user_id)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  @doc """
  Update a video (protected endpoint - owner only).
  PUT /api/v1/videos/:id
  """
  def update(conn, %{"id" => id, "video" => video_params}) do
    user_id = conn.assigns.current_user_id

    case Content.get_video(id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Video not found"})

      video ->
        # SECURITY: Only video owner can update
        if video.user_id == user_id do
          case Content.update_video(video, video_params) do
            {:ok, video} ->
              video = Content.get_video!(video.id)
              json(conn, %{data: serialize_video(video, user_id)})

            {:error, %Ecto.Changeset{} = changeset} ->
              conn
              |> put_status(:unprocessable_entity)
              |> json(%{error: "Validation failed", errors: format_errors(changeset)})
          end
        else
          conn
          |> put_status(:forbidden)
          |> json(%{error: "You don't have permission to update this video"})
        end
    end
  end

  @doc """
  Delete a video (protected endpoint - owner only).
  DELETE /api/v1/videos/:id
  """
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case Content.get_video(id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Video not found"})

      video ->
        # SECURITY: Only video owner can delete
        if video.user_id == user_id do
          case Content.delete_video(video) do
            {:ok, _video} ->
              conn
              |> put_status(:no_content)
              |> json(%{})

            {:error, _changeset} ->
              conn
              |> put_status(:internal_server_error)
              |> json(%{error: "Failed to delete video"})
          end
        else
          conn
          |> put_status(:forbidden)
          |> json(%{error: "You don't have permission to delete this video"})
        end
    end
  end

  @doc """
  Like a video (protected endpoint).
  POST /api/v1/videos/:id/like
  """
  def like(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case Content.get_video(id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Video not found"})

      video ->
        case Social.like_video(user_id, video.id, "like") do
          {:ok, _result} ->
            video = Content.get_video!(video.id)
            json(conn, %{data: serialize_video(video, user_id)})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to like video", errors: format_errors(changeset)})
        end
    end
  end

  @doc """
  Dislike a video (protected endpoint).
  POST /api/v1/videos/:id/dislike
  """
  def dislike(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case Content.get_video(id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Video not found"})

      video ->
        case Social.like_video(user_id, video.id, "dislike") do
          {:ok, _result} ->
            video = Content.get_video!(video.id)
            json(conn, %{data: serialize_video(video, user_id)})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to dislike video", errors: format_errors(changeset)})
        end
    end
  end

  # Helper functions

  defp parse_list_params(params) do
    [
      status: params["status"],
      visibility: params["visibility"],
      user_id: params["user_id"],
      category_id: params["category_id"],
      sort: parse_sort(params["sort"]),
      page: parse_page(params["page"]),
      limit: parse_limit(params["limit"])
    ]
    |> Enum.filter(fn {_key, value} -> not is_nil(value) end)
  end

  defp parse_sort(nil), do: nil
  defp parse_sort("views"), do: :views
  defp parse_sort("likes"), do: :likes
  defp parse_sort("newest"), do: :newest
  defp parse_sort("oldest"), do: :oldest
  defp parse_sort(_), do: nil

  defp parse_page(nil), do: 1
  defp parse_page(page) when is_binary(page), do: String.to_integer(page)
  defp parse_page(page) when is_integer(page), do: page

  defp parse_limit(nil), do: 20
  defp parse_limit(limit) when is_binary(limit), do: String.to_integer(limit)
  defp parse_limit(limit) when is_integer(limit), do: limit

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp serialize_video(video, user_id) do
    base_data = %{
      id: video.id,
      title: video.title,
      description: video.description,
      views: video.views,
      likes: video.likes,
      dislikes: video.dislikes,
      status: video.status,
      visibility: video.visibility,
      published_at: video.published_at,
      created_at: video.inserted_at,
      updated_at: video.updated_at,
      media: serialize_media(video.media),
      user: serialize_user(video.user),
      category: serialize_category(video.category),
      tags: Enum.map(video.tags || [], &serialize_tag/1)
    }

    # Add user's like/dislike status if user_id provided
    if user_id do
      user_liked = Social.user_liked_video?(user_id, video.id)
      user_disliked = Social.user_disliked_video?(user_id, video.id)
      Map.merge(base_data, %{
        user_liked: user_liked,
        user_disliked: user_disliked
      })
    else
      base_data
    end
  end

  defp serialize_media(nil), do: nil
  defp serialize_media(media) do
    %{
      id: media.id,
      content_type: media.content_type,
      duration: media.duration,
      resolution: media.resolution,
      status: media.status,
      playback_urls: media.playback_urls || %{},
      thumbnail_urls: media.thumbnail_urls || []
    }
  end

  defp serialize_user(nil), do: nil
  defp serialize_user(user) do
    %{
      id: user.id,
      username: user.username,
      email: user.email
    }
  end

  defp serialize_category(nil), do: nil
  defp serialize_category(category) do
    %{
      id: category.id,
      name: category.name,
      slug: category.slug
    }
  end

  defp serialize_tag(tag) do
    %{
      id: tag.id,
      name: tag.name
    }
  end

  defp get_user_id_from_conn(conn) do
    case conn.assigns do
      %{current_user_id: user_id} -> user_id
      _ -> nil
    end
  end
end

