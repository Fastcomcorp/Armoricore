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

defmodule ArmoricoreRealtimeWeb.SearchController do
  @moduledoc """
  Controller for full-text search operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Content
  import Phoenix.HTML, only: [html_escape: 1]

  @doc """
  Search videos using full-text search (public endpoint).
  GET /api/v1/search?q=query&page=1&limit=20
  """
  def search(conn, params) do
    case params["q"] do
      nil ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Missing search query parameter 'q'"})

      "" ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Search query cannot be empty"})

      query ->
        opts = parse_search_params(params)
        # Temporarily disable search until migrations are run
        # videos = Content.search_videos(query, opts)
        videos = []
        json(conn, %{
          query: sanitize_query(query),
          data: Enum.map(videos, &serialize_video/1),
          count: length(videos)
        })
    end
  end

  # Helper functions

  # SECURITY: Sanitize query parameter to prevent XSS
  defp sanitize_query(query) when is_binary(query) do
    query
    |> html_escape()
    |> Phoenix.HTML.safe_to_string()
  end

  defp sanitize_query(query), do: query

  defp parse_search_params(params) do
    [
      status: params["status"],
      visibility: params["visibility"],
      user_id: params["user_id"],
      category_id: params["category_id"],
      page: parse_page(params["page"]),
      limit: parse_limit(params["limit"])
    ]
    |> Enum.filter(fn {_key, value} -> not is_nil(value) end)
  end

  defp parse_page(nil), do: 1
  defp parse_page(page) when is_binary(page), do: String.to_integer(page)
  defp parse_page(page) when is_integer(page), do: page

  defp parse_limit(nil), do: 20
  defp parse_limit(limit) when is_binary(limit), do: String.to_integer(limit)
  defp parse_limit(limit) when is_integer(limit), do: limit

  defp serialize_video(video) do
    %{
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
      media: serialize_media(video.media),
      user: serialize_user(video.user),
      category: serialize_category(video.category),
      tags: Enum.map(video.tags || [], &serialize_tag/1)
    }
  end

  defp serialize_media(nil), do: nil
  defp serialize_media(media) do
    %{
      id: media.id,
      content_type: media.content_type,
      duration: media.duration,
      resolution: media.resolution,
      status: media.status
    }
  end

  defp serialize_user(nil), do: nil
  defp serialize_user(user) do
    %{
      id: user.id,
      username: user.username
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
end

