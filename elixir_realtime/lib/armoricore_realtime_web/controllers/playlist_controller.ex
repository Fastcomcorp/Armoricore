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

defmodule ArmoricoreRealtimeWeb.PlaylistController do
  @moduledoc """
  Controller for playlist operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Social
  alias ArmoricoreRealtime.Social.Playlist

  @doc """
  List playlists (public endpoint, filtered by visibility).
  GET /api/v1/playlists
  """
  def index(conn, params) do
    user_id = get_user_id_from_conn(conn)
    opts = parse_list_params(params, user_id)
    playlists = Social.list_playlists(user_id || "", opts)
    json(conn, %{
      data: Enum.map(playlists, &serialize_playlist/1),
      count: length(playlists)
    })
  end

  @doc """
  Get a single playlist (public endpoint, respects visibility).
  GET /api/v1/playlists/:id
  """
  def show(conn, %{"id" => id}) do
    try do
      playlist = Social.get_playlist!(id)
      # SECURITY: Check visibility
      current_user_id = get_user_id_from_conn(conn)
      if can_view_playlist?(playlist, current_user_id) do
        json(conn, %{data: serialize_playlist(playlist)})
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to view this playlist"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Playlist not found"})
    end
  end

  @doc """
  Create a playlist (protected endpoint).
  POST /api/v1/playlists
  """
  def create(conn, %{"playlist" => playlist_params}) do
    user_id = conn.assigns.current_user_id

    playlist_params =
      playlist_params
      |> Map.put("user_id", user_id)

    case Social.create_playlist(playlist_params) do
      {:ok, playlist} ->
        playlist = Social.get_playlist!(playlist.id)
        conn
        |> put_status(:created)
        |> json(%{data: serialize_playlist(playlist)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  @doc """
  Update a playlist (protected endpoint - owner only).
  PUT /api/v1/playlists/:id
  """
  def update(conn, %{"id" => id, "playlist" => playlist_params}) do
    user_id = conn.assigns.current_user_id

    try do
      playlist = Social.get_playlist!(id)

      # SECURITY: Only playlist owner can update
      if playlist.user_id == user_id do
        case Social.update_playlist(playlist, playlist_params) do
          {:ok, playlist} ->
            playlist = Social.get_playlist!(playlist.id)
            json(conn, %{data: serialize_playlist(playlist)})

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Validation failed", errors: format_errors(changeset)})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to update this playlist"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Playlist not found"})
    end
  end

  @doc """
  Delete a playlist (protected endpoint - owner only).
  DELETE /api/v1/playlists/:id
  """
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      playlist = Social.get_playlist!(id)

      # SECURITY: Only playlist owner can delete
      if playlist.user_id == user_id do
        case Social.delete_playlist(playlist) do
          {:ok, _playlist} ->
            conn
            |> put_status(:no_content)
            |> json(%{})

          {:error, _changeset} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to delete playlist"})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to delete this playlist"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Playlist not found"})
    end
  end

  @doc """
  Add video to playlist (protected endpoint - owner only).
  POST /api/v1/playlists/:id/videos
  """
  def add_video(conn, %{"id" => id, "video_id" => video_id}) do
    user_id = conn.assigns.current_user_id

    try do
      playlist = Social.get_playlist!(id)

      # SECURITY: Only playlist owner can add videos
      if playlist.user_id == user_id do
        case Social.add_video_to_playlist(playlist.id, video_id) do
          {:ok, :added} ->
            playlist = Social.get_playlist!(playlist.id)
            json(conn, %{data: serialize_playlist(playlist)})

          {:error, :already_in_playlist} ->
            conn
            |> put_status(:conflict)
            |> json(%{error: "Video already in playlist"})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to modify this playlist"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Playlist not found"})
    end
  end

  @doc """
  Remove video from playlist (protected endpoint - owner only).
  DELETE /api/v1/playlists/:id/videos/:video_id
  """
  def remove_video(conn, %{"id" => id, "video_id" => video_id}) do
    user_id = conn.assigns.current_user_id

    try do
      playlist = Social.get_playlist!(id)

      # SECURITY: Only playlist owner can remove videos
      if playlist.user_id == user_id do
        case Social.remove_video_from_playlist(playlist.id, video_id) do
          {:ok, :removed} ->
            playlist = Social.get_playlist!(playlist.id)
            json(conn, %{data: serialize_playlist(playlist)})

          {:error, :not_found} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Video not found in playlist"})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to modify this playlist"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Playlist not found"})
    end
  end

  # Helper functions

  defp parse_list_params(params, current_user_id) do
    [
      visibility: params["visibility"],
      user_id: params["user_id"] || current_user_id,
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

  defp can_view_playlist?(playlist, current_user_id) do
    case playlist.visibility do
      "public" -> true
      "unlisted" -> true  # Can view if you have the link
      "private" -> playlist.user_id == current_user_id
      _ -> false
    end
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp serialize_playlist(playlist) do
    %{
      id: playlist.id,
      name: playlist.name,
      description: playlist.description,
      visibility: playlist.visibility,
      video_count: playlist.video_count,
      user: serialize_user(playlist.user),
      videos: Enum.map(playlist.videos || [], &serialize_video/1),
      created_at: playlist.inserted_at,
      updated_at: playlist.updated_at
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

  defp serialize_video(video) do
    %{
      id: video.id,
      title: video.title,
      description: video.description,
      views: video.views,
      likes: video.likes,
      dislikes: video.dislikes
    }
  end

  defp get_user_id_from_conn(conn) do
    case conn.assigns do
      %{current_user_id: user_id} -> user_id
      _ -> nil
    end
  end
end

