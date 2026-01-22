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

defmodule ArmoricoreRealtimeWeb.WatchHistoryController do
  @moduledoc """
  Controller for watch history operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Social
  alias ArmoricoreRealtime.Content

  @doc """
  Update watch history for a video (protected endpoint).
  POST /api/v1/watch-history
  """
  def create(conn, %{"video_id" => video_id, "watch_progress" => watch_progress, "video_duration" => video_duration}) do
    user_id = conn.assigns.current_user_id

    # Get video to get duration if not provided
    case Content.get_video(video_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Video not found"})

      video ->
        # Get duration from media if available
        video_duration = case video.media do
          %{duration: duration} when is_integer(duration) -> duration
          _ -> String.to_integer(video_duration)
        end

        watch_progress = String.to_integer(watch_progress)

        case Social.update_watch_history(user_id, video_id, watch_progress, video_duration) do
      {:ok, history} ->
        history = Social.get_watch_history(user_id, video_id)
        json(conn, %{data: serialize_watch_history(history)})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to update watch history", errors: format_errors(changeset)})
        end
    end
  end

  @doc """
  List user's watch history (protected endpoint).
  GET /api/v1/watch-history
  """
  def index(conn, params) do
    user_id = conn.assigns.current_user_id
    opts = parse_list_params(params)
    history = Social.list_watch_history(user_id, opts)
    json(conn, %{
      data: Enum.map(history, &serialize_watch_history/1),
      count: length(history)
    })
  end

  @doc """
  Get watch history for a specific video (protected endpoint).
  GET /api/v1/watch-history/:video_id
  """
  def show(conn, %{"video_id" => video_id}) do
    user_id = conn.assigns.current_user_id

    case Social.get_watch_history(user_id, video_id) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Watch history not found"})

      history ->
        json(conn, %{data: serialize_watch_history(history)})
    end
  end

  @doc """
  Clear watch history (protected endpoint).
  DELETE /api/v1/watch-history
  """
  def delete(conn, _params) do
    user_id = conn.assigns.current_user_id
    Social.clear_watch_history(user_id)
    conn
    |> put_status(:no_content)
    |> json(%{})
  end

  # Helper functions

  defp parse_list_params(params) do
    [
      completed: parse_boolean(params["completed"]),
      page: parse_page(params["page"]),
      limit: parse_limit(params["limit"])
    ]
    |> Enum.filter(fn {_key, value} -> not is_nil(value) end)
  end

  defp parse_boolean(nil), do: nil
  defp parse_boolean("true"), do: true
  defp parse_boolean("false"), do: false
  defp parse_boolean(bool) when is_boolean(bool), do: bool
  defp parse_boolean(_), do: nil

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

  defp serialize_watch_history(history) do
    %{
      id: history.id,
      video: serialize_video(history.video),
      watch_progress: history.watch_progress,
      watch_percentage: history.watch_percentage,
      completed: history.completed,
      last_watched_at: history.last_watched_at,
      created_at: history.inserted_at,
      updated_at: history.updated_at
    }
  end

  defp serialize_video(nil), do: nil
  defp serialize_video(video) do
    %{
      id: video.id,
      title: video.title,
      description: video.description,
      duration: get_video_duration(video),
      views: video.views,
      likes: video.likes,
      dislikes: video.dislikes
    }
  end

  defp get_video_duration(video) do
    case video.media do
      %{duration: duration} when is_integer(duration) -> duration
      _ -> nil
    end
  end
end

