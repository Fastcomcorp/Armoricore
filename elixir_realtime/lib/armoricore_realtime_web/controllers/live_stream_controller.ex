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

defmodule ArmoricoreRealtimeWeb.LiveStreamController do
  @moduledoc """
  Controller for live stream operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.LiveStreaming
  alias ArmoricoreRealtime.Repo

  @doc """
  List live streams (public endpoint).
  GET /api/v1/live-streams
  """
  def index(conn, params) do
    opts = parse_list_params(params)
    streams = LiveStreaming.list_live_streams(opts)
    json(conn, %{
      data: Enum.map(streams, &serialize_live_stream/1),
      count: length(streams)
    })
  end

  @doc """
  List active (live) streams (public endpoint).
  GET /api/v1/live-streams/active
  """
  def active(conn, params) do
    opts = parse_list_params(params)
    streams = LiveStreaming.list_active_streams(opts)
    json(conn, %{
      data: Enum.map(streams, &serialize_live_stream/1),
      count: length(streams)
    })
  end

  @doc """
  Get a single live stream (public endpoint).
  GET /api/v1/live-streams/:id
  """
  def show(conn, %{"id" => id}) do
    try do
      stream = LiveStreaming.get_live_stream!(id)
      json(conn, %{data: serialize_live_stream(stream)})
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Live stream not found"})
    end
  end

  @doc """
  Create a live stream (protected endpoint).
  POST /api/v1/live-streams
  """
  def create(conn, %{"live_stream" => stream_params}) do
    user_id = conn.assigns.current_user_id

    stream_params =
      stream_params
      |> Map.put("user_id", user_id)

    case LiveStreaming.create_live_stream(stream_params) do
      {:ok, stream} ->
        stream = LiveStreaming.get_live_stream!(stream.id)
        conn
        |> put_status(:created)
        |> json(%{data: serialize_live_stream(stream)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  @doc """
  Update a live stream (protected endpoint - owner only).
  PUT /api/v1/live-streams/:id
  """
  def update(conn, %{"id" => id, "live_stream" => stream_params}) do
    user_id = conn.assigns.current_user_id

    try do
      stream = LiveStreaming.get_live_stream!(id)

      # SECURITY: Only stream owner can update
      if stream.user_id == user_id do
        case LiveStreaming.update_live_stream(stream, stream_params) do
          {:ok, stream} ->
            stream = LiveStreaming.get_live_stream!(stream.id)
            json(conn, %{data: serialize_live_stream(stream)})

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Validation failed", errors: format_errors(changeset)})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to update this stream"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Live stream not found"})
    end
  end

  @doc """
  Delete a live stream (protected endpoint - owner only).
  DELETE /api/v1/live-streams/:id
  """
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      stream = LiveStreaming.get_live_stream!(id)

      # SECURITY: Only stream owner can delete
      if stream.user_id == user_id do
        Repo.delete(stream)
        conn
        |> put_status(:no_content)
        |> json(%{})
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to delete this stream"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Live stream not found"})
    end
  end

  @doc """
  Start a live stream (protected endpoint - owner only).
  POST /api/v1/live-streams/:id/start
  """
  def start(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      stream = LiveStreaming.get_live_stream!(id)

      # SECURITY: Only stream owner can start
      if stream.user_id == user_id do
        case LiveStreaming.start_live_stream(id) do
          {:ok, stream} ->
            stream = LiveStreaming.get_live_stream!(stream.id)
            json(conn, %{data: serialize_live_stream(stream)})

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to start stream", reason: reason})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to start this stream"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Live stream not found"})
    end
  end

  @doc """
  End a live stream (protected endpoint - owner only).
  POST /api/v1/live-streams/:id/end
  """
  def end_stream(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      stream = LiveStreaming.get_live_stream!(id)

      # SECURITY: Only stream owner can end
      if stream.user_id == user_id do
        case LiveStreaming.end_live_stream(id) do
          {:ok, stream} ->
            stream = LiveStreaming.get_live_stream!(stream.id)
            json(conn, %{data: serialize_live_stream(stream)})

          {:error, reason} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to end stream", reason: reason})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to end this stream"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Live stream not found"})
    end
  end

  # Helper functions

  defp parse_list_params(params) do
    [
      status: params["status"],
      user_id: params["user_id"],
      category_id: params["category_id"],
      scheduled_only: parse_boolean(params["scheduled_only"]),
      sort: parse_sort(params["sort"]),
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

  defp parse_sort(nil), do: nil
  defp parse_sort("viewers"), do: :viewers
  defp parse_sort("peak_viewers"), do: :peak_viewers
  defp parse_sort("scheduled"), do: :scheduled
  defp parse_sort("started"), do: :started
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

  defp serialize_live_stream(stream) do
    %{
      id: stream.id,
      title: stream.title,
      description: stream.description,
      status: stream.status,
      ingest_protocol: stream.ingest_protocol,
      rtmp_url: stream.rtmp_url,
      hls_url: stream.hls_url,
      dash_url: stream.dash_url,
      is_recording_enabled: stream.is_recording_enabled,
      is_chat_enabled: stream.is_chat_enabled,
      is_comments_enabled: stream.is_comments_enabled,
      scheduled_start_at: stream.scheduled_start_at,
      started_at: stream.started_at,
      ended_at: stream.ended_at,
      duration_seconds: stream.duration_seconds,
      peak_viewers: stream.peak_viewers,
      current_viewers: stream.current_viewers,
      total_views: stream.total_views,
      user: serialize_user(stream.user),
      category: serialize_category(stream.category),
      quality_profiles: Enum.map(stream.quality_profiles || [], &serialize_quality_profile/1),
      created_at: stream.inserted_at,
      updated_at: stream.updated_at
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

  defp serialize_quality_profile(profile) do
    %{
      id: profile.id,
      quality_name: profile.quality_name,
      resolution: "#{profile.resolution_width}x#{profile.resolution_height}",
      bitrate_kbps: profile.bitrate_kbps,
      framerate: profile.framerate,
      codec: profile.codec,
      hls_segment_url: profile.hls_segment_url
    }
  end
end

