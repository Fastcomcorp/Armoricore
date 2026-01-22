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

defmodule ArmoricoreRealtimeWeb.StreamRecordingController do
  @moduledoc """
  Controller for stream recording operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.LiveStreaming
  alias ArmoricoreRealtime.Repo
  import Ecto.Query

  @doc """
  Start recording a stream (protected endpoint - owner only).
  POST /api/v1/live-streams/:id/recordings
  """
  def create(conn, %{"id" => stream_id} = params) do
    user_id = conn.assigns.current_user_id

    try do
      stream = LiveStreaming.get_live_stream!(stream_id)

      # SECURITY: Only stream owner can start recording
      if stream.user_id == user_id do
        attrs = Map.take(params, ["storage_path"])
        case LiveStreaming.start_recording(stream_id, attrs) do
          {:ok, recording} ->
            recording = Repo.preload(recording, [:stream])
            conn
            |> put_status(:created)
            |> json(%{data: serialize_recording(recording)})

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Validation failed", errors: format_errors(changeset)})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to record this stream"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Stream not found"})
    end
  end

  @doc """
  Get recording for a stream (protected endpoint - owner only).
  GET /api/v1/live-streams/:id/recordings/:recording_id
  """
  def show(conn, %{"id" => stream_id, "recording_id" => recording_id}) do
    user_id = conn.assigns.current_user_id

    try do
      stream = LiveStreaming.get_live_stream!(stream_id)

      # SECURITY: Only stream owner can view recordings
      if stream.user_id == user_id do
        case Repo.get(ArmoricoreRealtime.LiveStreaming.StreamRecording, recording_id) do
          nil ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Recording not found"})

          recording ->
            recording = Repo.preload(recording, [:stream, :media])
            json(conn, %{data: serialize_recording(recording)})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to view recordings for this stream"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Stream not found"})
    end
  end

  @doc """
  List recordings for a stream (protected endpoint - owner only).
  GET /api/v1/live-streams/:id/recordings
  """
  def index(conn, %{"id" => stream_id}) do
    user_id = conn.assigns.current_user_id

    try do
      stream = LiveStreaming.get_live_stream!(stream_id)

      # SECURITY: Only stream owner can list recordings
      if stream.user_id == user_id do
        recordings = from(r in ArmoricoreRealtime.LiveStreaming.StreamRecording,
          where: r.stream_id == ^stream_id,
          order_by: [desc: r.started_at],
          preload: [:media]
        )
        |> Repo.all()

        json(conn, %{
          data: Enum.map(recordings, &serialize_recording/1),
          count: length(recordings)
        })
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to list recordings for this stream"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Stream not found"})
    end
  end

  @doc """
  Update recording progress (internal endpoint).
  PUT /api/v1/live-streams/:id/recordings/:recording_id
  """
  def update(conn, %{"id" => _stream_id, "recording_id" => recording_id} = params) do
    attrs = Map.take(params, ["segment_count", "total_size_bytes", "recording_status"])

    case LiveStreaming.update_recording(recording_id, attrs) do
      {:ok, recording} ->
        recording = Repo.preload(recording, [:stream])
        json(conn, %{data: serialize_recording(recording)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Recording not found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  @doc """
  Complete recording and trigger VOD conversion (internal endpoint).
  POST /api/v1/live-streams/:id/recordings/:recording_id/complete
  """
  def complete(conn, %{"id" => _stream_id, "recording_id" => recording_id} = params) do
    media_id = params["media_id"]

    case LiveStreaming.complete_recording(recording_id, media_id) do
      {:ok, recording} ->
        recording = Repo.preload(recording, [:stream, :media])
        json(conn, %{data: serialize_recording(recording)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Recording not found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  # Helper functions

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp serialize_recording(recording) do
    %{
      id: recording.id,
      stream_id: recording.stream_id,
      media_id: recording.media_id,
      recording_status: recording.recording_status,
      segment_count: recording.segment_count,
      total_size_bytes: recording.total_size_bytes,
      storage_path: recording.storage_path,
      started_at: recording.started_at,
      ended_at: recording.ended_at,
      processed_at: recording.processed_at,
      created_at: recording.inserted_at,
      updated_at: recording.updated_at
    }
  end
end

