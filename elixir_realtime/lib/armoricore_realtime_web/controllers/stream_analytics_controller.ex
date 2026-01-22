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

defmodule ArmoricoreRealtimeWeb.StreamAnalyticsController do
  @moduledoc """
  Controller for stream analytics operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.LiveStreaming

  @doc """
  Get analytics for a stream (protected endpoint - owner only).
  GET /api/v1/live-streams/:id/analytics
  """
  def show(conn, %{"id" => stream_id} = params) do
    user_id = conn.assigns.current_user_id

    try do
      stream = LiveStreaming.get_live_stream!(stream_id)

      # SECURITY: Only stream owner can view analytics
      if stream.user_id == user_id do
        opts = parse_analytics_params(params)
        analytics = LiveStreaming.get_stream_analytics(stream_id, opts)
        json(conn, %{data: analytics})
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to view analytics for this stream"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Stream not found"})
    end
  end

  @doc """
  Get concurrent viewers for a stream (public endpoint).
  GET /api/v1/live-streams/:id/viewers
  """
  def viewers(conn, %{"id" => stream_id}) do
    case LiveStreaming.get_concurrent_viewers(stream_id) do
      {:ok, viewer_stats} ->
        json(conn, %{data: viewer_stats})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Stream not found"})
    end
  end

  @doc """
  Track viewer join (internal endpoint - called by clients).
  POST /api/v1/live-streams/:id/track-join
  """
  def track_join(conn, %{"id" => stream_id} = params) do
    user_id = conn.assigns.current_user_id

    attrs = %{
      viewer_ip: get_client_ip(conn),
      user_agent: get_req_header(conn, "user-agent") |> List.first(),
      quality: params["quality"],
      bitrate: parse_integer(params["bitrate"]),
    }

    # track_viewer_join currently always returns :ok
    # Future versions may return {:error, :not_found}
    LiveStreaming.track_viewer_join(stream_id, user_id, attrs)
    json(conn, %{success: true})
  end

  @doc """
  Track viewer leave (internal endpoint - called by clients).
  POST /api/v1/live-streams/:id/track-leave
  """
  def track_leave(conn, %{"id" => stream_id} = params) do
    user_id = conn.assigns.current_user_id

    attrs = %{
      viewer_ip: get_client_ip(conn),
      user_agent: get_req_header(conn, "user-agent") |> List.first(),
      quality: params["quality"],
    }

    # track_viewer_leave currently always returns :ok
    # Future versions may return {:error, :not_found}
    LiveStreaming.track_viewer_leave(stream_id, user_id, attrs)
    json(conn, %{success: true})
  end

  # Helper functions

  defp parse_analytics_params(params) do
    [
      event_type: params["event_type"],
      start_date: parse_datetime(params["start_date"]),
      end_date: parse_datetime(params["end_date"]),
    ]
    |> Enum.filter(fn {_key, value} -> not is_nil(value) end)
  end

  defp parse_datetime(nil), do: nil
  defp parse_datetime(datetime_str) when is_binary(datetime_str) do
    case DateTime.from_iso8601(datetime_str) do
      {:ok, datetime, _} -> datetime
      _ -> nil
    end
  end
  defp parse_datetime(_), do: nil

  defp parse_integer(nil), do: nil
  defp parse_integer(int_str) when is_binary(int_str) do
    case Integer.parse(int_str) do
      {int, _} -> int
      _ -> nil
    end
  end
  defp parse_integer(int) when is_integer(int), do: int
  defp parse_integer(_), do: nil

  defp get_client_ip(conn) do
    # Try to get IP from peer data first (more reliable)
    case Plug.Conn.get_peer_data(conn) do
      %{address: address} when is_tuple(address) ->
        address
        |> Tuple.to_list()
        |> Enum.join(".")

      _ ->
        # Fallback to X-Forwarded-For header
        case get_req_header(conn, "x-forwarded-for") do
          [ip | _] -> ip
          _ -> nil
        end
    end
  end
end

