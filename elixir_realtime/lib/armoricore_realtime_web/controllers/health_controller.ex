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

defmodule ArmoricoreRealtimeWeb.HealthController do
  @moduledoc """
  Health check controller for Armoricore.

  Provides comprehensive health monitoring endpoints that check the status of all
  critical system components including database connectivity, message bus, media
  engine, and external services.

  ## Endpoints

  - `GET /api/v1/health` - Comprehensive health check with detailed status

  ## Health Checks Performed

  - **Database**: PostgreSQL connection and query execution
  - **NATS**: Message bus connectivity and status
  - **ArcRTC Media Engine**: Media processing service availability
  - **Redis**: Caching layer connectivity (if configured)
  - **Application**: Uptime, version, and system metrics

  ## Security

  Health checks can be optionally authenticated to prevent information disclosure
  in production environments. Configure via `HEALTH_CHECK_AUTH_ENABLED=true`.
  """
  use ArmoricoreRealtimeWeb, :controller

  require Logger

  @doc """
  Comprehensive health check endpoint with detailed service status.

  Includes checks for:
  - Database connectivity
  - NATS message bus
  - ArcRTC media engine
  - Redis (if configured)

  SECURITY: Optionally requires authentication to prevent information disclosure.
  Configure via environment variable: HEALTH_CHECK_AUTH_ENABLED=true
  """
  def check(conn, _params) do
    # SECURITY: Optional authentication for health check to prevent information disclosure
    case should_authenticate_health_check?() do
      true ->
        case authenticate_health_check(conn) do
          :ok ->
            send_detailed_health_response(conn)

          {:error, reason} ->
            Logger.warning("Unauthorized health check attempt",
              ip: conn.remote_ip,
              reason: reason
            )
            conn
            |> put_status(:unauthorized)
            |> json(%{error: "Unauthorized"})
        end

      false ->
        send_detailed_health_response(conn)
    end
  end

  # Send comprehensive health check response
  defp send_detailed_health_response(conn) do
    health_status = %{
      status: "healthy",
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      version: Application.spec(:armoricore_realtime, :vsn),
      uptime: get_uptime(),
      environment: Application.get_env(:armoricore_realtime, Mix.env()),
      checks: %{
        database: check_database(),
        nats: check_nats(),
        arbrtc_media_engine: check_arcrtc_engine(),
        redis: check_redis()
      }
    }

    # Determine overall status
    overall_status = if all_checks_pass?(health_status.checks), do: "healthy", else: "unhealthy"
    status_code = if overall_status == "healthy", do: 200, else: 503

    conn
    |> put_status(status_code)
    |> json(Map.put(health_status, :status, overall_status))
  end
  
  # Check if health check authentication should be enabled
  defp should_authenticate_health_check? do
    Application.get_env(:armoricore_realtime, :health_check_auth_enabled, false)
  end
  
  # Authenticate health check request
  defp authenticate_health_check(conn) do
    # Option 1: Basic Auth
    case get_req_header(conn, "authorization") do
      ["Basic " <> encoded] ->
        case Base.decode64(encoded) do
          {:ok, credentials} ->
            [username, password] = String.split(credentials, ":", parts: 2)
            expected_username = System.get_env("HEALTH_CHECK_USERNAME") || "health"
            expected_password = System.get_env("HEALTH_CHECK_PASSWORD")
            
            if username == expected_username and password == expected_password do
              :ok
            else
              {:error, :invalid_credentials}
            end
          
          :error ->
            {:error, :invalid_encoding}
        end
      
      _ ->
        # Option 2: IP whitelist
        case check_ip_whitelist(conn.remote_ip) do
          true -> :ok
          false -> {:error, :ip_not_whitelisted}
        end
    end
  end
  
  # Check if IP is in whitelist
  defp check_ip_whitelist(remote_ip) do
    whitelist = Application.get_env(:armoricore_realtime, :health_check_ip_whitelist, [])
    remote_ip in whitelist
  end

  # Get application uptime
  defp get_uptime do
    {total_time, _} = :erlang.statistics(:wall_clock)
    total_time / 1000  # Convert to seconds
  end

  # Check database connectivity
  defp check_database do
    start_time = System.monotonic_time(:millisecond)

    try do
      # Simple query to test database connectivity
      case Ecto.Adapters.SQL.query(ArmoricoreRealtime.Repo, "SELECT 1 as test", []) do
        {:ok, %Postgrex.Result{}} ->
          response_time = System.monotonic_time(:millisecond) - start_time
          %{status: "healthy", response_time: response_time}

        {:error, error} ->
          %{status: "unhealthy", error: inspect(error)}
      end
    rescue
      error ->
        %{status: "unhealthy", error: inspect(error)}
    end
  end

  # Check NATS message bus connectivity
  defp check_nats do
    # Check if MessageBus process is alive
    case Process.whereis(ArmoricoreRealtime.MessageBus) do
      nil ->
        %{status: "not_configured", note: "MessageBus not running in this environment"}
      _pid ->
        try do
          case ArmoricoreRealtime.MessageBus.status() do
            :connected ->
              %{status: "healthy", connection_status: "connected"}
            :connecting ->
              %{status: "degraded", connection_status: "connecting"}
            :disconnected ->
              %{status: "unhealthy", connection_status: "disconnected"}
          end
        rescue
          _error ->
            %{status: "error", note: "MessageBus status check failed"}
        end
    end
  end

  # Check ArcRTC media engine connectivity
  defp check_arcrtc_engine do
    case ArmoricoreRealtime.MediaEngineClient.health_check() do
      {:ok, %{status: "healthy"} = result} ->
        %{status: "healthy", response_time: result[:response_time], grpc_url: result[:grpc_url]}
      
      {:ok, %{status: "unavailable"} = result} ->
        # Media engine not running is acceptable - it's an optional component
        %{status: "not_configured", note: result[:note], grpc_url: result[:grpc_url]}
      
      {:ok, %{status: "not_running"}} ->
        # MediaEngineClient process not started
        %{status: "not_configured", note: "MediaEngineClient not started"}
      
      {:ok, %{status: status} = result} ->
        %{status: status, note: result[:note] || result[:error]}
      
      {:error, reason} ->
        %{status: "unhealthy", error: inspect(reason)}
    end
  end

  # Check Redis connectivity (if configured)
  defp check_redis do
    case Application.get_env(:armoricore_realtime, :redis_url) do
      nil ->
        %{status: "not_configured"}

      _redis_url ->
        # Check Redis connectivity
        case ArmoricoreRealtime.Redis.get_connection() do
          {:ok, conn} when is_pid(conn) ->
            # Try a simple PING command
            start_time = System.monotonic_time(:millisecond)
            case Redix.command(conn, ["PING"]) do
              {:ok, "PONG"} ->
                response_time = System.monotonic_time(:millisecond) - start_time
                %{status: "healthy", response_time: response_time}
              {:error, reason} ->
                %{status: "unhealthy", error: inspect(reason)}
            end
          {:error, :not_configured} ->
            %{status: "not_configured"}
          {:error, reason} ->
            %{status: "unhealthy", error: inspect(reason)}
        end
    end
  rescue
    error ->
      %{status: "error", note: inspect(error)}
  end

  # Check if all health checks pass
  defp all_checks_pass?(checks) do
    Enum.all?(checks, fn {_service, check} ->
      check.status in ["healthy", "not_configured"]
    end)
  end
end
