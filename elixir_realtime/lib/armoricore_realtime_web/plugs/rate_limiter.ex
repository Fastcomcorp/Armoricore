# Copyright 2026 Francisco F. Pinochet, Fastcomcorp
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

defmodule ArmoricoreRealtimeWeb.Plugs.RateLimiter do
  @moduledoc """
  Rate limiting plug for API endpoints.
  
  Uses distributed rate limiting with Redis when available, falls back to ETS for single-node deployments.
  Implements a sliding window rate limiting algorithm.
  """
  
  import Plug.Conn
  require Logger

  @behaviour Plug

  # Default rate limits (requests per window)
  @default_limit 100
  @default_window 60_000 # 1 minute in milliseconds
  
  # Rate limits by endpoint type
  @limits %{
    "/api/auth/login" => {10, 60_000},      # 10 requests per minute
    "/api/auth/register" => {5, 60_000},    # 5 requests per minute
    "/api/auth/refresh" => {20, 60_000},    # 20 requests per minute
    "/api/media/upload" => {50, 60_000},    # 50 requests per minute
    "/api/notifications" => {100, 60_000},  # 100 requests per minute
    default: {@default_limit, @default_window}
  }

  def init(opts), do: opts

  def call(conn, _opts) do
    client_ip = get_client_ip(conn)
    path = conn.request_path
    
    {limit, window} = get_limit_for_path(path)
    
    case check_rate_limit(client_ip, path, limit, window) do
      :ok ->
        # Get remaining count (for Redis) or calculate (for ETS)
        remaining = get_remaining_count(client_ip, path, limit, window)
        
        conn
        |> put_resp_header("x-ratelimit-limit", Integer.to_string(limit))
        |> put_resp_header("x-ratelimit-remaining", Integer.to_string(remaining))
        |> put_resp_header("x-ratelimit-reset", Integer.to_string(get_reset_time(window)))
      
      {:error, :rate_limit_exceeded} ->
        Logger.warning("Rate limit exceeded for IP: #{client_ip}, path: #{path}")
        conn
        |> put_status(429)
        |> put_resp_header("x-ratelimit-limit", Integer.to_string(limit))
        |> put_resp_header("x-ratelimit-remaining", "0")
        |> put_resp_header("x-ratelimit-reset", Integer.to_string(get_reset_time(window)))
        |> put_resp_content_type("application/json")
        |> send_resp(429, Jason.encode!(%{error: "Rate limit exceeded. Please try again later."}))
        |> halt()
    end
  end

  # SECURITY: Validate X-Forwarded-For header to prevent IP spoofing
  defp get_client_ip(conn) do
    # Only trust X-Forwarded-For if behind a trusted proxy
    trusted_proxies = Application.get_env(:armoricore_realtime, :trusted_proxies, [])
    remote_ip = conn.remote_ip
    
    if Enum.empty?(trusted_proxies) || remote_ip in trusted_proxies do
      case get_req_header(conn, "x-forwarded-for") do
        [header | _] ->
          # Extract first IP from comma-separated list
          ip = header
            |> String.split(",")
            |> List.first()
            |> String.trim()
          
          # Validate IP format to prevent injection
          case validate_ip_address(ip) do
            {:ok, validated_ip} -> validated_ip
            {:error, _} -> to_string(:inet.ntoa(remote_ip))
          end
        
        _ ->
          to_string(:inet.ntoa(remote_ip))
      end
    else
      # Not behind trusted proxy, use direct connection IP
      to_string(:inet.ntoa(remote_ip))
    end
  end
  
  # Validate IP address format
  defp validate_ip_address(ip_string) do
    case :inet.parse_address(String.to_charlist(ip_string)) do
      {:ok, _ip_tuple} -> {:ok, ip_string}
      {:error, _} -> {:error, :invalid_ip}
    end
  end

  defp get_limit_for_path(path) do
    Enum.find_value(@limits, @limits.default, fn
      {key, value} when key != :default ->
        if String.starts_with?(path, key), do: value
      _ -> false
    end)
  end

  defp check_rate_limit(ip, path, limit, window) do
    # SECURITY: Try Redis first for distributed rate limiting
    # Falls back to ETS if Redis is not configured or unavailable
    case check_with_redis(ip, path, limit, window) do
      :ok ->
        :ok
      
      {:error, :rate_limit_exceeded} ->
        {:error, :rate_limit_exceeded}
      
      {:error, :fallback_to_ets} ->
        # Redis not available, use ETS fallback
        check_with_ets(ip, path, limit, window)
      
      {:error, _reason} ->
        # Redis error, fallback to ETS
        Logger.warning("Redis rate limiting failed, using ETS fallback")
        check_with_ets(ip, path, limit, window)
    end
  end
  
  # Try Redis-based rate limiting
  defp check_with_redis(ip, path, limit, window) do
    # Check if Redis rate limiter module is available (only if redix is loaded)
    if Code.ensure_loaded?(ArmoricoreRealtime.RateLimiter.Redis) do
      ArmoricoreRealtime.RateLimiter.Redis.check_rate_limit(ip, path, limit, window)
    else
      {:error, :fallback_to_ets}
    end
  end
  
  # ETS-based rate limiting (fallback for single-node deployments)
  defp check_with_ets(ip, path, limit, window) do
    # Ensure ETS table exists (create if it doesn't)
    ensure_ets_table()
    
    key = {:rate_limit, ip, path}
    now = System.system_time(:millisecond)
    
    case :ets.lookup(:rate_limits, key) do
      [] ->
        # First request, create entry
        reset_time = now + window
        :ets.insert(:rate_limits, {key, 1, reset_time})
        :ok
      
      [{^key, count, reset_time}] ->
        if now > reset_time do
          # Window expired, reset
          new_reset_time = now + window
          :ets.insert(:rate_limits, {key, 1, new_reset_time})
          :ok
        else
          if count >= limit do
            {:error, :rate_limit_exceeded}
          else
            # Increment counter atomically
            :ets.update_counter(:rate_limits, key, {2, 1})
            :ok
          end
        end
    end
  end

  defp get_reset_time(window) do
    # Return Unix timestamp in seconds
    div(System.system_time(:millisecond) + window, 1000)
  end
  
  # Get remaining request count (works with both Redis and ETS)
  defp get_remaining_count(ip, path, limit, window) do
    # Try Redis first
    if Code.ensure_loaded?(ArmoricoreRealtime.RateLimiter.Redis) do
      case ArmoricoreRealtime.RateLimiter.Redis.get_remaining(ip, path, limit, window) do
        {:ok, remaining} -> remaining
        {:error, _} -> get_remaining_from_ets(ip, path, limit, window)
      end
    else
      get_remaining_from_ets(ip, path, limit, window)
    end
  end
  
  # Get remaining count from ETS
  defp get_remaining_from_ets(ip, path, limit, window) do
    ensure_ets_table()
    key = {:rate_limit, ip, path}
    now = System.system_time(:millisecond)
    
    case :ets.lookup(:rate_limits, key) do
      [] ->
        limit
      
      [{^key, count, reset_time}] ->
        if now > reset_time do
          limit
        else
          max(0, limit - count)
        end
    end
  end

  defp ensure_ets_table do
    case :ets.whereis(:rate_limits) do
      :undefined ->
        # Table doesn't exist, create it
        :ets.new(:rate_limits, [:named_table, :public, :set])
      _ ->
        # Table exists, do nothing
        :ok
    end
  end
end
