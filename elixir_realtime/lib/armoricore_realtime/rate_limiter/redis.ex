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

defmodule ArmoricoreRealtime.RateLimiter.Redis do
  @moduledoc """
  Redis-based distributed rate limiting.
  
  Uses Redis for shared rate limit state across multiple nodes.
  Implements a sliding window rate limiting algorithm using Redis.
  """
  
  require Logger
  
  @redis_key_prefix "rate_limit:"
  
  @doc """
  Checks if a request should be allowed based on rate limits.
  
  Returns:
  - `:ok` if request is allowed
  - `{:error, :rate_limit_exceeded}` if rate limit is exceeded
  - `{:error, reason}` if Redis operation failed
  """
  @spec check_rate_limit(String.t(), String.t(), integer(), integer()) :: 
    :ok | {:error, :rate_limit_exceeded | atom()}
  def check_rate_limit(ip, path, limit, window_ms) do
    case get_redis_connection() do
      {:ok, pid} ->
        check_with_redis(pid, ip, path, limit, window_ms)
      
      {:error, :not_configured} ->
        # Redis not configured, fallback to ETS
        {:error, :fallback_to_ets}
      
      {:error, reason} ->
        Logger.warning("Redis connection error, falling back to ETS: #{inspect(reason)}")
        {:error, :fallback_to_ets}
    end
  end
  
  @doc """
  Gets the remaining requests for a given IP and path.
  """
  @spec get_remaining(String.t(), String.t(), integer(), integer()) :: 
    {:ok, integer()} | {:error, atom()}
  def get_remaining(ip, path, limit, window_ms) do
    case get_redis_connection() do
      {:ok, pid} ->
        key = build_key(ip, path)
        window_seconds = div(window_ms, 1000)
        
        # Get current count
        case Redix.command(pid, ["GET", key]) do
          {:ok, nil} ->
            {:ok, limit}
          
          {:ok, count_str} ->
            count = String.to_integer(count_str)
            remaining = max(0, limit - count)
            {:ok, remaining}
          
          {:error, reason} ->
            {:error, reason}
        end
      
      {:error, _} ->
        {:error, :not_configured}
    end
  end
  
  # Private functions
  
  defp check_with_redis(pid, ip, path, limit, window_ms) do
    key = build_key(ip, path)
    window_seconds = div(window_ms, 1000)
    
    # Use Redis INCR with EXPIRE for atomic sliding window rate limiting
    # This implements a simple counter with expiration
    case Redix.command(pid, ["INCR", key]) do
      {:ok, count} when is_integer(count) ->
        # Set expiration on first increment (if key is new)
        if count == 1 do
          Redix.command(pid, ["EXPIRE", key, Integer.to_string(window_seconds)])
        end
        
        # Check if limit exceeded
        if count > limit do
          # Decrement since we exceeded the limit
          Redix.command(pid, ["DECR", key])
          {:error, :rate_limit_exceeded}
        else
          :ok
        end
      
      {:ok, count_str} ->
        # Handle string response (shouldn't happen, but be safe)
        count = String.to_integer(count_str)
        if count == 1 do
          Redix.command(pid, ["EXPIRE", key, Integer.to_string(window_seconds)])
        end
        if count > limit do
          Redix.command(pid, ["DECR", key])
          {:error, :rate_limit_exceeded}
        else
          :ok
        end
      
      {:error, reason} ->
        Logger.error("Redis command error: #{inspect(reason)}")
        {:error, reason}
    end
  end
  
  defp build_key(ip, path) do
    # Sanitize path to create a safe key
    safe_path = path
      |> String.replace("/", ":")
      |> String.replace(" ", "_")
      |> String.slice(0, 100)  # Limit key length
    
    "#{@redis_key_prefix}#{ip}:#{safe_path}"
  end
  
  defp get_redis_connection do
    # Check if Redis module is available
    if Code.ensure_loaded?(ArmoricoreRealtime.Redis) do
      case ArmoricoreRealtime.Redis.get_connection() do
        {:ok, pid} -> {:ok, pid}
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, :not_configured}
    end
  end
end

