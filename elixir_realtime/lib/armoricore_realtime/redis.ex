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

defmodule ArmoricoreRealtime.Redis do
  @moduledoc """
  Redis connection manager for distributed rate limiting.
  
  Manages a persistent Redis connection using Redix.
  Connection is optional - if Redis is not configured, the application will
  fall back to ETS-based rate limiting.
  """
  
  use GenServer
  require Logger
  
  @server __MODULE__
  
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: @server)
  end
  
  def get_connection do
    GenServer.call(@server, :get_connection)
  end
  
  @impl true
  def init(_opts) do
    case Application.get_env(:armoricore_realtime, :redis_url) do
      nil ->
        Logger.info("Redis not configured - using ETS for rate limiting")
        {:ok, nil}
      
      url ->
        Logger.info("Connecting to Redis for distributed rate limiting: #{redact_url(url)}")
        # Redix supports redis:// URLs directly
        # Start Redix connection as a child process
        case Redix.start_link(url, sync_connect: true, name: nil) do
          {:ok, pid} ->
            Logger.info("Redis connected successfully")
            {:ok, pid}
          
          {:error, reason} ->
            Logger.warning("Failed to connect to Redis: #{inspect(reason)}. Falling back to ETS.")
            {:ok, nil}
        end
    end
  end
  
  @impl true
  def handle_call(:get_connection, _from, state) do
    case state do
      nil -> {:reply, {:error, :not_configured}, state}
      pid -> {:reply, {:ok, pid}, state}
    end
  end
  
  @impl true
  def handle_info({:redix, pid, :disconnected}, state) do
    Logger.warning("Redis disconnected, falling back to ETS")
    {:noreply, nil}
  end
  
  @impl true
  def handle_info({:redix, pid, :reconnected}, state) do
    Logger.info("Redis reconnected")
    {:noreply, pid}
  end
  
  @impl true
  def handle_info(msg, state) do
    Logger.debug("Redis received unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end
  
  # Redact password from Redis URL for logging
  defp redact_url(url) do
    case String.split(url, "@") do
      [auth, rest] ->
        case String.split(auth, ":") do
          [user, _pass] -> "#{user}:***@#{rest}"
          _ -> "***@#{rest}"
        end
      _ -> url
    end
  end
end

