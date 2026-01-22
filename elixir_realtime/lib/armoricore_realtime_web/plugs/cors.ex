# Copyright 2025 Fastcomcorp
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

defmodule ArmoricoreRealtimeWeb.Plugs.CORS do
  @moduledoc """
  CORS (Cross-Origin Resource Sharing) plug for API endpoints.
  
  Configurable via application config:
  
      config :armoricore_realtime, :cors,
        origins: ["https://yourdomain.com", "https://app.yourdomain.com"],
        max_age: 86400,
        credentials: true,
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        headers: ["Content-Type", "Authorization", "X-Requested-With"]
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  def init(opts), do: opts

  def call(conn, _opts) do
    if cors_enabled?() do
      handle_cors(conn)
    else
      conn
    end
  end

  defp handle_cors(conn) do
    conn
    |> handle_preflight()
    |> add_cors_headers()
  end

  # Handle preflight OPTIONS requests
  defp handle_preflight(%{method: "OPTIONS"} = conn) do
    conn
    |> put_resp_header("access-control-max-age", max_age())
    |> send_resp(:no_content, "")
    |> halt()
  end

  defp handle_preflight(conn), do: conn

  # Add CORS headers to response
  defp add_cors_headers(conn) do
    origin = get_req_header(conn, "origin") |> List.first()
    
    if origin && origin_allowed?(origin) do
      conn
      |> put_resp_header("access-control-allow-origin", origin)
      |> put_resp_header("access-control-allow-methods", allowed_methods())
      |> put_resp_header("access-control-allow-headers", allowed_headers())
      |> put_resp_header("access-control-max-age", max_age())
      |> put_resp_header("access-control-allow-credentials", allow_credentials())
    else
      # No origin or origin not allowed - don't add CORS headers
      conn
    end
  end

  # Check if CORS is enabled
  defp cors_enabled? do
    Application.get_env(:armoricore_realtime, :cors_enabled, false)
  end

  # Get allowed origins from config
  defp allowed_origins do
    Application.get_env(:armoricore_realtime, :cors)[:origins] || []
  end

  # Check if origin is allowed
  defp origin_allowed?(origin) do
    origins = allowed_origins()
    
    cond do
      "*" in origins ->
        # Allow all origins (not recommended for production)
        true
      
      origin in origins ->
        true
      
      # Check wildcard patterns (e.g., "https://*.example.com")
      true ->
        Enum.any?(origins, fn pattern ->
          case String.split(pattern, "*") do
            [prefix, suffix] ->
              String.starts_with?(origin, prefix) && String.ends_with?(origin, suffix)
            _ ->
              false
          end
        end)
    end
  end

  # Get allowed methods
  defp allowed_methods do
    methods = Application.get_env(:armoricore_realtime, :cors)[:methods] || 
              ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    Enum.join(methods, ", ")
  end

  # Get allowed headers
  defp allowed_headers do
    headers = Application.get_env(:armoricore_realtime, :cors)[:headers] || 
              ["Content-Type", "Authorization", "X-Requested-With"]
    Enum.join(headers, ", ")
  end

  # Get max age for preflight cache
  defp max_age do
    age = Application.get_env(:armoricore_realtime, :cors)[:max_age] || 86400
    to_string(age)
  end

  # Get credentials setting
  defp allow_credentials do
    credentials = Application.get_env(:armoricore_realtime, :cors)[:credentials] || false
    to_string(credentials)
  end
end

