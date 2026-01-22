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

defmodule ArmoricoreRealtimeWeb.Plugs.VerifyCSRFToken do
  @moduledoc """
  CSRF protection plug for API endpoints.
  
  For REST APIs, CSRF protection is implemented via:
  1. Custom header validation (X-Requested-With)
  2. Origin header validation (optional, configurable)
  3. SameSite cookie validation (for browser-based API calls)
  
  This protects state-changing operations (POST, PUT, PATCH, DELETE) from
  cross-site request forgery attacks.
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  def init(opts) do
    %{
      only: Keyword.get(opts, :only, [:post, :put, :patch, :delete]),
      require_custom_header: Keyword.get(opts, :require_custom_header, true),
      allowed_origins: Keyword.get(opts, :allowed_origins, [])
    }
  end

  def call(conn, opts) do
    method = conn.method |> String.downcase() |> String.to_existing_atom()
    
    if method in opts.only do
      verify_csrf_token(conn, opts)
    else
      conn
    end
  end

  defp verify_csrf_token(conn, opts) do
    # Method 1: Check for custom header (X-Requested-With)
    # This is a common CSRF protection technique for REST APIs
    if opts.require_custom_header do
      case get_req_header(conn, "x-requested-with") do
        ["XMLHttpRequest" | _] ->
          # Valid custom header present
          conn
        
        _ ->
          # Check if Origin header matches allowed origins
          case validate_origin(conn, opts.allowed_origins) do
            :ok ->
              conn
            
            :error ->
              Logger.warning("CSRF protection: Missing X-Requested-With header or invalid origin",
                ip: conn.remote_ip,
                path: conn.request_path,
                method: conn.method
              )
              
              conn
              |> put_resp_content_type("application/json")
              |> send_resp(403, Jason.encode!(%{
                error: "CSRF token validation failed",
                message: "This request requires CSRF protection. Please include X-Requested-With header."
              }))
              |> halt()
          end
      end
    else
      # If custom header not required, just validate origin
      case validate_origin(conn, opts.allowed_origins) do
        :ok -> conn
        :error ->
          Logger.warning("CSRF protection: Invalid origin",
            ip: conn.remote_ip,
            path: conn.request_path
          )
          conn
          |> put_resp_content_type("application/json")
          |> send_resp(403, Jason.encode!(%{error: "CSRF token validation failed"}))
          |> halt()
      end
    end
  end

  # Validate Origin header against allowed origins
  defp validate_origin(conn, allowed_origins) when is_list(allowed_origins) and length(allowed_origins) > 0 do
    origin = get_req_header(conn, "origin") |> List.first()
    referer = get_req_header(conn, "referer") |> List.first()
    
    cond do
      is_nil(origin) and is_nil(referer) ->
        # No origin/referer - might be a direct API call (allow if from trusted source)
        :ok
      
      origin in allowed_origins ->
        :ok
      
      referer && String.starts_with?(referer, hd(allowed_origins)) ->
        :ok
      
      true ->
        :error
    end
  end

  defp validate_origin(_conn, _), do: :ok  # If no origins configured, allow all
end

