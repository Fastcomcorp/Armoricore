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

defmodule ArmoricoreRealtimeWeb.Plugs.SecurityHeaders do
  @moduledoc """
  Security headers plug for enhanced web security.

  Adds comprehensive security headers including:
  - Content Security Policy (CSP)
  - HTTP Strict Transport Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  def init(opts), do: opts

  def call(conn, _opts) do
    conn
    |> put_csp_header()
    |> put_hsts_header()
    |> put_frame_options_header()
    |> put_content_type_options_header()
    |> put_referrer_policy_header()
    |> put_permissions_policy_header()
    |> put_cross_origin_headers()
  end

  # Content Security Policy - prevent XSS and injection attacks
  defp put_csp_header(conn) do
    # Conservative CSP that allows necessary resources but blocks dangerous ones
    csp = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com",
      "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https: blob:",
      "media-src 'self' https: blob:",
      "connect-src 'self' ws: wss: https:",
      "frame-src 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "upgrade-insecure-requests"
    ] |> Enum.join("; ")

    put_resp_header(conn, "content-security-policy", csp)
  end

  # HTTP Strict Transport Security - force HTTPS
  defp put_hsts_header(conn) do
    # Only set HSTS for HTTPS connections to avoid issues in development
    if conn.scheme == :https do
      # Max-age: 1 year, include subdomains, preload
      put_resp_header(conn, "strict-transport-security", "max-age=31536000; includeSubDomains; preload")
    else
      conn
    end
  end

  # X-Frame-Options - prevent clickjacking
  defp put_frame_options_header(conn) do
    put_resp_header(conn, "x-frame-options", "DENY")
  end

  # X-Content-Type-Options - prevent MIME type sniffing
  defp put_content_type_options_header(conn) do
    put_resp_header(conn, "x-content-type-options", "nosniff")
  end

  # Referrer-Policy - control referrer information
  defp put_referrer_policy_header(conn) do
    put_resp_header(conn, "referrer-policy", "strict-origin-when-cross-origin")
  end

  # Permissions-Policy - restrict browser features
  defp put_permissions_policy_header(conn) do
    # Restrict potentially dangerous permissions
    permissions = [
      "camera=()",
      "microphone=()",
      "geolocation=()",
      "gyroscope=()",
      "magnetometer=()",
      "payment=()",
      "usb=()",
      "autoplay=()",
      "fullscreen=(self)",
      "picture-in-picture=()"
    ] |> Enum.join(", ")

    put_resp_header(conn, "permissions-policy", permissions)
  end

  # Cross-Origin headers
  defp put_cross_origin_headers(conn) do
    conn
    |> put_resp_header("cross-origin-embedder-policy", "require-corp")
    |> put_resp_header("cross-origin-opener-policy", "same-origin")
    |> put_resp_header("cross-origin-resource-policy", "same-origin")
  end
end