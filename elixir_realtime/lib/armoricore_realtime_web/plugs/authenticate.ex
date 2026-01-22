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

# Copyright 2025 Francisco F. Pinochet
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

defmodule ArmoricoreRealtimeWeb.Plugs.Authenticate do
  @moduledoc """
  Plug for authenticating HTTP requests using Bearer tokens.
  
  Usage:
  
      plug ArmoricoreRealtimeWeb.Plugs.Authenticate
  
  This plug:
  - Extracts Bearer token from Authorization header
  - Validates the token
  - Assigns user_id to conn if valid
  - Returns 401 if invalid or missing
  """

  import Plug.Conn
  import Phoenix.Controller

  alias ArmoricoreRealtime.Auth

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_auth_token(conn) do
      nil ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Missing authorization token"})
        |> halt()

      token ->
        case Auth.validate_access_token(token) do
          {:ok, claims} ->
            user_id = Auth.get_user_id(claims)
            assign(conn, :current_user_id, user_id)

          {:error, :token_revoked} ->
            conn
            |> put_status(:unauthorized)
            |> json(%{error: "Token has been revoked"})
            |> halt()

          {:error, _reason} ->
            conn
            |> put_status(:unauthorized)
            |> json(%{error: "Invalid or expired token"})
            |> halt()
        end
    end
  end

  # Helper to extract Bearer token from Authorization header
  defp get_auth_token(conn) do
    case get_req_header(conn, "authorization") do
      [header] ->
        case String.split(header, " ", parts: 2) do
          ["Bearer", token] -> token
          _ -> nil
        end

      _ ->
        nil
    end
  end
end
