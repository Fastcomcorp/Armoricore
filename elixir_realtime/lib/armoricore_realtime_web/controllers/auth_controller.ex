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

defmodule ArmoricoreRealtimeWeb.AuthController do
  @moduledoc """
  Authentication controller for token-based authentication.
  
  Handles:
  - Login (token generation)
  - Token refresh
  - Logout (token revocation)
  """

  use ArmoricoreRealtimeWeb, :controller
  require Logger

  alias ArmoricoreRealtime.Auth
  alias ArmoricoreRealtime.Accounts
  alias ArmoricoreRealtime.Audit
  alias ArmoricoreRealtime.Analytics

  @doc """
  Register endpoint - creates a new user account.
  
  POST /api/auth/register
  Body: {
    "email": "user@example.com",
    "password": "Password123!",
    "password_confirmation": "Password123!",
    "username": "username"
  }
  
  Response: {
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {...}
  }
  """
  def register(conn, %{"email" => email, "password" => password, "password_confirmation" => password_confirmation, "username" => username}) do
    ip_address = get_client_ip(conn)
    user_agent = get_req_header(conn, "user-agent") |> List.first()

    attrs = %{
      email: email,
      password: password,
      password_confirmation: password_confirmation,
      username: username
    }

    case Accounts.register_user(attrs) do
      {:ok, user} ->
        # Generate tokens for the new user
        user_id_str = to_string(user.id)
        case Auth.generate_tokens(user_id_str) do
          {:ok, tokens} ->
            # Log successful registration
            Audit.log_auth_event(user.id, "register", true, %{
              ip_address: ip_address,
              user_agent: user_agent
            })
            Analytics.track_auth_event(user.id, "register", %{
              ip_address: ip_address
            })

            # Add user info to response
            user_data = %{
              id: user.id,
              email: user.email,
              username: user.username,
              first_name: user.first_name,
              last_name: user.last_name,
              is_verified: user.is_verified
            }

            conn
            |> put_status(:created)
            |> json(Map.merge(tokens, %{user: user_data}))

          {:error, reason} ->
            Logger.error("Token generation failed for new user #{user.id}: #{inspect(reason)}")
            
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Account created but failed to generate tokens. Please login."})
        end

      {:error, changeset} ->
        # Log failed registration attempt
        Audit.log_auth_event(nil, "register", false, %{
          email: email,
          ip_address: ip_address,
          errors: format_changeset_errors(changeset)
        })

        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Registration failed", details: format_changeset_errors(changeset)})
    end
  end

  def register(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing required fields: email, password, password_confirmation, username"})
  end

  # Helper to format changeset errors
  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  @doc """
  Login endpoint - authenticates user and generates tokens.
  
  POST /api/auth/login
  Body: {"email": "user@example.com", "password": "password123"}
  
  Response: {
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {...}
  }
  """
  def login(conn, %{"email" => email, "password" => password}) do
    ip_address = get_client_ip(conn)
    user_agent = get_req_header(conn, "user-agent") |> List.first()

    case Accounts.authenticate_user(email, password) do
      {:ok, user} ->
        # Generate tokens (convert UUID to string)
        user_id_str = to_string(user.id)
        case Auth.generate_tokens(user_id_str) do
          {:ok, tokens} ->
            # Log successful login
            Audit.log_auth_event(user.id, "login", true, %{
              ip_address: ip_address,
              user_agent: user_agent
            })
            Analytics.track_auth_event(user.id, "login", %{
              ip_address: ip_address
            })

            # Add user info to response
            user_data = %{
              id: user.id,
              email: user.email,
              username: user.username,
              first_name: user.first_name,
              last_name: user.last_name,
              is_verified: user.is_verified
            }

            conn
            |> put_status(:ok)
            |> json(Map.merge(tokens, %{user: user_data}))

          {:error, reason} ->
            # Log failed token generation (with full details for debugging)
            Logger.error("Token generation failed for user #{user.id}: #{inspect(reason)}")
            Audit.log_auth_event(user.id, "login", false, %{
              error: inspect(reason),
              ip_address: ip_address
            })

            # SECURITY: Don't expose internal error details to client
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to generate tokens"})
        end

      {:error, :invalid_credentials} ->
        # Log failed login attempt
        Audit.log_auth_event(nil, "login", false, %{
          email: email,
          ip_address: ip_address,
          user_agent: user_agent,
          error: "invalid_credentials"
        })

        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid email or password"})

      {:error, :account_inactive} ->
        Audit.log_auth_event(nil, "login", false, %{
          email: email,
          ip_address: ip_address,
          error: "account_inactive"
        })

        conn
        |> put_status(:forbidden)
        |> json(%{error: "Account is inactive"})

      {:error, reason} ->
        # Log full error details for debugging
        Logger.warning("Authentication failed: #{inspect(reason)}", 
          email: email,
          ip_address: ip_address
        )
        Audit.log_auth_event(nil, "login", false, %{
          email: email,
          ip_address: ip_address,
          error: inspect(reason)
        })

        # SECURITY: Don't expose internal error details to client
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Authentication failed"})
    end
  end

  # SECURITY: Legacy user_id login endpoint removed
  # This endpoint was a critical security vulnerability allowing authentication bypass
  # If you need service-to-service authentication, use a different mechanism:
  # - API keys with proper validation
  # - Service accounts with proper authentication
  # - Mutual TLS (mTLS) for service communication
  def login(conn, %{"user_id" => _user_id}) do
    Logger.warning("Legacy user_id login attempt blocked", 
      ip: get_client_ip(conn),
      user_agent: get_req_header(conn, "user-agent") |> List.first()
    )
    
    conn
    |> put_status(:forbidden)
    |> json(%{error: "This authentication method is not supported. Please use email and password."})
  end

  def login(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing email and password"})
  end

  @doc """
  Refresh token endpoint - generates new access token from refresh token.
  
  POST /api/auth/refresh
  Body: {"refresh_token": "..."}
  
  Response: {
    "access_token": "...",
    "token_type": "Bearer",
    "expires_in": 3600
  }
  """
  def refresh(conn, %{"refresh_token" => refresh_token}) do
    ip_address = get_client_ip(conn)

    case Auth.validate_refresh_token(refresh_token) do
      {:ok, claims} ->
        user_id = Map.get(claims, "user_id")
        old_jti = Map.get(claims, "jti")
        expires_at = DateTime.from_unix!(Map.get(claims, "exp"))

        # Revoke old refresh token (token rotation)
        ArmoricoreRealtime.Security.revoke_token(
          old_jti,
          user_id,
          "refresh",
          expires_at,
          "refresh"
        )

        # Generate new access token
        case Auth.generate_access_token(user_id) do
          {:ok, access_token} ->
            # Log token refresh
            Audit.log_token_event(user_id, "refresh", true, %{
              ip_address: ip_address
            })

            conn
            |> put_status(:ok)
            |> json(%{
              access_token: access_token,
              token_type: "Bearer",
              expires_in: 3600
            })

          {:error, reason} ->
            # Log full error details for debugging
            Logger.error("Access token generation failed during refresh: #{inspect(reason)}")
            Audit.log_token_event(user_id, "refresh", false, %{
              error: inspect(reason),
              ip_address: ip_address
            })

            # SECURITY: Don't expose internal error details to client
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to generate access token"})
        end

      {:error, :invalid_token} ->
        Audit.log_token_event(nil, "refresh", false, %{
          error: "invalid_token",
          ip_address: ip_address
        })

        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid refresh token"})

      {:error, :token_expired} ->
        Audit.log_token_event(nil, "refresh", false, %{
          error: "token_expired",
          ip_address: ip_address
        })

        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Refresh token expired"})

      {:error, :token_revoked} ->
        Audit.log_token_event(nil, "refresh", false, %{
          error: "token_revoked",
          ip_address: ip_address
        })

        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Refresh token has been revoked"})

      {:error, :invalid_token_type} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid token type"})

      {:error, reason} ->
        # Log full error details for debugging
        Logger.error("Token refresh failed: #{inspect(reason)}")
        
        # SECURITY: Don't expose internal error details to client
        conn
        |> put_status(:internal_server_error)
        |> json(%{error: "Failed to refresh token"})
    end
  end

  def refresh(conn, _params) do
    conn
    |> put_status(:bad_request)
    |> json(%{error: "Missing refresh_token"})
  end

  @doc """
  Logout endpoint - revokes tokens.
  
  POST /api/auth/logout
  Headers: Authorization: Bearer <access_token>
  
  Response: {"message": "Logged out successfully"}
  """
  def logout(conn, _params) do
    user_id = conn.assigns[:current_user_id]
    ip_address = get_client_ip(conn)

    case get_auth_token(conn) do
      nil ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Missing authorization token"})

      token ->
        case Auth.validate_access_token(token) do
          {:ok, claims} ->
            jti = Map.get(claims, "jti")
            expires_at = DateTime.from_unix!(Map.get(claims, "exp"))

            # Revoke the access token
            ArmoricoreRealtime.Security.revoke_token(
              jti,
              user_id,
              "access",
              expires_at,
              "logout"
            )

            # Log logout
            Audit.log_auth_event(user_id, "logout", true, %{
              ip_address: ip_address,
              token_jti: jti
            })
            Analytics.track_auth_event(user_id, "logout", %{
              ip_address: ip_address
            })

            conn
            |> put_status(:ok)
            |> json(%{message: "Logged out successfully"})

          {:error, _reason} ->
            conn
            |> put_status(:unauthorized)
            |> json(%{error: "Invalid token"})
        end
    end
  end

  @doc """
  Verify token endpoint - validates an access token.
  
  GET /api/auth/verify
  Headers: Authorization: Bearer <access_token>
  
  Response: {
    "valid": true,
    "user_id": "user-123",
    "expires_at": 1234567890
  }
  """
  def verify(conn, _params) do
    case get_auth_token(conn) do
      nil ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Missing authorization token"})

      token ->
        case Auth.validate_access_token(token) do
          {:ok, claims} ->
            user_id = Auth.get_user_id(claims)
            exp = Map.get(claims, "exp")

            conn
            |> put_status(:ok)
            |> json(%{
              valid: true,
              user_id: user_id,
              expires_at: exp
            })

          {:error, :invalid_token} ->
            conn
            |> put_status(:unauthorized)
            |> json(%{valid: false, error: "Invalid token"})

          {:error, :token_expired} ->
            conn
            |> put_status(:unauthorized)
            |> json(%{valid: false, error: "Token expired"})

          {:error, reason} ->
            # Log full error details for debugging
            Logger.debug("Token verification failed: #{inspect(reason)}")
            
            # SECURITY: Don't expose internal error details to client
            # Return generic error based on error type
            error_message = case reason do
              :invalid_token -> "Invalid token"
              :token_expired -> "Token expired"
              :missing_expiration -> "Invalid token format"
              _ -> "Token verification failed"
            end
            
            conn
            |> put_status(:unauthorized)
            |> json(%{valid: false, error: error_message})
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

  # Helper to get client IP address
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
end
