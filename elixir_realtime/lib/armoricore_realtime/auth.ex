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

defmodule ArmoricoreRealtime.Auth do
  @moduledoc """
  Authentication module for token-based authentication.
  
  Handles:
  - Token generation (access and refresh tokens)
  - Token validation
  - Token refresh
  - Token revocation
  """

  require Logger

  # Token expiration times (in seconds)
  @access_token_ttl 3600  # 1 hour
  @refresh_token_ttl 604800  # 7 days

  @doc """
  Generates an access token for a user.
  
  ## Examples
  
      iex> ArmoricoreRealtime.Auth.generate_access_token("user-123")
      {:ok, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
  """
  @spec generate_access_token(String.t() | binary()) :: {:ok, String.t()} | {:error, term()}
  def generate_access_token(user_id) do
    # Convert UUID binary to string if needed
    user_id_str = if is_binary(user_id) and byte_size(user_id) == 16 do
      UUID.binary_to_string!(user_id)
    else
      to_string(user_id)
    end

    now = System.system_time(:second)
    exp = now + @access_token_ttl
    jti = UUID.uuid4()  # JWT ID for revocation

    claims = %{
      "user_id" => user_id_str,
      "type" => "access",
      "jti" => jti,
      "iat" => now,
      "exp" => exp
    }

    # SECURITY: Audit log token generation
    case sign_token(claims) do
      {:ok, token} ->
        # Log successful token generation
        ArmoricoreRealtime.Audit.log_token_event(user_id_str, "access_token_generated", true, %{
          jti: jti,
          expires_at: exp,
          token_type: "access"
        })
        {:ok, token}
      
      {:error, reason} ->
        # Log failed token generation
        ArmoricoreRealtime.Audit.log_token_event(user_id_str, "access_token_generation_failed", false, %{
          error: inspect(reason)
        })
        {:error, reason}
    end
  end

  @doc """
  Generates a refresh token for a user.
  
  ## Examples
  
      iex> ArmoricoreRealtime.Auth.generate_refresh_token("user-123")
      {:ok, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
  """
  @spec generate_refresh_token(String.t() | binary()) :: {:ok, String.t()} | {:error, term()}
  def generate_refresh_token(user_id) do
    # Convert UUID binary to string if needed
    user_id_str = if is_binary(user_id) and byte_size(user_id) == 16 do
      UUID.binary_to_string!(user_id)
    else
      to_string(user_id)
    end

    now = System.system_time(:second)
    exp = now + @refresh_token_ttl
    jti = UUID.uuid4()  # JWT ID for revocation

    claims = %{
      "user_id" => user_id_str,
      "type" => "refresh",
      "jti" => jti,
      "iat" => now,
      "exp" => exp
    }

    # SECURITY: Audit log token generation
    case sign_token(claims) do
      {:ok, token} ->
        # Log successful token generation
        ArmoricoreRealtime.Audit.log_token_event(user_id_str, "refresh_token_generated", true, %{
          jti: jti,
          expires_at: exp,
          token_type: "refresh"
        })
        {:ok, token}
      
      {:error, reason} ->
        # Log failed token generation
        ArmoricoreRealtime.Audit.log_token_event(user_id_str, "refresh_token_generation_failed", false, %{
          error: inspect(reason)
        })
        {:error, reason}
    end
  end

  @doc """
  Generates both access and refresh tokens for a user.
  
  ## Examples
  
      iex> ArmoricoreRealtime.Auth.generate_tokens("user-123")
      {:ok, %{access_token: "...", refresh_token: "...", expires_in: 3600}}
  """
  @spec generate_tokens(String.t()) :: {:ok, map()} | {:error, term()}
  def generate_tokens(user_id) when is_binary(user_id) do
    with {:ok, access_token} <- generate_access_token(user_id),
         {:ok, refresh_token} <- generate_refresh_token(user_id) do
      {:ok, %{
        access_token: access_token,
        refresh_token: refresh_token,
        token_type: "Bearer",
        expires_in: @access_token_ttl
      }}
    end
  end

  @doc """
  Validates an access token.
  
  ## Examples
  
      iex> ArmoricoreRealtime.Auth.validate_access_token(token)
      {:ok, %{"user_id" => "user-123"}}
      
      iex> ArmoricoreRealtime.Auth.validate_access_token("invalid")
      {:error, :invalid_token}
  """
  @spec validate_access_token(String.t()) :: {:ok, map()} | {:error, atom()}
  def validate_access_token(token) when is_binary(token) do
    case ArmoricoreRealtime.JWT.validate_token(token) do
      {:ok, claims} ->
        # Verify it's an access token
        if Map.get(claims, "type") == "access" do
          # Check if token is revoked
          jti = Map.get(claims, "jti")
          if jti && ArmoricoreRealtime.Security.is_token_revoked?(jti) do
            {:error, :token_revoked}
          else
            {:ok, claims}
          end
        else
          {:error, :invalid_token_type}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Validates a refresh token.
  
  ## Examples
  
      iex> ArmoricoreRealtime.Auth.validate_refresh_token(token)
      {:ok, %{"user_id" => "user-123"}}
  """
  @spec validate_refresh_token(String.t()) :: {:ok, map()} | {:error, atom()}
  def validate_refresh_token(token) when is_binary(token) do
    case ArmoricoreRealtime.JWT.validate_token(token) do
      {:ok, claims} ->
        # Verify it's a refresh token
        if Map.get(claims, "type") == "refresh" do
          # Check if token is revoked
          jti = Map.get(claims, "jti")
          if jti && ArmoricoreRealtime.Security.is_token_revoked?(jti) do
            {:error, :token_revoked}
          else
            {:ok, claims}
          end
        else
          {:error, :invalid_token_type}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Refreshes an access token using a refresh token.
  
  ## Examples
  
      iex> ArmoricoreRealtime.Auth.refresh_access_token(refresh_token)
      {:ok, %{access_token: "...", expires_in: 3600}}
  """
  @spec refresh_access_token(String.t()) :: {:ok, map()} | {:error, atom()}
  def refresh_access_token(refresh_token) when is_binary(refresh_token) do
    case validate_refresh_token(refresh_token) do
      {:ok, claims} ->
        user_id = Map.get(claims, "user_id")
        old_jti = Map.get(claims, "jti")
        expires_at = Map.get(claims, "exp")
        
        # SECURITY: Token rotation - revoke old refresh token and issue new ones
        # This prevents token reuse if a refresh token is compromised
        if old_jti do
          # Revoke the old refresh token
          ArmoricoreRealtime.Security.revoke_token(old_jti, user_id, "refresh", expires_at, "refresh")
        end
        
        # Generate new access AND refresh tokens (token rotation)
        with {:ok, access_token} <- generate_access_token(user_id),
             {:ok, new_refresh_token} <- generate_refresh_token(user_id) do
          {:ok, %{
            access_token: access_token,
            refresh_token: new_refresh_token,  # New refresh token issued
            token_type: "Bearer",
            expires_in: @access_token_ttl
          }}
        else
          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Extracts user ID from validated token claims.
  """
  @spec get_user_id(map()) :: String.t() | nil
  def get_user_id(claims) when is_map(claims) do
    Map.get(claims, "user_id")
  end

  def get_user_id(_), do: nil

  # Private: Sign a token with JWT
  defp sign_token(claims) do
    secret = get_jwt_secret()
    signer = Joken.Signer.create("HS256", secret)

    case Joken.encode_and_sign(claims, signer) do
      {:ok, token, _} -> {:ok, token}
      {:error, reason} -> {:error, reason}
    end
  end

  # Get JWT secret from KeyManager with fallback
  # SECURITY: Never use default secrets - fail fast if not configured
  defp get_jwt_secret do
    case ArmoricoreRealtime.KeyManager.get_jwt_secret("jwt.secret") do
      {:ok, secret} when is_binary(secret) and byte_size(secret) > 32 ->
        secret

      {:ok, secret} when is_binary(secret) ->
        raise "JWT_SECRET from KeyManager is too short (minimum 32 bytes). Cannot start without secure JWT secret."

      {:error, _} ->
        # Fallback to environment variables
        secret = Application.get_env(:armoricore_realtime, :jwt)[:secret] ||
                 Application.get_env(:armoricore_realtime, :jwt_secret)

        cond do
          is_nil(secret) ->
            raise """
            JWT_SECRET must be configured. Cannot start without secure JWT secret.
            
            Set one of:
            - JWT_SECRET environment variable
            - armoricore_realtime.jwt.secret in config
            - Store in KeyManager as 'jwt.secret'
            
            Generate a secure secret with: mix phx.gen.secret
            """

          secret == "default-secret-change-in-production" ->
            raise """
            JWT_SECRET cannot be the default value. This is a security risk.
            Please set a secure JWT secret via environment variable or KeyManager.
            Generate a secure secret with: mix phx.gen.secret
            """

          is_binary(secret) and byte_size(secret) < 32 ->
            raise "JWT_SECRET is too short (minimum 32 bytes). Please use a longer, secure secret."

          true ->
            secret
        end
    end
  end
end
