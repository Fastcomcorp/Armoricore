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

defmodule ArmoricoreRealtime.JWT do
  @moduledoc """
  JWT validation module for authenticating WebSocket connections.
  
  Validates JWT tokens issued by the PHP backend.
  """

  @doc """
  Validates a JWT token and returns the claims if valid.
  
  ## Examples
  
      iex> ArmoricoreRealtime.JWT.validate_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
      {:ok, %{"user_id" => "123", "exp" => 1234567890}}
      
      iex> ArmoricoreRealtime.JWT.validate_token("invalid")
      {:error, :invalid_token}
  """
  def validate_token(token) when is_binary(token) do
    # Get JWT secret from KeyManager, with fallback to environment variables
    secret = get_jwt_secret()

    # Create signer with HS256 algorithm
    signer = Joken.Signer.create("HS256", secret)

    # Verify token first
    case Joken.verify(token, signer) do
      {:ok, claims} ->
        # Then validate expiration if present
        validate_expiration(claims)
      
      {:error, reason} ->
        {:error, reason}
    end
  end

  def validate_token(_), do: {:error, :invalid_token}

  @doc """
  Extracts user_id from validated JWT claims.
  """
  def get_user_id(claims) when is_map(claims) do
    Map.get(claims, "user_id") || Map.get(claims, :user_id)
  end

  def get_user_id(_), do: nil

  # Validate expiration claim
  # SECURITY: Require expiration claim for all tokens - tokens without exp are rejected
  defp validate_expiration(%{"exp" => exp} = claims) when is_integer(exp) do
    current_time = System.system_time(:second)
    if exp > current_time do
      {:ok, claims}
    else
      {:error, :token_expired}
    end
  end

  defp validate_expiration(_claims) do
    # SECURITY: Reject tokens without expiration claim
    # All tokens must have an expiration time for security
    {:error, :missing_expiration}
  end

  # Get JWT secret from KeyManager with fallback to environment variables
  # SECURITY: Never use default secrets - fail fast if not configured
  defp get_jwt_secret do
    # Try KeyManager first
    case ArmoricoreRealtime.KeyManager.get_jwt_secret("jwt.secret") do
      {:ok, secret} when is_binary(secret) and byte_size(secret) > 32 ->
        secret

      {:ok, secret} when is_binary(secret) ->
        raise "JWT_SECRET from KeyManager is too short (minimum 32 bytes). Cannot start without secure JWT secret."

      {:error, _} ->
        # Fallback to environment variables (for migration period)
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
