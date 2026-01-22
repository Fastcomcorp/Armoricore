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

defmodule ArmoricoreRealtime.AuthTest do
  use ExUnit.Case, async: true

  alias ArmoricoreRealtime.Auth
  alias ArmoricoreRealtime.Security

  @test_user_id "123e4567-e89b-12d3-a456-426614174000"

  setup do
    # Ensure KeyManager is available
    Application.ensure_all_started(:armoricore_realtime)
    :ok
  end

  describe "generate_tokens/1" do
    test "generates access and refresh tokens" do
      assert {:ok, tokens} = Auth.generate_tokens(@test_user_id)
      assert Map.has_key?(tokens, :access_token)
      assert Map.has_key?(tokens, :refresh_token)
      assert tokens.token_type == "Bearer"
      assert tokens.expires_in == 3600
    end

    test "generates different tokens for same user" do
      {:ok, tokens1} = Auth.generate_tokens(@test_user_id)
      {:ok, tokens2} = Auth.generate_tokens(@test_user_id)
      
      assert tokens1.access_token != tokens2.access_token
      assert tokens1.refresh_token != tokens2.refresh_token
    end
  end

  describe "generate_access_token/1" do
    test "generates valid access token" do
      assert {:ok, token} = Auth.generate_access_token(@test_user_id)
      assert is_binary(token)
      assert String.length(token) > 0
    end

    test "token contains user_id" do
      {:ok, token} = Auth.generate_access_token(@test_user_id)
      assert {:ok, claims} = Auth.validate_access_token(token)
      assert Auth.get_user_id(claims) == @test_user_id
    end

    test "token has correct type" do
      {:ok, token} = Auth.generate_access_token(@test_user_id)
      assert {:ok, claims} = Auth.validate_access_token(token)
      assert Map.get(claims, "type") == "access"
    end
  end

  describe "generate_refresh_token/1" do
    test "generates valid refresh token" do
      assert {:ok, token} = Auth.generate_refresh_token(@test_user_id)
      assert is_binary(token)
      assert String.length(token) > 0
    end

    test "token contains user_id" do
      {:ok, token} = Auth.generate_refresh_token(@test_user_id)
      assert {:ok, claims} = Auth.validate_refresh_token(token)
      assert Auth.get_user_id(claims) == @test_user_id
    end

    test "token has correct type" do
      {:ok, token} = Auth.generate_refresh_token(@test_user_id)
      assert {:ok, claims} = Auth.validate_refresh_token(token)
      assert Map.get(claims, "type") == "refresh"
    end
  end

  describe "validate_access_token/1" do
    test "validates valid access token" do
      {:ok, token} = Auth.generate_access_token(@test_user_id)
      assert {:ok, claims} = Auth.validate_access_token(token)
      assert Map.get(claims, "user_id") == @test_user_id
    end

    test "rejects invalid token" do
      assert {:error, :invalid_token} = Auth.validate_access_token("invalid.token.here")
    end

    test "rejects expired token" do
      # Create expired token manually
      secret = Application.get_env(:armoricore_realtime, :jwt)[:secret] || "test-secret"
      signer = Joken.Signer.create("HS256", secret)
      claims = %{
        "user_id" => @test_user_id,
        "type" => "access",
        "exp" => System.system_time(:second) - 3600
      }
      {:ok, expired_token, _} = Joken.encode_and_sign(claims, signer)

      assert {:error, :token_expired} = Auth.validate_access_token(expired_token)
    end

    test "rejects revoked token" do
      {:ok, token} = Auth.generate_access_token(@test_user_id)
      {:ok, claims} = Auth.validate_access_token(token)
      jti = Map.get(claims, "jti")
      expires_at = DateTime.from_unix!(Map.get(claims, "exp"))

      # Revoke the token
      Security.revoke_token(jti, @test_user_id, "access", expires_at, "test")

      # Token should now be rejected
      assert {:error, :token_revoked} = Auth.validate_access_token(token)
    end

    test "rejects refresh token when expecting access token" do
      {:ok, refresh_token} = Auth.generate_refresh_token(@test_user_id)
      assert {:error, :invalid_token_type} = Auth.validate_access_token(refresh_token)
    end
  end

  describe "validate_refresh_token/1" do
    test "validates valid refresh token" do
      {:ok, token} = Auth.generate_refresh_token(@test_user_id)
      assert {:ok, claims} = Auth.validate_refresh_token(token)
      assert Map.get(claims, "user_id") == @test_user_id
    end

    test "rejects invalid token" do
      assert {:error, :invalid_token} = Auth.validate_refresh_token("invalid.token.here")
    end

    test "rejects expired token" do
      secret = Application.get_env(:armoricore_realtime, :jwt)[:secret] || "test-secret"
      signer = Joken.Signer.create("HS256", secret)
      claims = %{
        "user_id" => @test_user_id,
        "type" => "refresh",
        "exp" => System.system_time(:second) - 3600
      }
      {:ok, expired_token, _} = Joken.encode_and_sign(claims, signer)

      assert {:error, :token_expired} = Auth.validate_refresh_token(expired_token)
    end

    test "rejects revoked token" do
      {:ok, token} = Auth.generate_refresh_token(@test_user_id)
      {:ok, claims} = Auth.validate_refresh_token(token)
      jti = Map.get(claims, "jti")
      expires_at = DateTime.from_unix!(Map.get(claims, "exp"))

      Security.revoke_token(jti, @test_user_id, "refresh", expires_at, "test")

      assert {:error, :token_revoked} = Auth.validate_refresh_token(token)
    end

    test "rejects access token when expecting refresh token" do
      {:ok, access_token} = Auth.generate_access_token(@test_user_id)
      assert {:error, :invalid_token_type} = Auth.validate_refresh_token(access_token)
    end
  end

  describe "refresh_access_token/2" do
    test "generates new access token from refresh token" do
      {:ok, refresh_token} = Auth.generate_refresh_token(@test_user_id)
      assert {:ok, new_access_token} = Auth.refresh_access_token(refresh_token, @test_user_id)
      assert is_binary(new_access_token)
    end

    test "new access token is valid" do
      {:ok, refresh_token} = Auth.generate_refresh_token(@test_user_id)
      {:ok, new_access_token} = Auth.refresh_access_token(refresh_token, @test_user_id)
      assert {:ok, claims} = Auth.validate_access_token(new_access_token)
      assert Auth.get_user_id(claims) == @test_user_id
    end

    test "rejects invalid refresh token" do
      assert {:error, :invalid_token} = Auth.refresh_access_token("invalid.token", @test_user_id)
    end
  end

  describe "get_user_id/1" do
    test "extracts user_id from claims" do
      {:ok, token} = Auth.generate_access_token(@test_user_id)
      {:ok, claims} = Auth.validate_access_token(token)
      assert Auth.get_user_id(claims) == @test_user_id
    end
  end

  describe "error paths" do
    test "handles nil user_id" do
      assert {:error, _} = Auth.generate_access_token(nil)
    end

    test "handles empty user_id" do
      assert {:error, _} = Auth.generate_access_token("")
    end

    test "handles non-binary token" do
      assert {:error, :invalid_token} = Auth.validate_access_token(nil)
      assert {:error, :invalid_token} = Auth.validate_access_token(123)
      assert {:error, :invalid_token} = Auth.validate_access_token(%{})
    end
  end
end

