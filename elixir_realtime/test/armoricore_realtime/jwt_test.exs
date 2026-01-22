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

defmodule ArmoricoreRealtime.JWTTest do
  use ExUnit.Case, async: true

  alias ArmoricoreRealtime.JWT

  @secret "test-secret-key-for-jwt-validation"
  @valid_user_id "123e4567-e89b-12d3-a456-426614174000"

  setup do
    # Set test secret
    Application.put_env(:armoricore_realtime, :jwt, secret: @secret)
    
    on_exit(fn ->
      Application.delete_env(:armoricore_realtime, :jwt)
    end)

    :ok
  end

  describe "validate_token/1" do
    test "validates a valid JWT token" do
      # Create a valid JWT token
      signer = Joken.Signer.create("HS256", @secret)
      
      claims = %{
        "user_id" => @valid_user_id,
        "exp" => System.system_time(:second) + 3600
      }
      
      {:ok, token, _} = Joken.encode_and_sign(claims, signer)
      
      assert {:ok, decoded_claims} = JWT.validate_token(token)
      assert JWT.get_user_id(decoded_claims) == @valid_user_id
    end

    test "rejects an invalid token" do
      assert {:error, _} = JWT.validate_token("invalid.token.here")
    end

    test "rejects an expired token" do
      signer = Joken.Signer.create("HS256", @secret)
      
      claims = %{
        "user_id" => @valid_user_id,
        "exp" => System.system_time(:second) - 3600  # Expired 1 hour ago
      }
      
      {:ok, token, _} = Joken.encode_and_sign(claims, signer)
      
      assert {:error, :token_expired} = JWT.validate_token(token)
    end

    test "rejects non-binary input" do
      assert {:error, :invalid_token} = JWT.validate_token(nil)
      assert {:error, :invalid_token} = JWT.validate_token(123)
      assert {:error, :invalid_token} = JWT.validate_token(%{})
    end

    test "rejects token without expiration (security requirement)" do
      signer = Joken.Signer.create("HS256", @secret)
      
      claims = %{
        "user_id" => @valid_user_id
        # Missing "exp" claim - should be rejected
      }
      
      {:ok, token, _} = Joken.encode_and_sign(claims, signer)
      
      # SECURITY: Tokens without expiration are now rejected
      assert {:error, :missing_expiration} = JWT.validate_token(token)
    end
  end

  describe "get_user_id/1" do
    test "extracts user_id from string key" do
      claims = %{"user_id" => @valid_user_id}
      assert JWT.get_user_id(claims) == @valid_user_id
    end

    test "extracts user_id from atom key" do
      claims = %{user_id: @valid_user_id}
      assert JWT.get_user_id(claims) == @valid_user_id
    end

    test "returns nil when user_id is missing" do
      claims = %{"other_field" => "value"}
      assert JWT.get_user_id(claims) == nil
    end

    test "returns nil for non-map input" do
      assert JWT.get_user_id(nil) == nil
      assert JWT.get_user_id("string") == nil
      assert JWT.get_user_id(123) == nil
    end
  end
end

