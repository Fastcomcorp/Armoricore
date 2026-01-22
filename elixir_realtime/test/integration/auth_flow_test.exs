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

defmodule ArmoricoreRealtime.Integration.AuthFlowTest do
  use ExUnit.Case, async: false
  use ArmoricoreRealtimeWeb.ConnCase

  alias ArmoricoreRealtime.Accounts
  alias ArmoricoreRealtime.Auth
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Accounts.User

  @valid_user_attrs %{
    email: "integration@example.com",
    password: "password123",
    username: "integration_user",
    first_name: "Integration",
    last_name: "Test"
  }

  setup do
    # Clean up test data
    Repo.delete_all(User)
    :ok
  end

  describe "Complete Authentication Flow" do
    test "end-to-end authentication flow: register → login → verify → refresh → logout" do
      # Step 1: Register user
      assert {:ok, %User{} = user} = Accounts.register_user(@valid_user_attrs)
      assert user.email == @valid_user_attrs.email

      # Step 2: Login
      conn = build_conn()
      conn = post(conn, ~p"/api/auth/login", %{
        "email" => @valid_user_attrs.email,
        "password" => @valid_user_attrs.password
      })

      assert %{
        "access_token" => access_token,
        "refresh_token" => refresh_token,
        "token_type" => "Bearer",
        "expires_in" => 3600,
        "user" => user_data
      } = json_response(conn, 200)

      assert user_data["email"] == @valid_user_attrs.email

      # Step 3: Verify token
      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{access_token}")
      conn = get(conn, ~p"/api/auth/verify")

      assert %{
        "valid" => true,
        "user_id" => user_id,
        "expires_at" => expires_at
      } = json_response(conn, 200)

      assert user_id == to_string(user.id)
      assert expires_at > System.system_time(:second)

      # Step 4: Refresh token
      conn = build_conn()
      conn = post(conn, ~p"/api/auth/refresh", %{
        "refresh_token" => refresh_token
      })

      assert %{
        "access_token" => new_access_token,
        "token_type" => "Bearer",
        "expires_in" => 3600
      } = json_response(conn, 200)

      assert new_access_token != access_token

      # Step 5: Use new access token
      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{new_access_token}")
      conn = get(conn, ~p"/api/auth/verify")

      assert %{"valid" => true} = json_response(conn, 200)

      # Step 6: Logout
      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{new_access_token}")
      conn = post(conn, ~p"/api/auth/logout", %{})

      assert %{"message" => "Logged out successfully"} = json_response(conn, 200)

      # Step 7: Verify token is revoked
      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{new_access_token}")
      conn = get(conn, ~p"/api/auth/verify")

      # Token should be rejected (either invalid or revoked)
      assert conn.status in [401, 403]
    end

    test "authentication flow with multiple refresh cycles" do
      # Register and login
      {:ok, _user} = Accounts.register_user(@valid_user_attrs)
      
      conn = build_conn()
      conn = post(conn, ~p"/api/auth/login", %{
        "email" => @valid_user_attrs.email,
        "password" => @valid_user_attrs.password
      })

      %{"refresh_token" => refresh_token} = json_response(conn, 200)

      # Refresh multiple times
      for i <- 1..3 do
        conn = build_conn()
        conn = post(conn, ~p"/api/auth/refresh", %{
          "refresh_token" => refresh_token
        })

        assert %{"access_token" => _} = json_response(conn, 200)
      end
    end

    test "authentication flow with token expiration" do
      {:ok, user} = Accounts.register_user(@valid_user_attrs)
      
      # Generate tokens
      {:ok, tokens} = Auth.generate_tokens(to_string(user.id))
      
      # Create expired access token manually
      secret = Application.get_env(:armoricore_realtime, :jwt)[:secret] || "test-secret"
      signer = Joken.Signer.create("HS256", secret)
      claims = %{
        "user_id" => to_string(user.id),
        "type" => "access",
        "exp" => System.system_time(:second) - 1  # Just expired
      }
      {:ok, expired_token, _} = Joken.encode_and_sign(claims, signer)

      # Try to use expired token
      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{expired_token}")
      conn = get(conn, ~p"/api/auth/verify")

      assert %{"valid" => false, "error" => "Token expired"} = json_response(conn, 401)

      # Refresh should still work
      conn = build_conn()
      conn = post(conn, ~p"/api/auth/refresh", %{
        "refresh_token" => tokens.refresh_token
      })

      assert %{"access_token" => _} = json_response(conn, 200)
    end
  end

  describe "Error Paths in Authentication Flow" do
    test "handles invalid credentials during login" do
      {:ok, _user} = Accounts.register_user(@valid_user_attrs)

      conn = build_conn()
      conn = post(conn, ~p"/api/auth/login", %{
        "email" => @valid_user_attrs.email,
        "password" => "wrong_password"
      })

      assert %{"error" => "Invalid email or password"} = json_response(conn, 401)
    end

    test "handles expired refresh token" do
      {:ok, user} = Accounts.register_user(@valid_user_attrs)
      
      # Create expired refresh token
      secret = Application.get_env(:armoricore_realtime, :jwt)[:secret] || "test-secret"
      signer = Joken.Signer.create("HS256", secret)
      claims = %{
        "user_id" => to_string(user.id),
        "type" => "refresh",
        "exp" => System.system_time(:second) - 3600
      }
      {:ok, expired_refresh_token, _} = Joken.encode_and_sign(claims, signer)

      conn = build_conn()
      conn = post(conn, ~p"/api/auth/refresh", %{
        "refresh_token" => expired_refresh_token
      })

      assert %{"error" => "Refresh token expired"} = json_response(conn, 401)
    end

    test "handles revoked token after logout" do
      {:ok, _user} = Accounts.register_user(@valid_user_attrs)
      
      conn = build_conn()
      conn = post(conn, ~p"/api/auth/login", %{
        "email" => @valid_user_attrs.email,
        "password" => @valid_user_attrs.password
      })

      %{"access_token" => access_token} = json_response(conn, 200)

      # Logout
      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{access_token}")
      conn = post(conn, ~p"/api/auth/logout", %{})
      assert json_response(conn, 200)

      # Try to use revoked token
      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{access_token}")
      conn = get(conn, ~p"/api/auth/verify")

      assert conn.status in [401, 403]
    end
  end
end

