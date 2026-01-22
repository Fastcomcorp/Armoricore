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

defmodule ArmoricoreRealtimeWeb.AuthControllerTest do
  use ExUnit.Case, async: true
  use ArmoricoreRealtimeWeb.ConnCase

  alias ArmoricoreRealtime.Accounts
  alias ArmoricoreRealtime.Auth
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Accounts.User

  @valid_user_attrs %{
    email: "test@example.com",
    password: "password123",
    username: "testuser",
    first_name: "Test",
    last_name: "User"
  }

  setup do
    # Clean up test data
    Repo.delete_all(User)
    
    # Register a test user
    {:ok, user} = Accounts.register_user(@valid_user_attrs)
    
    {:ok, user: user}
  end

  describe "POST /api/auth/login" do
    test "logs in with valid credentials", %{conn: conn, user: user} do
      conn = post(conn, ~p"/api/auth/login", %{
        "email" => @valid_user_attrs.email,
        "password" => @valid_user_attrs.password
      })

      assert %{
        "access_token" => _,
        "refresh_token" => _,
        "token_type" => "Bearer",
        "expires_in" => 3600,
        "user" => user_data
      } = json_response(conn, 200)

      assert user_data["email"] == user.email
      assert user_data["id"] == to_string(user.id)
    end

    test "rejects invalid password", %{conn: conn} do
      conn = post(conn, ~p"/api/auth/login", %{
        "email" => @valid_user_attrs.email,
        "password" => "wrong_password"
      })

      assert %{"error" => "Invalid email or password"} = json_response(conn, 401)
    end

    test "rejects non-existent email", %{conn: conn} do
      conn = post(conn, ~p"/api/auth/login", %{
        "email" => "nonexistent@example.com",
        "password" => "password123"
      })

      assert %{"error" => "Invalid email or password"} = json_response(conn, 401)
    end

    test "rejects inactive account", %{conn: conn, user: user} do
      Accounts.deactivate_user(user)

      conn = post(conn, ~p"/api/auth/login", %{
        "email" => @valid_user_attrs.email,
        "password" => @valid_user_attrs.password
      })

      assert %{"error" => "Account is inactive"} = json_response(conn, 403)
    end

    test "rejects missing email", %{conn: conn} do
      conn = post(conn, ~p"/api/auth/login", %{
        "password" => "password123"
      })

      assert %{"error" => "Missing email and password"} = json_response(conn, 400)
    end

    test "rejects missing password", %{conn: conn} do
      conn = post(conn, ~p"/api/auth/login", %{
        "email" => @valid_user_attrs.email
      })

      assert %{"error" => "Missing email and password"} = json_response(conn, 400)
    end

    test "legacy user_id login is blocked (security fix)", %{conn: conn, user: user} do
      # SECURITY: Legacy user_id login endpoint has been removed
      conn = post(conn, ~p"/api/auth/login", %{
        "user_id" => to_string(user.id)
      })

      # Should return 403 Forbidden
      assert %{"error" => "This authentication method is not supported. Please use email and password."} = json_response(conn, 403)
    end
  end

  describe "POST /api/auth/refresh" do
    test "refreshes access token with valid refresh token", %{user: user} do
      {:ok, tokens} = Auth.generate_tokens(to_string(user.id))
      refresh_token = tokens.refresh_token

      conn = build_conn()
      conn = post(conn, ~p"/api/auth/refresh", %{
        "refresh_token" => refresh_token
      })

      assert %{
        "access_token" => _,
        "token_type" => "Bearer",
        "expires_in" => 3600
      } = json_response(conn, 200)
    end

    test "rejects invalid refresh token", %{conn: conn} do
      conn = post(conn, ~p"/api/auth/refresh", %{
        "refresh_token" => "invalid.token.here"
      })

      assert %{"error" => "Invalid refresh token"} = json_response(conn, 401)
    end

    test "rejects expired refresh token", %{user: user} do
      # Create an expired token manually
      signer = Joken.Signer.create("HS256", Application.get_env(:armoricore_realtime, :jwt)[:secret] || "test-secret")
      claims = %{
        "user_id" => to_string(user.id),
        "type" => "refresh",
        "exp" => System.system_time(:second) - 3600  # Expired 1 hour ago
      }
      {:ok, expired_token, _} = Joken.encode_and_sign(claims, signer)

      conn = build_conn()
      conn = post(conn, ~p"/api/auth/refresh", %{
        "refresh_token" => expired_token
      })

      assert %{"error" => "Refresh token expired"} = json_response(conn, 401)
    end

    test "rejects missing refresh_token", %{conn: conn} do
      conn = post(conn, ~p"/api/auth/refresh", %{})

      assert %{"error" => "Missing refresh_token"} = json_response(conn, 400)
    end
  end

  describe "POST /api/auth/logout" do
    test "logs out with valid access token", %{user: user} do
      {:ok, tokens} = Auth.generate_tokens(to_string(user.id))
      access_token = tokens.access_token

      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{access_token}")
      conn = post(conn, ~p"/api/auth/logout", %{})

      assert %{"message" => "Logged out successfully"} = json_response(conn, 200)
    end

    test "rejects logout without token", %{conn: conn} do
      conn = post(conn, ~p"/api/auth/logout", %{})

      assert %{"error" => "Missing authorization token"} = json_response(conn, 401)
    end

    test "rejects logout with invalid token", %{conn: conn} do
      conn = put_req_header(conn, "authorization", "Bearer invalid.token")
      conn = post(conn, ~p"/api/auth/logout", %{})

      assert %{"error" => "Invalid token"} = json_response(conn, 401)
    end
  end

  describe "GET /api/auth/verify" do
    test "verifies valid access token", %{user: user} do
      {:ok, tokens} = Auth.generate_tokens(to_string(user.id))
      access_token = tokens.access_token

      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{access_token}")
      conn = get(conn, ~p"/api/auth/verify")

      assert %{
        "valid" => true,
        "user_id" => _,
        "expires_at" => _
      } = json_response(conn, 200)
    end

    test "rejects invalid token", %{conn: conn} do
      conn = put_req_header(conn, "authorization", "Bearer invalid.token")
      conn = get(conn, ~p"/api/auth/verify")

      assert %{"valid" => false, "error" => "Invalid token"} = json_response(conn, 401)
    end

    test "rejects expired token", %{user: user} do
      # Create an expired token
      signer = Joken.Signer.create("HS256", Application.get_env(:armoricore_realtime, :jwt)[:secret] || "test-secret")
      claims = %{
        "user_id" => to_string(user.id),
        "type" => "access",
        "exp" => System.system_time(:second) - 3600
      }
      {:ok, expired_token, _} = Joken.encode_and_sign(claims, signer)

      conn = build_conn()
      conn = put_req_header(conn, "authorization", "Bearer #{expired_token}")
      conn = get(conn, ~p"/api/auth/verify")

      assert %{"valid" => false, "error" => "Token expired"} = json_response(conn, 401)
    end

    test "rejects request without token", %{conn: conn} do
      conn = get(conn, ~p"/api/auth/verify")

      assert %{"error" => "Missing authorization token"} = json_response(conn, 401)
    end
  end

  describe "error paths" do
    test "handles malformed JSON", %{conn: conn} do
      conn = put_req_header(conn, "content-type", "application/json")
      conn = post(conn, ~p"/api/auth/login", "invalid json")

      assert conn.status in [400, 500]
    end

    test "handles empty request body", %{conn: conn} do
      conn = post(conn, ~p"/api/auth/login", %{})

      assert %{"error" => "Missing email and password"} = json_response(conn, 400)
    end
  end
end

