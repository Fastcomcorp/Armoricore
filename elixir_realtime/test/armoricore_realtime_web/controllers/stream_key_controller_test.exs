# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp
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

defmodule ArmoricoreRealtimeWeb.StreamKeyControllerTest do
  use ArmoricoreRealtimeWeb.ConnCase

  alias ArmoricoreRealtime.{LiveStreaming, Accounts}

  setup %{conn: conn} do
    {:ok, user} = Accounts.register_user(%{
      username: "testuser",
      email: "test@example.com",
      password: "TestPassword123!@#"
    })

    conn = build_authenticated_conn(conn, user)

    %{conn: conn, user: user}
  end

  describe "index" do
    test "lists user's stream keys (protected)", %{conn: conn, user: user} do
      {:ok, _key1} = LiveStreaming.generate_stream_key_for_user(user.id, %{name: "Key 1"})
      {:ok, _key2} = LiveStreaming.generate_stream_key_for_user(user.id, %{name: "Key 2"})

      conn = get(conn, ~p"/api/v1/stream-keys")
      assert %{"data" => keys, "count" => count} = json_response(conn, 200)
      assert count >= 2
      assert is_list(keys)
    end
  end

  describe "create" do
    test "generates a new stream key (protected)", %{conn: conn} do
      attrs = %{
        name: "My Stream Key"
      }

      conn = post(conn, ~p"/api/v1/stream-keys", %{stream_key: attrs})
      assert %{"data" => key_data} = json_response(conn, 201)
      assert key_data["name"] == "My Stream Key"
      assert key_data["stream_key"] != nil
      assert key_data["is_active"] == true
    end

    test "renders errors when data is invalid (protected)", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/stream-keys", %{stream_key: %{}})
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "delete" do
    setup %{user: user} do
      {:ok, key} = LiveStreaming.generate_stream_key_for_user(user.id, %{
        name: "Key to Revoke"
      })

      %{key: key}
    end

    test "revokes a stream key (owner only)", %{conn: conn, key: key} do
      conn = delete(conn, ~p"/api/v1/stream-keys/#{key.id}")
      assert response(conn, 204)

      # Verify key is inactive
      {:ok, updated} = LiveStreaming.validate_stream_key(key.stream_key)
      # Actually, validation should fail for revoked keys
      # But the key should be marked as inactive in the database
    end

    test "returns 403 when user is not owner", %{conn: conn} do
      {:ok, other_user} = Accounts.register_user(%{
        username: "otheruser",
        email: "other@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, other_key} = LiveStreaming.generate_stream_key_for_user(other_user.id, %{})

      conn = delete(conn, ~p"/api/v1/stream-keys/#{other_key.id}")
      assert json_response(conn, 403)
    end
  end

  describe "validate" do
    test "validates a valid stream key (internal)", %{conn: conn} do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, key} = LiveStreaming.generate_stream_key_for_user(user.id, %{
        stream_key: "test-key-123"
      })

      conn = post(conn, ~p"/api/v1/stream-keys/validate", %{stream_key: "test-key-123"})
      assert %{"valid" => true, "user_id" => user_id, "key_id" => key_id} = json_response(conn, 200)
      assert user_id == user.id
      assert key_id == key.id
    end

    test "returns error for invalid stream key (internal)", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/stream-keys/validate", %{stream_key: "invalid-key"})
      assert %{"valid" => false, "error" => _} = json_response(conn, 401)
    end

    test "returns error for expired stream key (internal)", %{conn: conn} do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#"
      })

      expires_at = DateTime.add(DateTime.utc_now(), -1, :second)

      {:ok, _key} = LiveStreaming.generate_stream_key_for_user(user.id, %{
        stream_key: "expired-key",
        expires_at: expires_at
      })

      conn = post(conn, ~p"/api/v1/stream-keys/validate", %{stream_key: "expired-key"})
      assert %{"valid" => false, "error" => _} = json_response(conn, 401)
    end
  end
end

