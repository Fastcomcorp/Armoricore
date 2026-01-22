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

defmodule ArmoricoreRealtimeWeb.PresenceChannelTest do
  use ExUnit.Case, async: true
  use Phoenix.ChannelTest

  @endpoint ArmoricoreRealtimeWeb.Endpoint

  alias ArmoricoreRealtimeWeb.UserSocket
  alias ArmoricoreRealtimeWeb.PresenceChannel
  alias ArmoricoreRealtime.JWT

  @secret "test-secret-key"
  @valid_user_id "123e4567-e89b-12d3-a456-426614174000"
  @room_id "test-room"

  setup do
    Application.put_env(:armoricore_realtime, :jwt, secret: @secret)
    
    # Create valid token
    signer = Joken.Signer.create("HS256", @secret)
    claims = %{
      "user_id" => @valid_user_id,
      "exp" => System.system_time(:second) + 3600
    }
    {:ok, token, _} = Joken.encode_and_sign(claims, signer)
    
    on_exit(fn ->
      Application.delete_env(:armoricore_realtime, :jwt)
    end)

    {:ok, user_id: @valid_user_id, room_id: @room_id}
  end

  describe "join/3" do
    test "allows user to join presence room", %{user_id: user_id, room_id: room_id} do
      {:ok, _, socket} =
        socket(UserSocket, "user_socket:#{user_id}", %{user_id: user_id})
        |> subscribe_and_join(PresenceChannel, "presence:room:#{room_id}", %{
          "user_id" => user_id,
          "status" => "online"
        })

      assert socket.assigns.room_id == room_id
      assert socket.assigns.user_id == user_id
    end

    test "uses socket user_id if not provided in payload", %{user_id: user_id, room_id: room_id} do
      {:ok, _, socket} =
        socket(UserSocket, "user_socket:#{user_id}", %{user_id: user_id})
        |> subscribe_and_join(PresenceChannel, "presence:room:#{room_id}", %{})

      assert socket.assigns.user_id == user_id
    end

    test "rejects user with mismatched user_id", %{user_id: user_id, room_id: room_id} do
      different_user_id = "999e4567-e89b-12d3-a456-426614174999"
      
      assert {:error, %{reason: "unauthorized"}} =
        socket(UserSocket, "user_socket:#{user_id}", %{user_id: user_id})
        |> subscribe_and_join(PresenceChannel, "presence:room:#{room_id}", %{
          "user_id" => different_user_id
        })
    end

    test "sends initial presence state", %{user_id: user_id, room_id: room_id} do
      {:ok, _, socket} =
        socket(UserSocket, "user_socket:#{user_id}", %{user_id: user_id})
        |> subscribe_and_join(PresenceChannel, "presence:room:#{room_id}", %{
          "user_id" => user_id
        })

      assert_push "presence_state", presences
      assert is_map(presences)
    end
  end

  describe "handle_in update_status" do
    test "updates user status successfully", %{user_id: user_id, room_id: room_id} do
      {:ok, _, socket} =
        socket(UserSocket, "user_socket:#{user_id}", %{user_id: user_id})
        |> subscribe_and_join(PresenceChannel, "presence:room:#{room_id}", %{
          "user_id" => user_id
        })

      ref = push(socket, "update_status", %{"status" => "away"})

      assert_reply ref, :ok, %{status: "away"}

      assert_broadcast "presence_diff", presences
      assert is_map(presences)
    end

    test "broadcasts presence diff on status update", %{user_id: user_id, room_id: room_id} do
      {:ok, _, socket} =
        socket(UserSocket, "user_socket:#{user_id}", %{user_id: user_id})
        |> subscribe_and_join(PresenceChannel, "presence:room:#{room_id}", %{
          "user_id" => user_id
        })

      push(socket, "update_status", %{"status" => "busy"})

      assert_broadcast "presence_diff", presences
      assert is_map(presences)
    end
  end

  describe "handle_in ping" do
    test "responds to ping", %{user_id: user_id, room_id: room_id} do
      {:ok, _, socket} =
        socket(UserSocket, "user_socket:#{user_id}", %{user_id: user_id})
        |> subscribe_and_join(PresenceChannel, "presence:room:#{room_id}", %{
          "user_id" => user_id
        })

      ref = push(socket, "ping", %{})
      assert_reply ref, :ok, %{ping: "pong"}
    end
  end

  describe "error handling" do
    test "handles missing status in update_status", %{user_id: user_id, room_id: room_id} do
      {:ok, _, socket} =
        socket(UserSocket, "user_socket:#{user_id}", %{user_id: user_id})
        |> subscribe_and_join(PresenceChannel, "presence:room:#{room_id}", %{
          "user_id" => user_id
        })

      ref = push(socket, "update_status", %{})

      assert_reply ref, :error, %{reason: _}
    end
  end
end

