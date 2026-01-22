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

defmodule ArmoricoreRealtimeWeb.ChatChannelTest do
  use ExUnit.Case, async: true
  use Phoenix.ChannelTest

  @endpoint ArmoricoreRealtimeWeb.Endpoint

  alias ArmoricoreRealtimeWeb.UserSocket
  alias ArmoricoreRealtimeWeb.ChatChannel
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
    
    {:ok, _, socket} =
      socket(UserSocket, "user_socket:#{@valid_user_id}", %{user_id: @valid_user_id})
      |> subscribe_and_join(ChatChannel, "chat:room:#{@room_id}")

    on_exit(fn ->
      Application.delete_env(:armoricore_realtime, :jwt)
    end)

    {:ok, socket: socket, user_id: @valid_user_id, room_id: @room_id}
  end

  describe "join/3" do
    test "allows user to join chat room", %{socket: socket} do
      assert socket.assigns.room_id == @room_id
      assert socket.assigns.user_id == @valid_user_id
    end
  end

  describe "handle_in/3" do
    test "broadcasts new message to all subscribers", %{socket: socket, user_id: user_id, room_id: room_id} do
      content = "Hello, world!"
      
      ref = push(socket, "new_message", %{"content" => content})
      assert_reply ref, :ok, %{id: message_id, content: ^content, user_id: ^user_id, room_id: ^room_id}
      
      assert_broadcast "new_message", %{
        id: ^message_id,
        content: ^content,
        user_id: ^user_id,
        room_id: ^room_id
      }
    end

    test "handles ping message", %{socket: socket} do
      ref = push(socket, "ping", %{})
      assert_reply ref, :ok, %{ping: "pong"}
    end

    test "broadcasts shout message", %{socket: socket} do
      payload = %{"message" => "shout test"}
      
      push(socket, "shout", payload)
      assert_broadcast "shout", ^payload
    end

    test "message includes timestamp", %{socket: socket} do
      content = "Test message"
      ref = push(socket, "new_message", %{"content" => content})
      
      assert_reply ref, :ok, message
      assert Map.has_key?(message, :timestamp)
      assert is_binary(message.timestamp)
    end
  end
end

