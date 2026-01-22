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

defmodule ArmoricoreRealtime.Integration.E2EWorkflowTest do
  use ExUnit.Case, async: false
  use Phoenix.ChannelTest

  @endpoint ArmoricoreRealtimeWeb.Endpoint

  alias ArmoricoreRealtime.Accounts
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Accounts.User
  alias ArmoricoreRealtimeWeb.UserSocket
  alias ArmoricoreRealtimeWeb.ChatChannel
  alias ArmoricoreRealtimeWeb.CommentsChannel
  alias ArmoricoreRealtimeWeb.PresenceChannel
  alias ArmoricoreRealtime.JWT

  @secret "test-secret-key"
  @valid_user_attrs %{
    email: "e2e@example.com",
    password: "password123",
    username: "e2e_user",
    first_name: "E2E",
    last_name: "Test"
  }

  setup do
    Application.put_env(:armoricore_realtime, :jwt, secret: @secret)
    
    # Clean up test data
    Repo.delete_all(User)
    
    # Register test user
    {:ok, user} = Accounts.register_user(@valid_user_attrs)
    
    # Create valid token
    signer = Joken.Signer.create("HS256", @secret)
    claims = %{
      "user_id" => to_string(user.id),
      "exp" => System.system_time(:second) + 3600
    }
    {:ok, token, _} = Joken.encode_and_sign(claims, signer)
    
    on_exit(fn ->
      Application.delete_env(:armoricore_realtime, :jwt)
      Repo.delete_all(User)
    end)

    {:ok, user: user, token: token, user_id: to_string(user.id)}
  end

  describe "End-to-End Workflow: User Registration → WebSocket Connection → Chat → Presence" do
    test "complete user journey", %{user: user, user_id: user_id} do
      # Step 1: User exists (already registered in setup)
      assert user.email == @valid_user_attrs.email

      # Step 2: Connect WebSocket
      {:ok, socket} = connect(UserSocket, %{"token" => create_token(user_id)})
      assert socket.assigns.user_id == user_id

      # Step 3: Join chat room
      {:ok, _, chat_socket} =
        socket
        |> subscribe_and_join(ChatChannel, "chat:room:test-room")

      assert chat_socket.assigns.room_id == "test-room"
      assert chat_socket.assigns.user_id == user_id

      # Step 4: Send message
      ref = push(chat_socket, "new_message", %{"content" => "Hello, world!"})
      assert_reply ref, :ok, message
      assert message.content == "Hello, world!"
      assert message.user_id == user_id

      # Step 5: Join presence room
      {:ok, _, presence_socket} =
        socket
        |> subscribe_and_join(PresenceChannel, "presence:room:test-room", %{
          "user_id" => user_id,
          "status" => "online"
        })

      assert presence_socket.assigns.room_id == "test-room"
      assert presence_socket.assigns.user_id == user_id

      # Step 6: Update presence status
      ref = push(presence_socket, "update_status", %{"status" => "away"})
      assert_reply ref, :ok, %{status: "away"}

      # Step 7: Join comments stream
      {:ok, _, comments_socket} =
        socket
        |> subscribe_and_join(CommentsChannel, "comments:stream:test-stream")

      assert comments_socket.assigns.stream_id == "test-stream"
      assert comments_socket.assigns.user_id == user_id

      # Step 8: Post comment
      ref = push(comments_socket, "new_comment", %{"content" => "Great stream!"})
      assert_reply ref, :ok, comment
      assert comment.content == "Great stream!"
      assert comment.user_id == user_id
    end

    test "multi-user chat workflow", %{user_id: user_id1} do
      # Create second user
      {:ok, user2} = Accounts.register_user(%{
        email: "user2@example.com",
        password: "password123",
        username: "user2",
        first_name: "User",
        last_name: "Two"
      })
      user_id2 = to_string(user2.id)

      # User 1 connects
      {:ok, socket1} = connect(UserSocket, %{"token" => create_token(user_id1)})
      {:ok, _, chat_socket1} =
        socket1
        |> subscribe_and_join(ChatChannel, "chat:room:multi-room")

      # User 2 connects
      {:ok, socket2} = connect(UserSocket, %{"token" => create_token(user_id2)})
      {:ok, _, chat_socket2} =
        socket2
        |> subscribe_and_join(ChatChannel, "chat:room:multi-room")

      # User 1 sends message
      push(chat_socket1, "new_message", %{"content" => "Hello from user 1"})

      # User 2 should receive the broadcast
      assert_broadcast "new_message", message
      assert message.content == "Hello from user 1"
      assert message.user_id == user_id1

      # User 2 sends message
      push(chat_socket2, "new_message", %{"content" => "Hello from user 2"})

      # User 1 should receive the broadcast
      assert_broadcast "new_message", message2
      assert message2.content == "Hello from user 2"
      assert message2.user_id == user_id2
    end

    test "presence tracking workflow", %{user_id: user_id1} do
      # Create second user
      {:ok, user2} = Accounts.register_user(%{
        email: "user2@example.com",
        password: "password123",
        username: "user2",
        first_name: "User",
        last_name: "Two"
      })
      user_id2 = to_string(user2.id)

      # User 1 joins presence
      {:ok, socket1} = connect(UserSocket, %{"token" => create_token(user_id1)})
      {:ok, _, presence_socket1} =
        socket1
        |> subscribe_and_join(PresenceChannel, "presence:room:presence-room", %{
          "user_id" => user_id1,
          "status" => "online"
        })

      # User 2 joins presence
      {:ok, socket2} = connect(UserSocket, %{"token" => create_token(user_id2)})
      {:ok, _, presence_socket2} =
        socket2
        |> subscribe_and_join(PresenceChannel, "presence:room:presence-room", %{
          "user_id" => user_id2,
          "status" => "online"
        })

      # User 1 updates status
      push(presence_socket1, "update_status", %{"status" => "away"})

      # User 2 should receive presence diff
      assert_broadcast "presence_diff", presences
      assert is_map(presences)
    end
  end

  describe "Error Paths in E2E Workflows" do
    test "handles invalid token during WebSocket connection", %{} do
      assert {:error, %{reason: _}} = connect(UserSocket, %{"token" => "invalid.token"})
    end

    test "handles expired token during WebSocket connection", %{} do
      # Create expired token
      signer = Joken.Signer.create("HS256", @secret)
      claims = %{
        "user_id" => "test-user",
        "exp" => System.system_time(:second) - 3600
      }
      {:ok, expired_token, _} = Joken.encode_and_sign(claims, signer)

      assert {:error, %{reason: :token_expired}} = connect(UserSocket, %{"token" => expired_token})
    end

    test "handles unauthorized channel join", %{user_id: user_id} do
      {:ok, socket} = connect(UserSocket, %{"token" => create_token(user_id)})
      
      # Try to join signaling channel with wrong user
      unauthorized_id = "999e4567-e89b-12d3-a456-426614174999"
      assert {:error, %{reason: "unauthorized"}} =
        socket
        |> subscribe_and_join(PresenceChannel, "presence:room:test", %{
          "user_id" => unauthorized_id
        })
    end

    test "handles rate limiting in comments", %{user_id: user_id} do
      {:ok, socket} = connect(UserSocket, %{"token" => create_token(user_id)})
      {:ok, _, comments_socket} =
        socket
        |> subscribe_and_join(CommentsChannel, "comments:stream:test")

      # First comment succeeds
      ref1 = push(comments_socket, "new_comment", %{"content" => "First"})
      assert_reply ref1, :ok, _

      # Second comment immediately should be rate limited
      ref2 = push(comments_socket, "new_comment", %{"content" => "Second"})
      assert_reply ref2, :error, %{reason: "rate_limit"}
    end
  end

  # Helper function to create token
  defp create_token(user_id) do
    signer = Joken.Signer.create("HS256", @secret)
    claims = %{
      "user_id" => user_id,
      "exp" => System.system_time(:second) + 3600
    }
    {:ok, token, _} = Joken.encode_and_sign(claims, signer)
    token
  end
end

