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

defmodule ArmoricoreRealtimeWeb.CommentsChannelTest do
  use ExUnit.Case, async: true
  use Phoenix.ChannelTest

  @endpoint ArmoricoreRealtimeWeb.Endpoint

  alias ArmoricoreRealtimeWeb.UserSocket
  alias ArmoricoreRealtimeWeb.CommentsChannel
  alias ArmoricoreRealtime.JWT

  @secret "test-secret-key"
  @valid_user_id "123e4567-e89b-12d3-a456-426614174000"
  @stream_id "stream-123"

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
      |> subscribe_and_join(CommentsChannel, "comments:stream:#{@stream_id}")

    on_exit(fn ->
      Application.delete_env(:armoricore_realtime, :jwt)
    end)

    {:ok, socket: socket, user_id: @valid_user_id, stream_id: @stream_id}
  end

  describe "join/3" do
    test "allows user to join comments stream", %{socket: socket} do
      assert socket.assigns.stream_id == @stream_id
      assert socket.assigns.user_id == @valid_user_id
    end
  end

  describe "handle_in new_comment" do
    test "broadcasts new comment successfully", %{socket: socket, user_id: user_id, stream_id: stream_id} do
      content = "Great stream!"
      
      ref = push(socket, "new_comment", %{"content" => content})
      
      assert_reply ref, :ok, comment
      assert comment.content == content
      assert comment.user_id == user_id
      assert comment.stream_id == stream_id
      assert Map.has_key?(comment, :id)
      assert Map.has_key?(comment, :timestamp)

      assert_broadcast "new_comment", ^comment
    end

    test "includes custom timestamp if provided", %{socket: socket} do
      custom_timestamp = System.system_time(:second) - 100
      content = "Comment with timestamp"
      
      ref = push(socket, "new_comment", %{
        "content" => content,
        "timestamp" => custom_timestamp
      })
      
      assert_reply ref, :ok, comment
      assert comment.timestamp == custom_timestamp
    end

    test "rate limiting prevents spam", %{socket: socket} do
      content = "First comment"
      
      # First comment should succeed
      ref1 = push(socket, "new_comment", %{"content" => content})
      assert_reply ref1, :ok, _

      # Second comment immediately should be rate limited
      ref2 = push(socket, "new_comment", %{"content" => "Second comment"})
      assert_reply ref2, :error, %{reason: "rate_limit"}
    end

    test "allows comment after rate limit window", %{socket: socket} do
      content1 = "First comment"
      
      ref1 = push(socket, "new_comment", %{"content" => content1})
      assert_reply ref1, :ok, _

      # Wait for rate limit window (1 second)
      Process.sleep(1100)

      # Should now allow another comment
      content2 = "Second comment"
      ref2 = push(socket, "new_comment", %{"content" => content2})
      assert_reply ref2, :ok, comment2
      assert comment2.content == content2
    end
  end

  describe "handle_in ping" do
    test "responds to ping", %{socket: socket} do
      ref = push(socket, "ping", %{})
      assert_reply ref, :ok, %{ping: "pong"}
    end
  end

  describe "error handling" do
    test "handles missing content in new_comment", %{socket: socket} do
      ref = push(socket, "new_comment", %{})
      assert_reply ref, :error, %{reason: _}
    end

    test "handles empty content in new_comment", %{socket: socket} do
      ref = push(socket, "new_comment", %{"content" => ""})
      # Empty content might be allowed or rejected depending on validation
      # This test verifies the system handles it gracefully
      # We just check that it doesn't crash - either :ok or :error is acceptable
      try do
        assert_reply ref, :ok, _
      rescue
        ExUnit.AssertionError ->
          assert_reply ref, :error, _
      end
    end
  end
end

