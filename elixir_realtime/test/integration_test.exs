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

defmodule ArmoricoreRealtime.IntegrationTest do
  @moduledoc """
  Comprehensive integration tests for Armoricore.

  Tests end-to-end functionality including:
  - User registration and authentication
  - Video upload and processing
  - ArcRTC communication
  - Real-time features
  - Database operations under load
  """

  use ExUnit.Case, async: false
  use ArmoricoreRealtimeWeb.ChannelCase

  alias ArmoricoreRealtime.{Repo, Accounts, Content, Rooms, Messaging}
  alias ArmoricoreRealtimeWeb.{UserSocket, RoomChannel}

  setup_all do
    # Start required services for integration testing
    # Note: In production, these would be external services
    {:ok, _} = Application.ensure_all_started(:armoricore_realtime)

    # Clean up any existing test data
    cleanup_test_data()

    on_exit(&cleanup_test_data/0)
    :ok
  end

  describe "complete user journey" do
    test "user registration, video upload, and streaming" do
      # Step 1: User Registration
      user_attrs = %{
        email: "integration-test-#{System.unique_integer()}@example.com",
        password: "TestPassword123!",
        password_confirmation: "TestPassword123!",
        username: "integration_user_#{System.unique_integer()}"
      }

      assert {:ok, user} = Accounts.register_user(user_attrs)
      assert user.email == user_attrs.email
      assert user.username == user_attrs.username

      # Step 2: User Authentication
      assert {:ok, token} = Accounts.create_user_session(user, "integration-test")

      # Step 3: Video Upload Simulation
      video_attrs = %{
        title: "Integration Test Video",
        description: "Test video for integration testing",
        user_id: user.id,
        filename: "test_video.mp4",
        content_type: "video/mp4",
        size_bytes: 1024 * 1024 # 1MB
      }

      assert {:ok, video} = Content.create_video(video_attrs)
      assert video.title == video_attrs.title
      assert video.user_id == user.id

      # Step 4: Verify Video Processing (simulated)
      # In real integration, this would wait for background processing
      assert video.status == "processing"

      # Simulate processing completion
      {:ok, processed_video} = Content.update_video_status(video, "completed", %{
        duration: 300, # 5 minutes
        thumbnail_url: "/uploads/thumbnails/#{video.id}.jpg",
        hls_playlist_url: "/uploads/hls/#{video.id}/playlist.m3u8"
      })

      assert processed_video.status == "completed"
      assert processed_video.duration == 300

      # Step 5: Video Discovery
      videos = Content.list_videos(limit: 10)
      assert Enum.any?(videos, fn v -> v.id == video.id end)

      # Step 6: Video Search
      search_results = Content.search_videos("integration test")
      assert Enum.any?(search_results, fn v -> v.id == video.id end)

      # Clean up
      assert {:ok, _} = Content.delete_video(video)
      assert {:ok, _} = Accounts.delete_user(user)
    end

    test "real-time room communication" do
      # Step 1: Create Test Users
      user1 = create_test_user("room_test_1@example.com")
      user2 = create_test_user("room_test_2@example.com")

      # Step 2: Create Room
      room_attrs = %{
        name: "Integration Test Room",
        description: "Room for integration testing",
        is_private: false,
        created_by_id: user1.id
      }

      assert {:ok, room} = Rooms.create_room(room_attrs)
      assert room.name == room_attrs.name

      # Step 3: Join Room (User 1)
      assert {:ok, membership1} = Rooms.join_room(room.id, user1.id)
      assert membership1.user_id == user1.id
      assert membership1.room_id == room.id

      # Step 4: Join Room (User 2)
      assert {:ok, membership2} = Rooms.join_room(room.id, user2.id)

      # Step 5: Test WebSocket Connection (User 1)
      {:ok, socket1} = connect(UserSocket, %{"token" => create_test_token(user1)})
      {:ok, _, socket1} = subscribe_and_join(socket1, RoomChannel, "room:#{room.id}")

      # Step 6: Send Message (User 1)
      message_content = "Integration test message #{System.unique_integer()}"
      ref = push(socket1, "message", %{"content" => message_content})
      assert_reply ref, :ok, %{message_id: message_id}

      # Verify message was created
      assert {:ok, message} = Messaging.get_message(message_id)
      assert message.content == message_content
      assert message.user_id == user1.id
      assert message.room_id == room.id

      # Step 7: Test Message Broadcasting (User 2)
      # In a real scenario, User 2 would receive the message via WebSocket
      # For this test, we verify the message exists in the database
      messages = Messaging.list_room_messages(room.id, limit: 10)
      assert Enum.any?(messages, fn m -> m.id == message_id end)

      # Step 8: Test Presence Tracking
      presence = Rooms.get_room_presence(room.id)
      assert length(presence) >= 2  # At least 2 users

      # Clean up
      leave(socket1)
      assert {:ok, _} = Rooms.leave_room(room.id, user1.id)
      assert {:ok, _} = Rooms.leave_room(room.id, user2.id)
      assert {:ok, _} = Rooms.delete_room(room)
      assert {:ok, _} = Accounts.delete_user(user1)
      assert {:ok, _} = Accounts.delete_user(user2)
    end

    test "ArcRTC communication flow" do
      # This test simulates the ArcRTC bridge functionality
      # In a full integration test, this would require the Rust media engine

      user = create_test_user("arbrtc_test@example.com")
      session_id = "arbrtc-integration-#{System.unique_integer()}"

      # Step 1: Simulate WebRTC SDP Offer
      webrtc_offer = """
      v=0
      o=- 123456789 0 IN IP4 127.0.0.1
      s=-
      t=0 0
      m=audio 5000 RTP/AVP 96 0
      a=rtpmap:96 opus/48000/2
      m=video 5002 RTP/AVP 97
      a=rtpmap:97 H264/90000
      """

      # Step 2: Test ArcRTC Bridge Translation
      assert {:ok, arc_request} = ArcRtcBridge.webrtc_to_arcrtc(session_id, webrtc_offer)
      assert arc_request.type == "CONNECT"
      assert arc_request.session_id == session_id
      assert is_map(arc_request.capabilities)

      # Step 3: Verify Codec Detection
      capabilities = arc_request.capabilities
      assert "opus" in capabilities.audio_codecs
      assert "PCMU" in capabilities.audio_codecs
      assert "H264" in capabilities.video_codecs

      # Step 4: Test Reverse Translation (ArcRTC to WebRTC)
      arc_ack = %{
        "session_id" => session_id,
        "capabilities" => %{
          "audio_codecs" => ["opus"],
          "video_codecs" => ["H264"]
        }
      }

      assert {:ok, webrtc_response} = ArcRtcBridge.arcrtc_to_webrtc(arc_ack, webrtc_offer)
      assert is_binary(webrtc_response.sdp)
      assert String.contains?(webrtc_response.sdp, "v=0")
      assert webrtc_response.session_id == session_id

      # Step 5: Test Media Packet Routing (simulated)
      packet = <<1, 2, 3, 4, 5>>
      stream_id = "test-stream-#{System.unique_integer()}"

      # Test WebRTC to ArcRTC routing
      assert :ok = ArcRtcBridge.route_media_packet(packet, :webrtc, :arcrtc, stream_id)

      # Test ArcRTC to WebRTC routing
      assert :ok = ArcRtcBridge.route_media_packet(packet, :arcrtc, :webrtc, stream_id)

      # Clean up
      assert {:ok, _} = Accounts.delete_user(user)
    end
  end

  describe "load and performance testing" do
    test "concurrent user registration" do
      # Test concurrent user registration under load
      num_users = 50
      user_tasks = Enum.map(1..num_users, fn i ->
        Task.async(fn ->
          email = "load-test-#{i}-#{System.unique_integer()}@example.com"
          user_attrs = %{
            email: email,
            password: "TestPassword123!",
            password_confirmation: "TestPassword123!",
            username: "load_user_#{i}_#{System.unique_integer()}"
          }

          case Accounts.register_user(user_attrs) do
            {:ok, user} -> {:ok, user}
            {:error, changeset} -> {:error, changeset.errors}
          end
        end)
      end)

      # Wait for all registrations to complete
      results = Task.yield_many(user_tasks, 30000)

      # Count successful registrations
      successful = Enum.count(results, fn
        {task, {:ok, _}} when is_reference(task) -> true
        _ -> false
      end)

      # Allow for some failures due to database constraints, but expect high success rate
      success_rate = successful / num_users
      assert success_rate > 0.8, "Expected >80% success rate, got #{success_rate * 100}%"

      # Clean up created users
      Enum.each(results, fn
        {task, {:ok, user}} ->
          Task.shutdown(task)
          Accounts.delete_user(user)
        {task, _} ->
          Task.shutdown(task)
      end)
    end

    test "database query performance" do
      # Create test data for performance testing
      users = Enum.map(1..100, fn i ->
        create_test_user("perf-test-#{i}@example.com")
      end)

      videos = Enum.map(users, fn user ->
        create_test_video(user, "Performance Test Video #{System.unique_integer()}")
      end)

      # Test video listing performance
      {time, result} = :timer.tc(fn ->
        Content.list_videos(limit: 50)
      end)

      # Should complete in under 100ms
      assert time < 100_000, "Video listing took #{time}μs (>100ms)"

      assert length(result) > 0

      # Test search performance
      {search_time, search_result} = :timer.tc(fn ->
        Content.search_videos("performance")
      end)

      # Should complete in under 200ms
      assert search_time < 200_000, "Video search took #{search_time}μs (>200ms)"

      # Clean up
      Enum.each(videos, fn video -> Content.delete_video(video) end)
      Enum.each(users, fn user -> Accounts.delete_user(user) end)
    end
  end

  describe "error handling and edge cases" do
    test "invalid video upload handling" do
      user = create_test_user("error-test@example.com")

      # Test invalid file type
      invalid_video_attrs = %{
        title: "Invalid Video",
        user_id: user.id,
        filename: "test.exe",
        content_type: "application/x-msdownload",
        size_bytes: 1024
      }

      assert {:error, changeset} = Content.create_video(invalid_video_attrs)
      assert {:content_type, _} = changeset.errors[:content_type] || changeset.errors[:filename]

      # Test file too large
      large_video_attrs = %{
        title: "Large Video",
        user_id: user.id,
        filename: "large.mp4",
        content_type: "video/mp4",
        size_bytes: 10 * 1024 * 1024 * 1024  # 10GB
      }

      assert {:error, changeset} = Content.create_video(large_video_attrs)
      assert {:size_bytes, _} = changeset.errors[:size_bytes]

      # Clean up
      Accounts.delete_user(user)
    end

    test "room access control" do
      user1 = create_test_user("access-test-1@example.com")
      user2 = create_test_user("access-test-2@example.com")

      # Create private room
      private_room_attrs = %{
        name: "Private Test Room",
        is_private: true,
        created_by_id: user1.id
      }

      assert {:ok, room} = Rooms.create_room(private_room_attrs)

      # User 2 should not be able to join private room without invitation
      assert {:error, :unauthorized} = Rooms.join_room(room.id, user2.id)

      # User 1 should be able to join their own room
      assert {:ok, _} = Rooms.join_room(room.id, user1.id)

      # Clean up
      Rooms.delete_room(room)
      Accounts.delete_user(user1)
      Accounts.delete_user(user2)
    end

    test "ArcRTC error scenarios" do
      # Test invalid SDP
      assert {:error, :invalid_sdp} = ArcRtcBridge.webrtc_to_arcrtc("test", "")

      # Test nil ArcRTC response
      assert {:error, :invalid_arcrtc_response} = ArcRtcBridge.arcrtc_to_webrtc(nil, "sdp")

      # Test empty session compatibility
      assert {:error, :incompatible} = ArcRtcBridge.validate_session_compatibility(
        "test",
        %{},
        %{}
      )
    end
  end

  # Helper functions

  defp create_test_user(email) do
    user_attrs = %{
      email: email,
      password: "TestPassword123!",
      password_confirmation: "TestPassword123!",
      username: "test_user_#{System.unique_integer()}"
    }

    {:ok, user} = Accounts.register_user(user_attrs)
    user
  end

  defp create_test_token(user) do
    {:ok, session} = Accounts.create_user_session(user, "test")
    session.token
  end

  defp create_test_video(user, title) do
    video_attrs = %{
      title: title,
      description: "Test video description",
      user_id: user.id,
      filename: "test_#{System.unique_integer()}.mp4",
      content_type: "video/mp4",
      size_bytes: 1024 * 1024  # 1MB
    }

    {:ok, video} = Content.create_video(video_attrs)
    video
  end

  defp cleanup_test_data do
    # Clean up test data - be careful with this in production!
    # This is only for integration testing

    # Delete test videos
    Content.list_videos(limit: 1000)
    |> Enum.filter(fn v -> String.contains?(v.title || "", "test") end)
    |> Enum.each(fn v -> Content.delete_video(v) end)

    # Delete test rooms
    Rooms.list_rooms(limit: 1000)
    |> Enum.filter(fn r -> String.contains?(r.name || "", "test") end)
    |> Enum.each(fn r -> Rooms.delete_room(r) end)

    # Delete test users (be very careful with this!)
    # Only delete users created by integration tests
    Accounts.list_users(limit: 1000)
    |> Enum.filter(fn u ->
      String.contains?(u.email || "", "integration-test") or
      String.contains?(u.email || "", "room-test") or
      String.contains?(u.email || "", "arbrtc-test") or
      String.contains?(u.email || "", "error-test") or
      String.contains?(u.email || "", "access-test") or
      String.contains?(u.email || "", "load-test") or
      String.contains?(u.email || "", "perf-test")
    end)
    |> Enum.each(fn u -> Accounts.delete_user(u) end)
  end
end