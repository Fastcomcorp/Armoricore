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

defmodule ArmoricoreRealtime.LiveStreamingTest do
  use ArmoricoreRealtime.DataCase

  alias ArmoricoreRealtime.LiveStreaming
  alias ArmoricoreRealtime.Accounts
  alias ArmoricoreRealtime.Content

  describe "live streams" do
    setup do
      # Create a user
      {:ok, user} = Accounts.register_user(%{
        username: "testuser",
        email: "test@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      # Create a category
      {:ok, category} = Content.create_category(%{
        name: "Gaming",
        slug: "gaming"
      })

      %{user: user, category: category}
    end

    test "create_live_stream/1 creates a stream with valid data" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      # Use a unique slug to avoid conflicts
      {:ok, category} = Content.create_category(%{
        name: "Gaming Test",
        slug: "gaming-test-#{System.unique_integer([:positive])}"
      })

      attrs = %{
        user_id: user.id,
        title: "My First Stream",
        description: "Testing live streaming",
        category_id: category.id,
        ingest_protocol: "rtmp"
      }

      assert {:ok, stream} = LiveStreaming.create_live_stream(attrs)
      assert stream.title == "My First Stream"
      assert stream.status == "scheduled"
      assert stream.stream_key != nil
      assert stream.user_id == user.id
      assert stream.category_id == category.id
    end

    test "create_live_stream/1 generates stream key if not provided" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      attrs = %{
        user_id: user.id,
        title: "Stream Without Key"
      }

      assert {:ok, stream} = LiveStreaming.create_live_stream(attrs)
      assert stream.stream_key != nil
      assert String.starts_with?(stream.stream_key, "sk-")
    end

    test "create_live_stream/1 returns error with invalid data" do
      assert {:error, %Ecto.Changeset{}} = LiveStreaming.create_live_stream(%{})
    end

    test "get_live_stream!/1 returns stream with associations" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Test Stream"
      })

      fetched = LiveStreaming.get_live_stream!(stream.id)
      assert fetched.id == stream.id
      assert fetched.user != nil
    end

    test "get_live_stream_by_key/1 returns stream by stream key" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Test Stream",
        stream_key: "test-key-123"
      })

      assert fetched = LiveStreaming.get_live_stream_by_key("test-key-123")
      assert fetched.id == stream.id
    end

    test "list_live_streams/1 returns all streams" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, _stream1} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Stream 1"
      })

      {:ok, _stream2} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Stream 2"
      })

      streams = LiveStreaming.list_live_streams()
      assert length(streams) >= 2
    end

    test "list_live_streams/1 filters by status" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, stream1} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Scheduled Stream",
        status: "scheduled"
      })

      {:ok, stream2} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Live Stream",
        status: "live"
      })

      live_streams = LiveStreaming.list_live_streams(status: "live")
      assert length(live_streams) >= 1
      assert Enum.any?(live_streams, &(&1.id == stream2.id))
    end

    test "list_active_streams/1 returns only live streams" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, _scheduled} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Scheduled",
        status: "scheduled"
      })

      {:ok, live} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Live",
        status: "live"
      })

      active = LiveStreaming.list_active_streams()
      assert Enum.any?(active, &(&1.id == live.id))
      refute Enum.any?(active, &(&1.status == "scheduled"))
    end

    test "start_live_stream/1 updates status to live" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Test Stream",
        status: "scheduled"
      })

      assert {:ok, updated} = LiveStreaming.start_live_stream(stream.id)
      assert updated.status == "live"
      assert updated.started_at != nil
    end

    test "end_live_stream/1 updates status to ended and calculates duration" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      started_at = DateTime.add(DateTime.utc_now(), -3600, :second) # 1 hour ago

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Test Stream",
        status: "live",
        started_at: started_at
      })

      assert {:ok, updated} = LiveStreaming.end_live_stream(stream.id)
      assert updated.status == "ended"
      assert updated.ended_at != nil
      assert updated.duration_seconds >= 3600
    end

    test "update_viewer_count/2 updates current and peak viewers" do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Test Stream",
        status: "live",
        current_viewers: 10,
        peak_viewers: 15
      })

      :ok = LiveStreaming.update_viewer_count(stream.id, 20)
      updated = LiveStreaming.get_live_stream!(stream.id)
      assert updated.current_viewers == 20
      assert updated.peak_viewers == 20 # Peak should be updated
    end
  end

  describe "stream keys" do
    setup do
      {:ok, user} = Accounts.register_user(%{
        username: "testuser",
        email: "test@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      %{user: user}
    end

    test "generate_stream_key_for_user/2 creates a stream key", %{user: user} do
      {:ok, key} = LiveStreaming.generate_stream_key_for_user(user.id, %{
        name: "My Stream Key"
      })

      assert key.user_id == user.id
      assert key.stream_key != nil
      assert key.name == "My Stream Key"
      assert key.is_active == true
    end

    test "validate_stream_key/1 validates active key", %{user: user} do
      {:ok, key} = LiveStreaming.generate_stream_key_for_user(user.id, %{
        stream_key: "test-key-123"
      })

      assert {:ok, validated} = LiveStreaming.validate_stream_key("test-key-123")
      assert validated.id == key.id
      assert validated.last_used_at != nil
    end

    test "validate_stream_key/1 returns error for invalid key" do
      assert {:error, :invalid_key} = LiveStreaming.validate_stream_key("invalid-key")
    end

    test "validate_stream_key/1 returns error for expired key", %{user: user} do
      expires_at = DateTime.add(DateTime.utc_now(), -1, :second) # Expired 1 second ago

      {:ok, _key} = LiveStreaming.generate_stream_key_for_user(user.id, %{
        stream_key: "expired-key",
        expires_at: expires_at
      })

      assert {:error, :expired_key} = LiveStreaming.validate_stream_key("expired-key")
    end

    test "list_stream_keys/2 returns user's stream keys", %{user: user} do
      {:ok, _key1} = LiveStreaming.generate_stream_key_for_user(user.id, %{name: "Key 1"})
      {:ok, _key2} = LiveStreaming.generate_stream_key_for_user(user.id, %{name: "Key 2"})

      keys = LiveStreaming.list_stream_keys(user.id)
      assert length(keys) >= 2
    end

    test "revoke_stream_key/1 deactivates a key", %{user: user} do
      {:ok, key} = LiveStreaming.generate_stream_key_for_user(user.id, %{})

      assert {:ok, revoked} = LiveStreaming.revoke_stream_key(key.id)
      assert revoked.is_active == false
    end
  end

  describe "stream analytics" do
    setup do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Test Stream",
        status: "live"
      })

      %{user: user, stream: stream}
    end

    test "track_viewer_event/3 creates analytics event", %{user: user, stream: stream} do
      attrs = %{
        user_id: user.id,
        event_type: "join",
        viewer_ip: "192.168.1.1",
        quality: "720p"
      }

      assert {:ok, event} = LiveStreaming.track_viewer_event(stream.id, "join", attrs)
      assert event.stream_id == stream.id
      assert event.event_type == "join"
      assert event.user_id == user.id
    end

    test "track_viewer_join/3 increments viewer count", %{user: user, stream: stream} do
      initial_count = stream.current_viewers

      LiveStreaming.track_viewer_join(stream.id, user.id, %{})

      updated = LiveStreaming.get_live_stream!(stream.id)
      assert updated.current_viewers == initial_count + 1
    end

    test "track_viewer_leave/3 decrements viewer count", %{user: user, stream: stream} do
      # Set initial viewers
      LiveStreaming.update_viewer_count(stream.id, 5)

      LiveStreaming.track_viewer_leave(stream.id, user.id, %{})

      updated = LiveStreaming.get_live_stream!(stream.id)
      assert updated.current_viewers == 4
    end

    test "get_stream_analytics/2 returns analytics summary", %{user: user, stream: stream} do
      # Create some events
      LiveStreaming.track_viewer_event(stream.id, "join", %{user_id: user.id})
      LiveStreaming.track_viewer_event(stream.id, "join", %{user_id: user.id})
      LiveStreaming.track_viewer_event(stream.id, "leave", %{user_id: user.id})
      LiveStreaming.track_viewer_event(stream.id, "quality_change", %{quality: "1080p"})

      analytics = LiveStreaming.get_stream_analytics(stream.id)

      assert analytics.total_events >= 4
      assert analytics.join_events >= 2
      assert analytics.leave_events >= 1
      assert analytics.quality_changes >= 1
      assert analytics.unique_viewers >= 1
    end

    test "get_concurrent_viewers/1 returns viewer statistics", %{stream: stream} do
      LiveStreaming.update_viewer_count(stream.id, 25)
      LiveStreaming.update_viewer_count(stream.id, 30) # Update peak

      assert {:ok, stats} = LiveStreaming.get_concurrent_viewers(stream.id)
      assert stats.current == 30
      assert stats.peak == 30
      assert stats.total >= 0
    end
  end

  describe "stream recordings" do
    setup do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Test Stream",
        status: "live"
      })

      %{user: user, stream: stream}
    end

    test "start_recording/2 creates a recording", %{stream: stream} do
      attrs = %{
        storage_path: "recordings/stream_123"
      }

      assert {:ok, recording} = LiveStreaming.start_recording(stream.id, attrs)
      assert recording.stream_id == stream.id
      assert recording.recording_status == "recording"
      assert recording.started_at != nil
    end

    test "update_recording/2 updates recording progress", %{stream: stream} do
      {:ok, recording} = LiveStreaming.start_recording(stream.id, %{})

      attrs = %{
        segment_count: 150,
        total_size_bytes: 1_500_000_000
      }

      assert {:ok, updated} = LiveStreaming.update_recording(recording.id, attrs)
      assert updated.segment_count == 150
      assert updated.total_size_bytes == 1_500_000_000
    end

    test "complete_recording/2 marks recording as processing", %{stream: stream} do
      {:ok, recording} = LiveStreaming.start_recording(stream.id, %{})

      assert {:ok, completed} = LiveStreaming.complete_recording(recording.id)
      assert completed.recording_status == "processing"
      assert completed.ended_at != nil
    end
  end

  describe "stream quality profiles" do
    setup do
      {:ok, user} = Accounts.register_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#",
        password_confirmation: "TestPassword123!@#"
      })

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Test Stream"
      })

      %{user: user, stream: stream}
    end

    test "create_quality_profile/2 creates a quality profile", %{stream: stream} do
      attrs = %{
        quality_name: "720p",
        resolution_width: 1280,
        resolution_height: 720,
        bitrate_kbps: 2500,
        framerate: 30
      }

      assert {:ok, profile} = LiveStreaming.create_quality_profile(stream.id, attrs)
      assert profile.stream_id == stream.id
      assert profile.quality_name == "720p"
      assert profile.resolution_width == 1280
      assert profile.resolution_height == 720
      assert profile.bitrate_kbps == 2500
    end

    test "list_quality_profiles/1 returns active profiles", %{stream: stream} do
      {:ok, _profile1} = LiveStreaming.create_quality_profile(stream.id, %{
        quality_name: "360p",
        resolution_width: 640,
        resolution_height: 360,
        bitrate_kbps: 800,
        is_active: true
      })

      {:ok, _profile2} = LiveStreaming.create_quality_profile(stream.id, %{
        quality_name: "720p",
        resolution_width: 1280,
        resolution_height: 720,
        bitrate_kbps: 2500,
        is_active: true
      })

      {:ok, _inactive} = LiveStreaming.create_quality_profile(stream.id, %{
        quality_name: "1080p",
        resolution_width: 1920,
        resolution_height: 1080,
        bitrate_kbps: 5000,
        is_active: false
      })

      profiles = LiveStreaming.list_quality_profiles(stream.id)
      assert length(profiles) == 2
      assert Enum.all?(profiles, &(&1.is_active == true))
    end
  end
end

