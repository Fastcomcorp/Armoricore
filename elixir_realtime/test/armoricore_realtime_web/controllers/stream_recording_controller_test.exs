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

defmodule ArmoricoreRealtimeWeb.StreamRecordingControllerTest do
  use ArmoricoreRealtimeWeb.ConnCase

  alias ArmoricoreRealtime.{LiveStreaming, Accounts}

  setup %{conn: conn} do
    {:ok, user} = Accounts.register_user(%{
      username: "streamer",
      email: "streamer@example.com",
      password: "TestPassword123!@#"
    })

    {:ok, stream} = LiveStreaming.create_live_stream(%{
      user_id: user.id,
      title: "Test Stream",
      status: "live"
    })

    conn = build_authenticated_conn(conn, user)

    %{conn: conn, user: user, stream: stream}
  end

  describe "index" do
    test "lists recordings for stream (owner only)", %{conn: conn, stream: stream} do
      {:ok, _recording1} = LiveStreaming.start_recording(stream.id, %{
        storage_path: "recordings/stream_1"
      })

      {:ok, _recording2} = LiveStreaming.start_recording(stream.id, %{
        storage_path: "recordings/stream_2"
      })

      conn = get(conn, ~p"/api/v1/live-streams/#{stream.id}/recordings")
      assert %{"data" => recordings, "count" => count} = json_response(conn, 200)
      assert count >= 2
      assert is_list(recordings)
    end

    test "returns 403 when user is not owner", %{conn: conn} do
      {:ok, other_user} = Accounts.register_user(%{
        username: "otheruser",
        email: "other@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, other_stream} = LiveStreaming.create_live_stream(%{
        user_id: other_user.id,
        title: "Other Stream"
      })

      conn = get(conn, ~p"/api/v1/live-streams/#{other_stream.id}/recordings")
      assert json_response(conn, 403)
    end
  end

  describe "show" do
    test "shows a recording (owner only)", %{conn: conn, stream: stream} do
      {:ok, recording} = LiveStreaming.start_recording(stream.id, %{
        storage_path: "recordings/stream_1"
      })

      conn = get(conn, ~p"/api/v1/live-streams/#{stream.id}/recordings/#{recording.id}")
      assert %{"data" => recording_data} = json_response(conn, 200)
      assert recording_data["id"] == recording.id
      assert recording_data["stream_id"] == stream.id
      assert recording_data["recording_status"] == "recording"
    end

    test "returns 404 for non-existent recording", %{conn: conn, stream: stream} do
      fake_id = Ecto.UUID.generate()
      conn = get(conn, ~p"/api/v1/live-streams/#{stream.id}/recordings/#{fake_id}")
      assert json_response(conn, 404)
    end
  end

  describe "create" do
    test "starts recording for stream (owner only)", %{conn: conn, stream: stream} do
      attrs = %{
        storage_path: "recordings/stream_123"
      }

      conn = post(conn, ~p"/api/v1/live-streams/#{stream.id}/recordings", %{recording: attrs})
      assert %{"data" => recording_data} = json_response(conn, 201)
      assert recording_data["stream_id"] == stream.id
      assert recording_data["recording_status"] == "recording"
      assert recording_data["storage_path"] == "recordings/stream_123"
    end

    test "returns 403 when user is not owner", %{conn: conn} do
      {:ok, other_user} = Accounts.register_user(%{
        username: "otheruser",
        email: "other@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, other_stream} = LiveStreaming.create_live_stream(%{
        user_id: other_user.id,
        title: "Other Stream"
      })

      conn = post(conn, ~p"/api/v1/live-streams/#{other_stream.id}/recordings", %{
        recording: %{storage_path: "recordings/other"}
      })
      assert json_response(conn, 403)
    end
  end

  describe "update" do
    test "updates recording progress (internal)", %{conn: conn, stream: stream} do
      {:ok, recording} = LiveStreaming.start_recording(stream.id, %{})

      attrs = %{
        segment_count: 150,
        total_size_bytes: 1_500_000_000
      }

      conn = put(conn, ~p"/api/v1/live-streams/#{stream.id}/recordings/#{recording.id}", attrs)
      assert %{"data" => recording_data} = json_response(conn, 200)
      assert recording_data["segment_count"] == 150
      assert recording_data["total_size_bytes"] == 1_500_000_000
    end
  end

  describe "complete" do
    test "completes recording and triggers VOD conversion (internal)", %{conn: conn, stream: stream} do
      {:ok, recording} = LiveStreaming.start_recording(stream.id, %{})
      media_id = Ecto.UUID.generate()

      conn = post(conn, ~p"/api/v1/live-streams/#{stream.id}/recordings/#{recording.id}/complete", %{
        media_id: media_id
      })

      assert %{"data" => recording_data} = json_response(conn, 200)
      assert recording_data["recording_status"] == "processing"
      assert recording_data["ended_at"] != nil
      assert recording_data["media_id"] == media_id
    end
  end
end

