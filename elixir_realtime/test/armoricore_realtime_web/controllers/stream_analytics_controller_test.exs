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

defmodule ArmoricoreRealtimeWeb.StreamAnalyticsControllerTest do
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

  describe "show" do
    test "returns analytics for stream (owner only)", %{conn: conn, stream: stream, user: user} do
      # Create some analytics events
      LiveStreaming.track_viewer_event(stream.id, "join", %{user_id: user.id})
      LiveStreaming.track_viewer_event(stream.id, "join", %{user_id: user.id})
      LiveStreaming.track_viewer_event(stream.id, "leave", %{user_id: user.id})

      conn = get(conn, ~p"/api/v1/live-streams/#{stream.id}/analytics")
      assert %{"data" => analytics} = json_response(conn, 200)
      assert analytics["total_events"] >= 3
      assert analytics["join_events"] >= 2
      assert analytics["leave_events"] >= 1
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

      conn = get(conn, ~p"/api/v1/live-streams/#{other_stream.id}/analytics")
      assert json_response(conn, 403)
    end
  end

  describe "viewers" do
    test "returns viewer statistics (public)", %{conn: conn, stream: stream} do
      LiveStreaming.update_viewer_count(stream.id, 25)

      conn = get(conn, ~p"/api/v1/live-streams/#{stream.id}/viewers")
      assert %{"data" => stats} = json_response(conn, 200)
      assert stats["current"] == 25
      assert stats["peak"] >= 25
      assert stats["total"] >= 0
    end

    test "returns 404 for non-existent stream", %{conn: conn} do
      fake_id = Ecto.UUID.generate()
      conn = get(conn, ~p"/api/v1/live-streams/#{fake_id}/viewers")
      assert json_response(conn, 404)
    end
  end

  describe "track_join" do
    test "tracks viewer join (internal)", %{conn: conn, stream: stream, user: user} do
      initial_count = stream.current_viewers

      conn = post(conn, ~p"/api/v1/live-streams/#{stream.id}/track-join", %{
        quality: "720p",
        bitrate: "2500"
      })

      assert %{"success" => true} = json_response(conn, 200)

      # Verify viewer count increased
      updated = LiveStreaming.get_live_stream!(stream.id)
      assert updated.current_viewers == initial_count + 1
    end
  end

  describe "track_leave" do
    test "tracks viewer leave (internal)", %{conn: conn, stream: stream, user: user} do
      # Set initial viewers
      LiveStreaming.update_viewer_count(stream.id, 10)

      conn = post(conn, ~p"/api/v1/live-streams/#{stream.id}/track-leave", %{
        quality: "720p"
      })

      assert %{"success" => true} = json_response(conn, 200)

      # Verify viewer count decreased
      updated = LiveStreaming.get_live_stream!(stream.id)
      assert updated.current_viewers == 9
    end
  end
end

