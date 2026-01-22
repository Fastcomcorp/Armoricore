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

defmodule ArmoricoreRealtimeWeb.LiveStreamControllerTest do
  use ArmoricoreRealtimeWeb.ConnCase

  alias ArmoricoreRealtime.{LiveStreaming, Accounts, Content}

  @create_attrs %{
    title: "Test Stream",
    description: "A test live stream",
    ingest_protocol: "rtmp"
  }

  @update_attrs %{
    title: "Updated Stream Title"
  }

  setup %{conn: conn} do
    # Create a user
    {:ok, user} = Accounts.register_user(%{
      username: "testuser",
      email: "test@example.com",
      password: "TestPassword123!@#"
    })

    # Create a category
    {:ok, category} = Content.create_category(%{
      name: "Gaming",
      slug: "gaming"
    })

    # Create authenticated connection
    conn = build_authenticated_conn(conn, user)

    %{conn: conn, user: user, category: category}
  end

  describe "index" do
    test "lists all live streams (public)", %{conn: conn} do
      # Create some streams
      {:ok, user} = Accounts.register_user(%{
        username: "streamer1",
        email: "streamer1@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, _stream1} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Stream 1",
        status: "live"
      })

      {:ok, _stream2} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Stream 2",
        status: "scheduled"
      })

      conn = get(conn, ~p"/api/v1/live-streams")
      assert %{"data" => streams, "count" => count} = json_response(conn, 200)
      assert count >= 2
      assert is_list(streams)
    end

    test "filters streams by status", %{conn: conn} do
      {:ok, user} = Accounts.create_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, _live} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Live Stream",
        status: "live"
      })

      {:ok, _scheduled} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Scheduled Stream",
        status: "scheduled"
      })

      conn = get(conn, ~p"/api/v1/live-streams?status=live")
      assert %{"data" => streams} = json_response(conn, 200)
      assert Enum.all?(streams, &(&1["status"] == "live"))
    end
  end

  describe "active" do
    test "lists only active (live) streams (public)", %{conn: conn} do
      {:ok, user} = Accounts.create_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, _live} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Live Stream",
        status: "live"
      })

      {:ok, _scheduled} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Scheduled Stream",
        status: "scheduled"
      })

      conn = get(conn, ~p"/api/v1/live-streams/active")
      assert %{"data" => streams} = json_response(conn, 200)
      assert Enum.all?(streams, &(&1["status"] == "live"))
    end
  end

  describe "show" do
    test "shows a live stream (public)", %{conn: conn} do
      {:ok, user} = Accounts.create_user(%{
        username: "streamer",
        email: "streamer@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Test Stream"
      })

      conn = get(conn, ~p"/api/v1/live-streams/#{stream.id}")
      assert %{"data" => stream_data} = json_response(conn, 200)
      assert stream_data["id"] == stream.id
      assert stream_data["title"] == "Test Stream"
    end

    test "returns 404 for non-existent stream", %{conn: conn} do
      fake_id = Ecto.UUID.generate()
      conn = get(conn, ~p"/api/v1/live-streams/#{fake_id}")
      assert json_response(conn, 404)
    end
  end

  describe "create" do
    test "creates a live stream when data is valid (protected)", %{conn: conn, user: user, category: category} do
      attrs = Map.merge(@create_attrs, %{category_id: category.id})

      conn = post(conn, ~p"/api/v1/live-streams", %{live_stream: attrs})
      assert %{"data" => stream_data} = json_response(conn, 201)
      assert stream_data["title"] == "Test Stream"
      assert stream_data["user"]["id"] == user.id
      assert stream_data["stream_key"] != nil
    end

    test "renders errors when data is invalid (protected)", %{conn: conn} do
      conn = post(conn, ~p"/api/v1/live-streams", %{live_stream: %{}})
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "update" do
    setup %{user: user} do
      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Original Title"
      })

      %{stream: stream}
    end

    test "updates stream when data is valid (owner only)", %{conn: conn, stream: stream} do
      conn = put(conn, ~p"/api/v1/live-streams/#{stream.id}", %{live_stream: @update_attrs})
      assert %{"data" => stream_data} = json_response(conn, 200)
      assert stream_data["title"] == "Updated Stream Title"
    end

    test "renders errors when data is invalid (owner only)", %{conn: conn, stream: stream} do
      conn = put(conn, ~p"/api/v1/live-streams/#{stream.id}", %{live_stream: %{title: nil}})
      assert json_response(conn, 422)["errors"] != %{}
    end

    test "returns 403 when user is not owner", %{conn: conn} do
      # Create another user and stream
      {:ok, other_user} = Accounts.create_user(%{
        username: "otheruser",
        email: "other@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, other_stream} = LiveStreaming.create_live_stream(%{
        user_id: other_user.id,
        title: "Other Stream"
      })

      conn = put(conn, ~p"/api/v1/live-streams/#{other_stream.id}", %{live_stream: @update_attrs})
      assert json_response(conn, 403)
    end
  end

  describe "delete" do
    setup %{user: user} do
      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Stream to Delete"
      })

      %{stream: stream}
    end

    test "deletes stream (owner only)", %{conn: conn, stream: stream} do
      conn = delete(conn, ~p"/api/v1/live-streams/#{stream.id}")
      assert response(conn, 204)

      assert_raise Ecto.NoResultsError, fn ->
        LiveStreaming.get_live_stream!(stream.id)
      end
    end

    test "returns 403 when user is not owner", %{conn: conn} do
      {:ok, other_user} = Accounts.create_user(%{
        username: "otheruser",
        email: "other@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, other_stream} = LiveStreaming.create_live_stream(%{
        user_id: other_user.id,
        title: "Other Stream"
      })

      conn = delete(conn, ~p"/api/v1/live-streams/#{other_stream.id}")
      assert json_response(conn, 403)
    end
  end

  describe "start" do
    setup %{user: user} do
      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Stream to Start",
        status: "scheduled"
      })

      %{stream: stream}
    end

    test "starts a stream (owner only)", %{conn: conn, stream: stream} do
      conn = post(conn, ~p"/api/v1/live-streams/#{stream.id}/start")
      assert %{"data" => stream_data} = json_response(conn, 200)
      assert stream_data["status"] == "live"
      assert stream_data["started_at"] != nil
    end

    test "returns 403 when user is not owner", %{conn: conn} do
      {:ok, other_user} = Accounts.create_user(%{
        username: "otheruser",
        email: "other@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, other_stream} = LiveStreaming.create_live_stream(%{
        user_id: other_user.id,
        title: "Other Stream"
      })

      conn = post(conn, ~p"/api/v1/live-streams/#{other_stream.id}/start")
      assert json_response(conn, 403)
    end
  end

  describe "end" do
    setup %{user: user} do
      started_at = DateTime.add(DateTime.utc_now(), -3600, :second)

      {:ok, stream} = LiveStreaming.create_live_stream(%{
        user_id: user.id,
        title: "Stream to End",
        status: "live",
        started_at: started_at
      })

      %{stream: stream}
    end

    test "ends a stream (owner only)", %{conn: conn, stream: stream} do
      conn = post(conn, ~p"/api/v1/live-streams/#{stream.id}/end")
      assert %{"data" => stream_data} = json_response(conn, 200)
      assert stream_data["status"] == "ended"
      assert stream_data["ended_at"] != nil
      assert stream_data["duration_seconds"] >= 3600
    end

    test "returns 403 when user is not owner", %{conn: conn} do
      {:ok, other_user} = Accounts.create_user(%{
        username: "otheruser",
        email: "other@example.com",
        password: "TestPassword123!@#"
      })

      {:ok, other_stream} = LiveStreaming.create_live_stream(%{
        user_id: other_user.id,
        title: "Other Stream",
        status: "live"
      })

      conn = post(conn, ~p"/api/v1/live-streams/#{other_stream.id}/end")
      assert json_response(conn, 403)
    end
  end
end

