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

defmodule ArmoricoreRealtimeWeb.SearchControllerTest do
  use ExUnit.Case, async: false
  use ArmoricoreRealtimeWeb.ConnCase

  import Ecto.Query
  alias ArmoricoreRealtime.Content
  alias ArmoricoreRealtime.Content.Video
  alias ArmoricoreRealtime.Accounts
  alias ArmoricoreRealtime.Media.MediaFile
  alias ArmoricoreRealtime.Repo

  @valid_user_attrs %{
    email: "test@example.com",
    password: "Password123!@#",
    password_confirmation: "Password123!@#",
    username: "testuser",
    first_name: "Test",
    last_name: "User"
  }

  setup %{conn: conn} do
    # Clean up test data
    Repo.delete_all(Video)
    Repo.delete_all(MediaFile)
    Repo.delete_all(Accounts.User)

    # Create test user
    {:ok, user} = Accounts.register_user(@valid_user_attrs)

    # Create test media file
    {:ok, media} = Repo.insert(%MediaFile{
      user_id: user.id,
      original_filename: "test_video.mp4",
      content_type: "video/mp4",
      file_size: 1_000_000,
      status: "ready"
    })

    {:ok, conn: conn, user: user, media: media}
  end

  describe "GET /api/v1/search" do
    test "searches videos by query", %{conn: conn, user: user, media: media} do
      {:ok, _video1} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Rust Programming Tutorial",
        description: "Learn Rust programming language",
        status: "ready",
        visibility: "public"
      })

      {:ok, _video2} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Python Basics",
        description: "Learn Python programming",
        status: "ready",
        visibility: "public"
      })

      # Force search vector update (in real app, trigger handles this)
      Repo.query!("UPDATE videos SET search_vector = to_tsvector('english', coalesce(title, '') || ' ' || coalesce(description, ''))")

      conn = get(conn, ~p"/api/v1/search?q=Rust")
      assert %{"query" => "Rust", "data" => data, "count" => count} = json_response(conn, 200)
      assert count >= 1
      assert Enum.any?(data, fn v -> String.contains?(String.downcase(v["title"]), "rust") end)
    end

    test "returns error when query is missing", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/search")
      assert %{"error" => "Missing search query parameter 'q'"} = json_response(conn, 400)
    end

    test "returns error when query is empty", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/search?q=")
      assert %{"error" => "Search query cannot be empty"} = json_response(conn, 400)
    end

    test "filters search results by status", %{conn: conn, user: user, media: media} do
      {:ok, _video1} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Ready Video",
        description: "This is ready",
        status: "ready",
        visibility: "public"
      })

      {:ok, _video2} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Draft Video",
        description: "This is draft",
        status: "draft",
        visibility: "public"
      })

      # Force search vector update
      Repo.query!("UPDATE videos SET search_vector = to_tsvector('english', coalesce(title, '') || ' ' || coalesce(description, ''))")

      conn = get(conn, ~p"/api/v1/search?q=video&status=ready")
      assert %{"data" => data} = json_response(conn, 200)
      assert Enum.all?(data, &(&1["status"] == "ready"))
    end

    test "supports pagination", %{conn: conn, user: user, media: media} do
      # Create multiple videos
      for i <- 1..5 do
        {:ok, _video} = Content.create_video(%{
          media_id: media.id,
          user_id: user.id,
          title: "Video #{i}",
          description: "Description #{i}",
          status: "ready",
          visibility: "public"
        })
      end

      # Force search vector update
      Repo.query!("UPDATE videos SET search_vector = to_tsvector('english', coalesce(title, '') || ' ' || coalesce(description, ''))")

      conn = get(conn, ~p"/api/v1/search?q=video&limit=2&page=1")
      assert %{"data" => data} = json_response(conn, 200)
      assert length(data) <= 2
    end
  end
end

