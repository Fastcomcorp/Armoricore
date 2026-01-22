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

defmodule ArmoricoreRealtimeWeb.VideoControllerTest do
  use ExUnit.Case, async: false
  use ArmoricoreRealtimeWeb.ConnCase

  alias ArmoricoreRealtime.Content
  alias ArmoricoreRealtime.Content.Video
  alias ArmoricoreRealtime.Accounts
  alias ArmoricoreRealtime.Media.MediaFile
  alias ArmoricoreRealtime.Auth
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

    # Generate auth token
    user_id_str = to_string(user.id)
    {:ok, tokens} = Auth.generate_tokens(user_id_str)

    conn = put_req_header(conn, "authorization", "Bearer #{tokens.access_token}")

    {:ok, conn: conn, user: user, media: media, tokens: tokens}
  end

  describe "GET /api/v1/videos" do
    test "lists all videos", %{conn: conn, user: user, media: media} do
      {:ok, _video1} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Video 1",
        status: "ready",
        visibility: "public"
      })

      {:ok, _video2} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Video 2",
        status: "ready",
        visibility: "public"
      })

      conn = get(conn, ~p"/api/v1/videos")
      assert %{"data" => data, "count" => count} = json_response(conn, 200)
      assert count >= 2
      assert length(data) >= 2
    end

    test "filters videos by status", %{conn: conn, user: user, media: media} do
      {:ok, _video1} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Ready Video",
        status: "ready",
        visibility: "public"
      })

      {:ok, _video2} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Draft Video",
        status: "draft",
        visibility: "public"
      })

      conn = get(conn, ~p"/api/v1/videos?status=ready")
      assert %{"data" => data} = json_response(conn, 200)
      assert Enum.all?(data, &(&1["status"] == "ready"))
    end

    test "filters videos by visibility", %{conn: conn, user: user, media: media} do
      {:ok, _video1} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Public Video",
        status: "ready",
        visibility: "public"
      })

      {:ok, _video2} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Private Video",
        status: "ready",
        visibility: "private"
      })

      conn = get(conn, ~p"/api/v1/videos?visibility=public")
      assert %{"data" => data} = json_response(conn, 200)
      assert Enum.all?(data, &(&1["visibility"] == "public"))
    end

    test "sorts videos by views", %{conn: conn, user: user, media: media} do
      {:ok, video1} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Low Views",
        status: "ready",
        visibility: "public"
      })
      Content.update_video(video1, %{views: 10})

      {:ok, video2} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "High Views",
        status: "ready",
        visibility: "public"
      })
      Content.update_video(video2, %{views: 100})

      conn = get(conn, ~p"/api/v1/videos?sort=views")
      assert %{"data" => data} = json_response(conn, 200)
      views = Enum.map(data, & &1["views"])
      assert views == Enum.sort(views, :desc)
    end
  end

  describe "GET /api/v1/videos/:id" do
    test "shows video and increments view count", %{conn: conn, user: user, media: media} do
      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test Video",
        status: "ready",
        visibility: "public"
      })

      assert video.views == 0

      conn = get(conn, ~p"/api/v1/videos/#{video.id}")
      assert %{"data" => data} = json_response(conn, 200)
      assert data["id"] == to_string(video.id)
      assert data["title"] == "Test Video"
      assert data["views"] == 1  # View count incremented
    end

    test "returns 404 for non-existent video", %{conn: conn} do
      fake_id = Ecto.UUID.generate()
      conn = get(conn, ~p"/api/v1/videos/#{fake_id}")
      assert %{"error" => "Video not found"} = json_response(conn, 404)
    end
  end

  describe "POST /api/v1/videos" do
    test "creates video when data is valid", %{conn: conn, user: user, media: media} do
      video_params = %{
        "video" => %{
          "media_id" => to_string(media.id),
          "title" => "New Video",
          "description" => "Video description",
          "status" => "ready",
          "visibility" => "public"
        }
      }

      conn = post(conn, ~p"/api/v1/videos", video_params)
      assert %{"data" => data} = json_response(conn, 201)
      assert data["title"] == "New Video"
      assert data["user"]["id"] == to_string(user.id)
    end

    test "returns error when data is invalid", %{conn: conn, media: media} do
      video_params = %{
        "video" => %{
          "media_id" => to_string(media.id),
          "title" => ""  # Invalid: empty title
        }
      }

      conn = post(conn, ~p"/api/v1/videos", video_params)
      assert %{"error" => "Validation failed"} = json_response(conn, 422)
    end

    test "requires authentication", %{conn: conn, media: media} do
      conn = build_conn()  # No auth token
      video_params = %{
        "video" => %{
          "media_id" => to_string(media.id),
          "title" => "New Video",
          "status" => "ready",
          "visibility" => "public"
        }
      }

      conn = post(conn, ~p"/api/v1/videos", video_params)
      assert %{"error" => "Missing authorization token"} = json_response(conn, 401)
    end
  end

  describe "PUT /api/v1/videos/:id" do
    test "updates video when user is owner", %{conn: conn, user: user, media: media} do
      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Original Title",
        status: "ready",
        visibility: "public"
      })

      update_params = %{
        "video" => %{
          "title" => "Updated Title"
        }
      }

      conn = put(conn, ~p"/api/v1/videos/#{video.id}", update_params)
      assert %{"data" => data} = json_response(conn, 200)
      assert data["title"] == "Updated Title"
    end

    test "returns 403 when user is not owner", %{conn: conn, media: media} do
      # Create another user
      {:ok, other_user} = Accounts.register_user(%{
        email: "other@example.com",
        password: "Password123!@#",
    password_confirmation: "Password123!@#",
        username: "otheruser",
        first_name: "Other",
        last_name: "User"
      })

      # Create video owned by other user
      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: other_user.id,
        title: "Other User's Video",
        status: "ready",
        visibility: "public"
      })

      update_params = %{
        "video" => %{
          "title" => "Hacked Title"
        }
      }

      conn = put(conn, ~p"/api/v1/videos/#{video.id}", update_params)
      assert %{"error" => "You don't have permission to update this video"} = json_response(conn, 403)
    end

    test "returns 404 for non-existent video", %{conn: conn} do
      fake_id = Ecto.UUID.generate()
      update_params = %{"video" => %{"title" => "Updated"}}

      conn = put(conn, ~p"/api/v1/videos/#{fake_id}", update_params)
      assert %{"error" => "Video not found"} = json_response(conn, 404)
    end
  end

  describe "DELETE /api/v1/videos/:id" do
    test "deletes video when user is owner", %{conn: conn, user: user, media: media} do
      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "To Delete",
        status: "ready",
        visibility: "public"
      })

      conn = delete(conn, ~p"/api/v1/videos/#{video.id}")
      assert response(conn, 204)

      # Verify video is deleted
      assert_raise Ecto.NoResultsError, fn ->
        Content.get_video!(video.id)
      end
    end

    test "returns 403 when user is not owner", %{conn: conn, media: media} do
      # Create another user
      {:ok, other_user} = Accounts.register_user(%{
        email: "other2@example.com",
        password: "Password123!@#",
    password_confirmation: "Password123!@#",
        username: "otheruser2",
        first_name: "Other",
        last_name: "User"
      })

      # Create video owned by other user
      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: other_user.id,
        title: "Other User's Video",
        status: "ready",
        visibility: "public"
      })

      conn = delete(conn, ~p"/api/v1/videos/#{video.id}")
      assert %{"error" => "You don't have permission to delete this video"} = json_response(conn, 403)
    end
  end

  describe "POST /api/v1/videos/:id/like" do
    test "increments likes count", %{conn: conn, user: user, media: media} do
      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test Video",
        status: "ready",
        visibility: "public"
      })

      assert video.likes == 0

      conn = post(conn, ~p"/api/v1/videos/#{video.id}/like")
      assert %{"data" => data} = json_response(conn, 200)
      assert data["likes"] == 1
    end

    test "requires authentication", %{conn: conn, user: user, media: media} do
      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test Video",
        status: "ready",
        visibility: "public"
      })

      conn = build_conn()  # No auth token
      conn = post(conn, ~p"/api/v1/videos/#{video.id}/like")
      assert %{"error" => "Missing authorization token"} = json_response(conn, 401)
    end
  end

  describe "POST /api/v1/videos/:id/dislike" do
    test "increments dislikes count", %{conn: conn, user: user, media: media} do
      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test Video",
        status: "ready",
        visibility: "public"
      })

      assert video.dislikes == 0

      conn = post(conn, ~p"/api/v1/videos/#{video.id}/dislike")
      assert %{"data" => data} = json_response(conn, 200)
      assert data["dislikes"] == 1
    end
  end
end

