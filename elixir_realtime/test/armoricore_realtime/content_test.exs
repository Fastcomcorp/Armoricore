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

defmodule ArmoricoreRealtime.ContentTest do
  use ExUnit.Case, async: true
  use ArmoricoreRealtimeWeb.ConnCase

  import Ecto.Query
  alias ArmoricoreRealtime.Content
  alias ArmoricoreRealtime.Content.{Video, Category, Tag}
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

  @valid_media_attrs %{
    original_filename: "test_video.mp4",
    content_type: "video/mp4",
    file_size: 1_000_000,
    status: "ready"
  }

  @valid_video_attrs %{
    title: "Test Video",
    description: "This is a test video",
    status: "ready",
    visibility: "public"
  }

  @valid_category_attrs %{
    name: "Technology",
    slug: "technology",
    description: "Technology videos"
  }

  @valid_tag_attrs %{
    name: "rust"
  }

  setup do
    # Clean up test data
    Repo.delete_all(Video)
    Repo.delete_all(Category)
    Repo.delete_all(Tag)
    Repo.delete_all(MediaFile)
    Repo.delete_all(Accounts.User)

    # Create test user
    {:ok, user} = Accounts.register_user(@valid_user_attrs)

    # Create test media file
    {:ok, media} = Repo.insert(%MediaFile{
      user_id: user.id,
      original_filename: @valid_media_attrs.original_filename,
      content_type: @valid_media_attrs.content_type,
      file_size: @valid_media_attrs.file_size,
      status: @valid_media_attrs.status
    })

    {:ok, user: user, media: media}
  end

  describe "videos" do
    test "list_videos/1 returns all videos" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user2@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video2.mp4",
        content_type: "video/mp4",
        file_size: 2_000_000,
        status: "ready"
      })

      {:ok, video1} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Video 1",
        status: "ready",
        visibility: "public"
      })

      {:ok, video2} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Video 2",
        status: "ready",
        visibility: "public"
      })

      videos = Content.list_videos()
      assert length(videos) == 2
      assert Enum.any?(videos, &(&1.id == video1.id))
      assert Enum.any?(videos, &(&1.id == video2.id))
    end

    test "list_videos/1 filters by status" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user3@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video3.mp4",
        content_type: "video/mp4",
        file_size: 3_000_000,
        status: "ready"
      })

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

      videos = Content.list_videos(status: "ready")
      assert length(videos) == 1
      assert hd(videos).status == "ready"
    end

    test "list_videos/1 filters by visibility" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user4@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video4.mp4",
        content_type: "video/mp4",
        file_size: 4_000_000,
        status: "ready"
      })

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

      videos = Content.list_videos(visibility: "public")
      assert length(videos) == 1
      assert hd(videos).visibility == "public"
    end

    test "list_videos/1 sorts by views" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user5@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video5.mp4",
        content_type: "video/mp4",
        file_size: 5_000_000,
        status: "ready"
      })

      {:ok, video1} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Low Views",
        status: "ready",
        visibility: "public"
      })
      {:ok, video1} = Content.update_video(video1, %{views: 10})

      {:ok, video2} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "High Views",
        status: "ready",
        visibility: "public"
      })
      {:ok, video2} = Content.update_video(video2, %{views: 100})

      videos = Content.list_videos(sort: :views)
      assert length(videos) == 2
      assert hd(videos).views >= List.last(videos).views
    end

    test "get_video!/1 returns the video with given id" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user6@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video6.mp4",
        content_type: "video/mp4",
        file_size: 6_000_000,
        status: "ready"
      })

      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test Video",
        status: "ready",
        visibility: "public"
      })

      found_video = Content.get_video!(video.id)
      assert found_video.id == video.id
      assert found_video.title == "Test Video"
    end

    test "get_video!/1 raises if id is invalid" do
      assert_raise Ecto.NoResultsError, fn ->
        Content.get_video!(Ecto.UUID.generate())
      end
    end

    test "create_video/1 with valid data creates a video" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user7@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video7.mp4",
        content_type: "video/mp4",
        file_size: 7_000_000,
        status: "ready"
      })

      attrs = Map.merge(@valid_video_attrs, %{
        media_id: media.id,
        user_id: user.id
      })

      assert {:ok, %Video{} = video} = Content.create_video(attrs)
      assert video.title == @valid_video_attrs.title
      assert video.description == @valid_video_attrs.description
      assert video.status == "ready"
      assert video.visibility == "public"
    end

    test "create_video/1 with invalid data returns error changeset" do
      assert {:error, %Ecto.Changeset{}} = Content.create_video(%{})
    end

    test "update_video/2 with valid data updates the video" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user8@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video8.mp4",
        content_type: "video/mp4",
        file_size: 8_000_000,
        status: "ready"
      })

      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Original Title",
        status: "ready",
        visibility: "public"
      })

      assert {:ok, %Video{} = video} = Content.update_video(video, %{title: "Updated Title"})
      assert video.title == "Updated Title"
    end

    test "update_video/2 with invalid data returns error changeset" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user9@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video9.mp4",
        content_type: "video/mp4",
        file_size: 9_000_000,
        status: "ready"
      })

      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test",
        status: "ready",
        visibility: "public"
      })

      assert {:error, %Ecto.Changeset{}} = Content.update_video(video, %{title: ""})
    end

    test "delete_video/1 deletes the video" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user10@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video10.mp4",
        content_type: "video/mp4",
        file_size: 10_000_000,
        status: "ready"
      })

      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "To Delete",
        status: "ready",
        visibility: "public"
      })

      assert {:ok, %Video{}} = Content.delete_video(video)
      assert_raise Ecto.NoResultsError, fn ->
        Content.get_video!(video.id)
      end
    end

    test "increment_video_views/1 increments view count" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user11@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video11.mp4",
        content_type: "video/mp4",
        file_size: 11_000_000,
        status: "ready"
      })

      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test",
        status: "ready",
        visibility: "public"
      })

      assert video.views == 0
      {:ok, video} = Content.increment_video_views(video)
      assert video.views == 1
      {:ok, video} = Content.increment_video_views(video)
      assert video.views == 2
    end

    test "increment_video_likes/1 increments likes count" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user12@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video12.mp4",
        content_type: "video/mp4",
        file_size: 12_000_000,
        status: "ready"
      })

      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test",
        status: "ready",
        visibility: "public"
      })

      assert video.likes == 0
      {:ok, video} = Content.increment_video_likes(video)
      assert video.likes == 1
    end

    test "increment_video_dislikes/1 increments dislikes count" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user13@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video13.mp4",
        content_type: "video/mp4",
        file_size: 13_000_000,
        status: "ready"
      })

      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test",
        status: "ready",
        visibility: "public"
      })

      assert video.dislikes == 0
      {:ok, video} = Content.increment_video_dislikes(video)
      assert video.dislikes == 1
    end
  end

  describe "search_videos/2" do
    test "searches videos by title" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user14@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video14.mp4",
        content_type: "video/mp4",
        file_size: 14_000_000,
        status: "ready"
      })

      {:ok, _video1} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Rust Programming Tutorial",
        description: "Learn Rust",
        status: "ready",
        visibility: "public"
      })

      {:ok, _video2} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Python Basics",
        description: "Learn Python",
        status: "ready",
        visibility: "public"
      })

      # Force search vector update (in real app, trigger handles this)
      Repo.query!("UPDATE videos SET search_vector = to_tsvector('english', coalesce(title, '') || ' ' || coalesce(description, ''))")

      videos = Content.search_videos("Rust")
      assert length(videos) >= 1
      assert Enum.any?(videos, fn v -> String.contains?(String.downcase(v.title), "rust") end)
    end
  end

  describe "categories" do
    test "list_categories/1 returns all categories" do
      {:ok, category1} = Content.create_category(@valid_category_attrs)
      {:ok, category2} = Content.create_category(%{
        name: "Science",
        slug: "science"
      })

      categories = Content.list_categories()
      assert length(categories) == 2
    end

    test "get_category!/1 returns the category with given id" do
      {:ok, category} = Content.create_category(@valid_category_attrs)
      found_category = Content.get_category!(category.id)
      assert found_category.id == category.id
      assert found_category.name == "Technology"
    end

    test "get_category_by_slug/1 returns the category with given slug" do
      {:ok, category} = Content.create_category(@valid_category_attrs)
      found_category = Content.get_category_by_slug("technology")
      assert found_category.id == category.id
      assert found_category.slug == "technology"
    end

    test "create_category/1 with valid data creates a category" do
      assert {:ok, %Category{} = category} = Content.create_category(@valid_category_attrs)
      assert category.name == "Technology"
      assert category.slug == "technology"
    end

    test "create_category/1 generates slug from name if not provided" do
      attrs = Map.delete(@valid_category_attrs, :slug)
      assert {:ok, %Category{} = category} = Content.create_category(attrs)
      assert category.slug == "technology"
    end

    test "update_category/2 with valid data updates the category" do
      {:ok, category} = Content.create_category(@valid_category_attrs)
      assert {:ok, %Category{} = category} = Content.update_category(category, %{name: "Tech"})
      assert category.name == "Tech"
    end

    test "delete_category/1 deletes the category" do
      {:ok, category} = Content.create_category(@valid_category_attrs)
      assert {:ok, %Category{}} = Content.delete_category(category)
      assert_raise Ecto.NoResultsError, fn ->
        Content.get_category!(category.id)
      end
    end
  end

  describe "tags" do
    test "list_tags/1 returns all tags" do
      {:ok, _tag1} = Content.create_tag(@valid_tag_attrs)
      {:ok, _tag2} = Content.create_tag(%{name: "python"})

      tags = Content.list_tags()
      assert length(tags) == 2
    end

    test "get_tag!/1 returns the tag with given id" do
      {:ok, tag} = Content.create_tag(@valid_tag_attrs)
      found_tag = Content.get_tag!(tag.id)
      assert found_tag.id == tag.id
      assert found_tag.name == "rust"
    end

    test "get_tag_by_name/1 returns the tag with given name" do
      {:ok, tag} = Content.create_tag(@valid_tag_attrs)
      found_tag = Content.get_tag_by_name("rust")
      assert found_tag.id == tag.id
      assert found_tag.name == "rust"
    end

    test "create_tag/1 with valid data creates a tag" do
      assert {:ok, %Tag{} = tag} = Content.create_tag(@valid_tag_attrs)
      assert tag.name == "rust"
    end

    test "get_or_create_tags/1 creates tags that don't exist" do
      tags = Content.get_or_create_tags(["rust", "python", "elixir"])
      assert length(tags) == 3
      assert Enum.any?(tags, &(&1.name == "rust"))
      assert Enum.any?(tags, &(&1.name == "python"))
      assert Enum.any?(tags, &(&1.name == "elixir"))
    end

    test "get_or_create_tags/1 returns existing tags" do
      {:ok, _existing_tag} = Content.create_tag(@valid_tag_attrs)
      tags = Content.get_or_create_tags(["rust", "python"])
      assert length(tags) == 2
      # Should reuse existing "rust" tag
      assert Enum.any?(tags, &(&1.name == "rust"))
    end
  end

  describe "video tags" do
    test "add_tags_to_video/2 adds tags to a video" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user15@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video15.mp4",
        content_type: "video/mp4",
        file_size: 15_000_000,
        status: "ready"
      })

      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test",
        status: "ready",
        visibility: "public"
      })

      {:ok, video} = Content.add_tags_to_video(video, ["rust", "programming"])
      video = Content.get_video!(video.id)
      assert length(video.tags) == 2
      assert Enum.any?(video.tags, &(&1.name == "rust"))
      assert Enum.any?(video.tags, &(&1.name == "programming"))
    end

    test "remove_tags_from_video/2 removes tags from a video" do
      {:ok, user} = Accounts.register_user(Map.put(@valid_user_attrs, :email, "user16@example.com"))
      {:ok, media} = Repo.insert(%MediaFile{
        user_id: user.id,
        original_filename: "video16.mp4",
        content_type: "video/mp4",
        file_size: 16_000_000,
        status: "ready"
      })

      {:ok, video} = Content.create_video(%{
        media_id: media.id,
        user_id: user.id,
        title: "Test",
        status: "ready",
        visibility: "public"
      })

      {:ok, video} = Content.add_tags_to_video(video, ["rust", "python", "elixir"])
      {:ok, video} = Content.remove_tags_from_video(video, ["python"])
      video = Content.get_video!(video.id)
      assert length(video.tags) == 2
      assert Enum.any?(video.tags, &(&1.name == "rust"))
      refute Enum.any?(video.tags, &(&1.name == "python"))
    end
  end
end

