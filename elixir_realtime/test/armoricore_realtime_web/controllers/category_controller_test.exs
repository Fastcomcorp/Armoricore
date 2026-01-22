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

defmodule ArmoricoreRealtimeWeb.CategoryControllerTest do
  use ExUnit.Case, async: false
  use ArmoricoreRealtimeWeb.ConnCase

  alias ArmoricoreRealtime.Content
  alias ArmoricoreRealtime.Content.Category
  alias ArmoricoreRealtime.Accounts
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
    Repo.delete_all(Category)
    Repo.delete_all(Accounts.User)

    # Create test user
    {:ok, user} = Accounts.register_user(@valid_user_attrs)

    # Generate auth token
    user_id_str = to_string(user.id)
    {:ok, tokens} = Auth.generate_tokens(user_id_str)

    conn = put_req_header(conn, "authorization", "Bearer #{tokens.access_token}")

    {:ok, conn: conn, user: user, tokens: tokens}
  end

  describe "GET /api/v1/categories" do
    test "lists all categories", %{conn: conn} do
      {:ok, _category1} = Content.create_category(%{
        name: "Technology",
        slug: "technology"
      })

      {:ok, _category2} = Content.create_category(%{
        name: "Science",
        slug: "science"
      })

      conn = get(conn, ~p"/api/v1/categories")
      assert %{"data" => data, "count" => count} = json_response(conn, 200)
      assert count >= 2
      assert length(data) >= 2
    end
  end

  describe "GET /api/v1/categories/:id" do
    test "shows category", %{conn: conn} do
      {:ok, category} = Content.create_category(%{
        name: "Technology",
        slug: "technology",
        description: "Tech videos"
      })

      conn = get(conn, ~p"/api/v1/categories/#{category.id}")
      assert %{"data" => data} = json_response(conn, 200)
      assert data["id"] == to_string(category.id)
      assert data["name"] == "Technology"
      assert data["slug"] == "technology"
    end

    test "returns 404 for non-existent category", %{conn: conn} do
      fake_id = Ecto.UUID.generate()
      conn = get(conn, ~p"/api/v1/categories/#{fake_id}")
      assert %{"error" => "Category not found"} = json_response(conn, 404)
    end
  end

  describe "GET /api/v1/categories/slug/:slug" do
    test "shows category by slug", %{conn: conn} do
      {:ok, category} = Content.create_category(%{
        name: "Technology",
        slug: "technology"
      })

      conn = get(conn, ~p"/api/v1/categories/slug/technology")
      assert %{"data" => data} = json_response(conn, 200)
      assert data["id"] == to_string(category.id)
      assert data["slug"] == "technology"
    end

    test "returns 404 for non-existent slug", %{conn: conn} do
      conn = get(conn, ~p"/api/v1/categories/slug/nonexistent")
      assert %{"error" => "Category not found"} = json_response(conn, 404)
    end
  end

  describe "POST /api/v1/categories" do
    test "creates category when data is valid", %{conn: conn} do
      category_params = %{
        "category" => %{
          "name" => "New Category",
          "slug" => "new-category",
          "description" => "Category description"
        }
      }

      conn = post(conn, ~p"/api/v1/categories", category_params)
      assert %{"data" => data} = json_response(conn, 201)
      assert data["name"] == "New Category"
      assert data["slug"] == "new-category"
    end

    test "generates slug from name if not provided", %{conn: conn} do
      category_params = %{
        "category" => %{
          "name" => "Auto Slug Category"
        }
      }

      conn = post(conn, ~p"/api/v1/categories", category_params)
      assert %{"data" => data} = json_response(conn, 201)
      assert data["slug"] == "auto-slug-category"
    end

    test "returns error when data is invalid", %{conn: conn} do
      category_params = %{
        "category" => %{
          "name" => ""  # Invalid: empty name
        }
      }

      conn = post(conn, ~p"/api/v1/categories", category_params)
      assert %{"error" => "Validation failed"} = json_response(conn, 422)
    end

    test "requires authentication", %{conn: conn} do
      conn = build_conn()  # No auth token
      category_params = %{
        "category" => %{
          "name" => "New Category",
          "slug" => "new-category"
        }
      }

      conn = post(conn, ~p"/api/v1/categories", category_params)
      assert %{"error" => "Missing authorization token"} = json_response(conn, 401)
    end
  end

  describe "PUT /api/v1/categories/:id" do
    test "updates category when data is valid", %{conn: conn} do
      {:ok, category} = Content.create_category(%{
        name: "Original Name",
        slug: "original-name"
      })

      update_params = %{
        "category" => %{
          "name" => "Updated Name"
        }
      }

      conn = put(conn, ~p"/api/v1/categories/#{category.id}", update_params)
      assert %{"data" => data} = json_response(conn, 200)
      assert data["name"] == "Updated Name"
    end

    test "returns 404 for non-existent category", %{conn: conn} do
      fake_id = Ecto.UUID.generate()
      update_params = %{"category" => %{"name" => "Updated"}}

      conn = put(conn, ~p"/api/v1/categories/#{fake_id}", update_params)
      assert %{"error" => "Category not found"} = json_response(conn, 404)
    end

    test "requires authentication", %{conn: conn} do
      {:ok, category} = Content.create_category(%{
        name: "Test",
        slug: "test"
      })

      conn = build_conn()  # No auth token
      update_params = %{"category" => %{"name" => "Updated"}}

      conn = put(conn, ~p"/api/v1/categories/#{category.id}", update_params)
      assert %{"error" => "Missing authorization token"} = json_response(conn, 401)
    end
  end

  describe "DELETE /api/v1/categories/:id" do
    test "deletes category", %{conn: conn} do
      {:ok, category} = Content.create_category(%{
        name: "To Delete",
        slug: "to-delete"
      })

      conn = delete(conn, ~p"/api/v1/categories/#{category.id}")
      assert response(conn, 204)

      # Verify category is deleted
      assert_raise Ecto.NoResultsError, fn ->
        Content.get_category!(category.id)
      end
    end

    test "returns 404 for non-existent category", %{conn: conn} do
      fake_id = Ecto.UUID.generate()
      conn = delete(conn, ~p"/api/v1/categories/#{fake_id}")
      assert %{"error" => "Category not found"} = json_response(conn, 404)
    end

    test "requires authentication", %{conn: conn} do
      {:ok, category} = Content.create_category(%{
        name: "Test",
        slug: "test"
      })

      conn = build_conn()  # No auth token
      conn = delete(conn, ~p"/api/v1/categories/#{category.id}")
      assert %{"error" => "Missing authorization token"} = json_response(conn, 401)
    end
  end
end

