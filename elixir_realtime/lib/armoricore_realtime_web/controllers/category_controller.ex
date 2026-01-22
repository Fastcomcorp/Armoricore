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

defmodule ArmoricoreRealtimeWeb.CategoryController do
  @moduledoc """
  Controller for category CRUD operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Content

  @doc """
  List categories (public endpoint).
  GET /api/v1/categories
  """
  def index(conn, params) do
    opts = parse_list_params(params)
    categories = Content.list_categories(opts)
    json(conn, %{
      data: Enum.map(categories, &serialize_category/1),
      count: length(categories)
    })
  end

  @doc """
  Get a single category (public endpoint).
  GET /api/v1/categories/:id
  """
  def show(conn, %{"id" => id}) do
    try do
      category = Content.get_category!(id)
      json(conn, %{data: serialize_category(category)})
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Category not found"})
    end
  end

  @doc """
  Get category by slug (public endpoint).
  GET /api/v1/categories/slug/:slug
  """
  def show_by_slug(conn, %{"slug" => slug}) do
    case Content.get_category_by_slug(slug) do
      nil ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Category not found"})

      category ->
        json(conn, %{data: serialize_category(category)})
    end
  end

  @doc """
  Create a new category (protected endpoint - admin only in future).
  POST /api/v1/categories
  
  Accepts params either nested under "category" key or directly:
  - {"category": {"name": "...", "slug": "..."}}
  - {"name": "...", "slug": "..."}
  """
  def create(conn, %{"category" => category_params}) do
    do_create_category(conn, category_params)
  end

  def create(conn, params) when is_map(params) do
    # Handle direct params (not nested under "category")
    category_params = Map.drop(params, ["_format", "_utf8"])
    do_create_category(conn, category_params)
  end

  defp do_create_category(conn, category_params) do
    case Content.create_category(category_params) do
      {:ok, category} ->
        category = Content.get_category!(category.id)
        conn
        |> put_status(:created)
        |> json(%{data: serialize_category(category)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  @doc """
  Update a category (protected endpoint - admin only in future).
  PUT /api/v1/categories/:id
  """
  def update(conn, %{"id" => id, "category" => category_params}) do
    try do
      category = Content.get_category!(id)
      case Content.update_category(category, category_params) do
        {:ok, category} ->
          category = Content.get_category!(category.id)
          json(conn, %{data: serialize_category(category)})

        {:error, %Ecto.Changeset{} = changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "Validation failed", errors: format_errors(changeset)})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Category not found"})
    end
  end

  @doc """
  Delete a category (protected endpoint - admin only in future).
  DELETE /api/v1/categories/:id
  """
  def delete(conn, %{"id" => id}) do
    try do
      category = Content.get_category!(id)
      case Content.delete_category(category) do
        {:ok, _category} ->
          conn
          |> put_status(:no_content)
          |> json(%{})

        {:error, _changeset} ->
          conn
          |> put_status(:internal_server_error)
          |> json(%{error: "Failed to delete category"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Category not found"})
    end
  end

  # Helper functions

  defp parse_list_params(params) do
    [
      parent_id: params["parent_id"]
    ]
    |> Enum.filter(fn {_key, value} -> not is_nil(value) end)
  end

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp serialize_category(nil), do: nil
  defp serialize_category(category) do
    %{
      id: category.id,
      name: category.name,
      slug: category.slug,
      description: category.description,
      parent: if(category.parent, do: serialize_category(category.parent), else: nil),
      children: Enum.map(category.children || [], &serialize_category/1),
      created_at: category.inserted_at,
      updated_at: category.updated_at
    }
  end
end

