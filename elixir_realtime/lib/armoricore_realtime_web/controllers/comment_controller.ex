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

defmodule ArmoricoreRealtimeWeb.CommentController do
  @moduledoc """
  Controller for comment operations (REST API).
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Social

  @doc """
  List comments for a video (public endpoint).
  GET /api/v1/videos/:video_id/comments
  """
  def index(conn, %{"video_id" => video_id} = params) do
    opts = parse_list_params(params)
    comments = Social.list_comments(video_id, opts)
    json(conn, %{
      data: Enum.map(comments, &serialize_comment/1),
      count: length(comments)
    })
  end

  @doc """
  Get a single comment (public endpoint).
  GET /api/v1/comments/:id
  """
  def show(conn, %{"id" => id}) do
    try do
      comment = Social.get_comment!(id)
      json(conn, %{data: serialize_comment(comment)})
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Comment not found"})
    end
  end

  @doc """
  Create a comment (protected endpoint).
  POST /api/v1/videos/:video_id/comments
  """
  def create(conn, %{"video_id" => video_id, "comment" => comment_params}) do
    user_id = conn.assigns.current_user_id

    comment_params =
      comment_params
      |> Map.put("user_id", user_id)
      |> Map.put("video_id", video_id)

    case Social.create_comment(comment_params) do
      {:ok, comment} ->
        comment = Social.get_comment!(comment.id)
        conn
        |> put_status(:created)
        |> json(%{data: serialize_comment(comment)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  @doc """
  Update a comment (protected endpoint - owner only).
  PUT /api/v1/comments/:id
  """
  def update(conn, %{"id" => id, "comment" => comment_params}) do
    user_id = conn.assigns.current_user_id

    try do
      comment = Social.get_comment!(id)

      # SECURITY: Only comment owner can update
      if comment.user_id == user_id do
        case Social.update_comment(comment, comment_params) do
          {:ok, comment} ->
            comment = Social.get_comment!(comment.id)
            json(conn, %{data: serialize_comment(comment)})

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Validation failed", errors: format_errors(changeset)})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to update this comment"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Comment not found"})
    end
  end

  @doc """
  Delete a comment (protected endpoint - owner only).
  DELETE /api/v1/comments/:id
  """
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      comment = Social.get_comment!(id)

      # SECURITY: Only comment owner can delete
      if comment.user_id == user_id do
        case Social.delete_comment(comment) do
          {:ok, _comment} ->
            conn
            |> put_status(:no_content)
            |> json(%{})

          {:error, _changeset} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to delete comment"})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to delete this comment"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Comment not found"})
    end
  end

  @doc """
  Like a comment (protected endpoint).
  POST /api/v1/comments/:id/like
  """
  def like(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case Social.like_comment(user_id, id, "like") do
      {:ok, _result} ->
        comment = Social.get_comment!(id)
        json(conn, %{data: serialize_comment(comment)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to like comment", errors: format_errors(changeset)})
    end
  end

  @doc """
  Dislike a comment (protected endpoint).
  POST /api/v1/comments/:id/dislike
  """
  def dislike(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case Social.like_comment(user_id, id, "dislike") do
      {:ok, _result} ->
        comment = Social.get_comment!(id)
        json(conn, %{data: serialize_comment(comment)})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to dislike comment", errors: format_errors(changeset)})
    end
  end

  # Helper functions

  defp parse_list_params(params) do
    [
      parent_id: params["parent_id"],
      pinned_only: parse_boolean(params["pinned_only"]),
      page: parse_page(params["page"]),
      limit: parse_limit(params["limit"])
    ]
    |> Enum.filter(fn {_key, value} -> not is_nil(value) end)
  end

  defp parse_boolean(nil), do: nil
  defp parse_boolean("true"), do: true
  defp parse_boolean("false"), do: false
  defp parse_boolean(bool) when is_boolean(bool), do: bool
  defp parse_boolean(_), do: nil

  defp parse_page(nil), do: 1
  defp parse_page(page) when is_binary(page), do: String.to_integer(page)
  defp parse_page(page) when is_integer(page), do: page

  defp parse_limit(nil), do: 20
  defp parse_limit(limit) when is_binary(limit), do: String.to_integer(limit)
  defp parse_limit(limit) when is_integer(limit), do: limit

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp serialize_comment(comment) do
    %{
      id: comment.id,
      content: comment.content,
      likes: comment.likes,
      dislikes: comment.dislikes,
      is_pinned: comment.is_pinned,
      is_deleted: comment.is_deleted,
      parent_id: comment.parent_id,
      user: serialize_user(comment.user),
      video_id: comment.video_id,
      replies: Enum.map(comment.replies || [], &serialize_comment/1),
      created_at: comment.inserted_at,
      updated_at: comment.updated_at
    }
  end

  defp serialize_user(nil), do: nil
  defp serialize_user(user) do
    %{
      id: user.id,
      username: user.username,
      email: user.email
    }
  end
end

