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

defmodule ArmoricoreRealtimeWeb.GroupChatController do
  @moduledoc """
  Controller for group chat operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Messaging
  alias ArmoricoreRealtime.Repo

  @doc """
  List group chats for current user (protected endpoint).
  GET /api/v1/group-chats
  """
  def index(conn, params) do
    user_id = conn.assigns.current_user_id
    opts = parse_list_params(params)
    group_chats = Messaging.list_group_chats(user_id, opts)
    json(conn, %{
      data: Enum.map(group_chats, &serialize_group_chat/1),
      count: length(group_chats)
    })
  end

  @doc """
  Get a single group chat (protected endpoint - members only).
  GET /api/v1/group-chats/:id
  """
  def show(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      group_chat = Messaging.get_group_chat!(id)

      # SECURITY: Only members can view
      if Messaging.is_group_chat_member?(id, user_id) do
        json(conn, %{data: serialize_group_chat(group_chat)})
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to view this group chat"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Group chat not found"})
    end
  end

  @doc """
  Create a group chat (protected endpoint).
  POST /api/v1/group-chats
  """
  def create(conn, %{"group_chat" => group_chat_params}) do
    user_id = conn.assigns.current_user_id

    group_chat_params =
      group_chat_params
      |> Map.put("creator_id", user_id)

    case Messaging.create_group_chat(group_chat_params) do
      {:ok, group_chat} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_group_chat(group_chat)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  @doc """
  Update a group chat (protected endpoint - admin only).
  PUT /api/v1/group-chats/:id
  """
  def update(conn, %{"id" => id, "group_chat" => group_chat_params}) do
    user_id = conn.assigns.current_user_id

    try do
      group_chat = Messaging.get_group_chat!(id)

      # SECURITY: Only admins can update
      if Messaging.get_user_role_in_group_chat(id, user_id) == "admin" do
        case Messaging.update_group_chat(group_chat, group_chat_params) do
          {:ok, group_chat} ->
            group_chat = Messaging.get_group_chat!(group_chat.id)
            json(conn, %{data: serialize_group_chat(group_chat)})

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Validation failed", errors: format_errors(changeset)})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Only admins can update group chats"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Group chat not found"})
    end
  end

  @doc """
  Delete a group chat (protected endpoint - admin only).
  DELETE /api/v1/group-chats/:id
  """
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      group_chat = Messaging.get_group_chat!(id)

      # SECURITY: Only admins can delete
      if Messaging.get_user_role_in_group_chat(id, user_id) == "admin" do
        case Messaging.delete_group_chat(group_chat) do
          {:ok, _group_chat} ->
            conn
            |> put_status(:no_content)
            |> json(%{})

          {:error, _changeset} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to delete group chat"})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Only admins can delete group chats"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Group chat not found"})
    end
  end

  @doc """
  Add member to group chat (protected endpoint - admin/moderator only).
  POST /api/v1/group-chats/:id/members
  """
  def add_member(conn, %{"id" => id, "user_id" => member_user_id, "role" => role}) do
    user_id = conn.assigns.current_user_id

    # SECURITY: Only admins and moderators can add members
    user_role = Messaging.get_user_role_in_group_chat(id, user_id)
    if user_role in ["admin", "moderator"] do
      case Messaging.add_member_to_group_chat(id, member_user_id, role || "member") do
        {:ok, _member} ->
          group_chat = Messaging.get_group_chat!(id)
          json(conn, %{data: serialize_group_chat(group_chat)})

        {:error, changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "Failed to add member", errors: format_errors(changeset)})
      end
    else
      conn
      |> put_status(:forbidden)
      |> json(%{error: "Only admins and moderators can add members"})
    end
  end

  @doc """
  Remove member from group chat (protected endpoint - admin/moderator or self).
  DELETE /api/v1/group-chats/:id/members/:user_id
  """
  def remove_member(conn, %{"id" => id, "user_id" => member_user_id}) do
    user_id = conn.assigns.current_user_id

    # SECURITY: Admins/moderators can remove anyone, users can remove themselves
    user_role = Messaging.get_user_role_in_group_chat(id, user_id)
    can_remove = user_role in ["admin", "moderator"] || member_user_id == user_id

    if can_remove do
      case Messaging.remove_member_from_group_chat(id, member_user_id) do
        {:ok, _member} ->
          group_chat = Messaging.get_group_chat!(id)
          json(conn, %{data: serialize_group_chat(group_chat)})

        {:error, :not_found} ->
          conn
          |> put_status(:not_found)
          |> json(%{error: "Member not found"})
      end
    else
      conn
      |> put_status(:forbidden)
      |> json(%{error: "You don't have permission to remove this member"})
    end
  end

  # Helper functions

  defp parse_list_params(params) do
    [
      is_encrypted: parse_boolean(params["is_encrypted"]),
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

  defp serialize_group_chat(group_chat) do
    %{
      id: group_chat.id,
      name: group_chat.name,
      description: group_chat.description,
      is_encrypted: group_chat.is_encrypted,
      member_count: group_chat.member_count,
      creator: serialize_user(group_chat.creator),
      avatar: serialize_media(group_chat.avatar_media),
      members: Enum.map(group_chat.members || [], &serialize_member/1),
      created_at: group_chat.inserted_at,
      updated_at: group_chat.updated_at
    }
  end

  defp serialize_member(member) do
    %{
      id: member.id,
      user: serialize_user(member.user),
      role: member.role,
      joined_at: member.joined_at
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

  defp serialize_media(nil), do: nil
  defp serialize_media(media) do
    %{
      id: media.id,
      content_type: media.content_type,
      url: media.url
    }
  end
end

