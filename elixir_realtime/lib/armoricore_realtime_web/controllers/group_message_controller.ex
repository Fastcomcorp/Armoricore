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

defmodule ArmoricoreRealtimeWeb.GroupMessageController do
  @moduledoc """
  Controller for group message operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Messaging

  @doc """
  List messages in a group chat (protected endpoint - members only).
  GET /api/v1/group-chats/:group_chat_id/messages
  """
  def index(conn, %{"group_chat_id" => group_chat_id} = params) do
    user_id = conn.assigns.current_user_id

    # SECURITY: Only members can view messages
    if Messaging.is_group_chat_member?(group_chat_id, user_id) do
      opts = parse_list_params(params)
      messages = Messaging.list_group_messages(group_chat_id, opts)
      json(conn, %{
        data: Enum.map(messages, &serialize_group_message/1),
        count: length(messages)
      })
    else
      conn
      |> put_status(:forbidden)
      |> json(%{error: "You don't have permission to view messages in this group chat"})
    end
  end

  @doc """
  Send a group message (protected endpoint - members only).
  POST /api/v1/group-chats/:group_chat_id/messages
  """
  def create(conn, %{"group_chat_id" => group_chat_id, "message" => message_params}) do
    user_id = conn.assigns.current_user_id

    # SECURITY: Only members can send messages
    if Messaging.is_group_chat_member?(group_chat_id, user_id) do
      message_params =
        message_params
        |> Map.put("group_chat_id", group_chat_id)
        |> Map.put("sender_id", user_id)

      case Messaging.send_group_message(message_params) do
        {:ok, message} ->
          message = Messaging.get_group_message!(message.id)
          conn
          |> put_status(:created)
          |> json(%{data: serialize_group_message(message)})

        {:error, %Ecto.Changeset{} = changeset} ->
          conn
          |> put_status(:unprocessable_entity)
          |> json(%{error: "Validation failed", errors: format_errors(changeset)})
      end
    else
      conn
      |> put_status(:forbidden)
      |> json(%{error: "You don't have permission to send messages in this group chat"})
    end
  end

  @doc """
  Update a group message (protected endpoint - sender only).
  PUT /api/v1/group-messages/:id
  """
  def update(conn, %{"id" => id, "message" => message_params}) do
    user_id = conn.assigns.current_user_id

    try do
      message = Messaging.get_group_message!(id)

      # SECURITY: Only sender can update
      if message.sender_id == user_id do
        case Messaging.update_group_message(message, message_params) do
          {:ok, message} ->
            message = Messaging.get_group_message!(message.id)
            json(conn, %{data: serialize_group_message(message)})

          {:error, %Ecto.Changeset{} = changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Validation failed", errors: format_errors(changeset)})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to update this message"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Message not found"})
    end
  end

  @doc """
  Delete a group message (protected endpoint - sender or admin).
  DELETE /api/v1/group-messages/:id
  """
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      message = Messaging.get_group_message!(id)

      # SECURITY: Sender or admin can delete
      user_role = Messaging.get_user_role_in_group_chat(message.group_chat_id, user_id)
      can_delete = message.sender_id == user_id || user_role == "admin"

      if can_delete do
        case Messaging.delete_group_message(message) do
          {:ok, _message} ->
            conn
            |> put_status(:no_content)
            |> json(%{})

          {:error, _changeset} ->
            conn
            |> put_status(:internal_server_error)
            |> json(%{error: "Failed to delete message"})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to delete this message"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Message not found"})
    end
  end

  @doc """
  Pin a group message (protected endpoint - admin/moderator only).
  POST /api/v1/group-messages/:id/pin
  """
  def pin(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      message = Messaging.get_group_message!(id)

      # SECURITY: Only admins and moderators can pin
      user_role = Messaging.get_user_role_in_group_chat(message.group_chat_id, user_id)
      if user_role in ["admin", "moderator"] do
        case Messaging.pin_group_message(id) do
          {:ok, message} ->
            message = Messaging.get_group_message!(message.id)
            json(conn, %{data: serialize_group_message(message)})

          {:error, :not_found} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Message not found"})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Only admins and moderators can pin messages"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Message not found"})
    end
  end

  @doc """
  Unpin a group message (protected endpoint - admin/moderator only).
  POST /api/v1/group-messages/:id/unpin
  """
  def unpin(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      message = Messaging.get_group_message!(id)

      # SECURITY: Only admins and moderators can unpin
      user_role = Messaging.get_user_role_in_group_chat(message.group_chat_id, user_id)
      if user_role in ["admin", "moderator"] do
        case Messaging.unpin_group_message(id) do
          {:ok, message} ->
            message = Messaging.get_group_message!(message.id)
            json(conn, %{data: serialize_group_message(message)})

          {:error, :not_found} ->
            conn
            |> put_status(:not_found)
            |> json(%{error: "Message not found"})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "Only admins and moderators can unpin messages"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Message not found"})
    end
  end

  @doc """
  Mark message as read (protected endpoint - members only).
  POST /api/v1/group-messages/:id/read
  """
  def mark_read(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    try do
      message = Messaging.get_group_message!(id)

      # SECURITY: Only members can mark as read
      if Messaging.is_group_chat_member?(message.group_chat_id, user_id) do
        case Messaging.mark_group_message_read(id, user_id) do
          {:ok, _receipt} ->
            json(conn, %{status: "read"})

          {:error, changeset} ->
            conn
            |> put_status(:unprocessable_entity)
            |> json(%{error: "Failed to mark as read", errors: format_errors(changeset)})
        end
      else
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to mark this message as read"})
      end
    rescue
      Ecto.NoResultsError ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Message not found"})
    end
  end

  @doc """
  Get unread message count for a group chat (protected endpoint).
  GET /api/v1/group-chats/:group_chat_id/unread-count
  """
  def unread_count(conn, %{"group_chat_id" => group_chat_id}) do
    user_id = conn.assigns.current_user_id
    count = Messaging.get_unread_group_message_count(group_chat_id, user_id)
    json(conn, %{unread_count: count})
  end

  # Helper functions

  defp parse_list_params(params) do
    [
      message_type: params["message_type"],
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

  defp parse_limit(nil), do: 50
  defp parse_limit(limit) when is_binary(limit), do: String.to_integer(limit)
  defp parse_limit(limit) when is_integer(limit), do: limit

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp serialize_group_message(message) do
    %{
      id: message.id,
      content: message.content,
      message_type: message.message_type,
      group_chat_id: message.group_chat_id,
      sender_id: message.sender_id,
      sender: serialize_user(message.sender),
      reply_to_id: message.reply_to_id,
      reply_to: if(message.reply_to, do: serialize_group_message(message.reply_to), else: nil),
      is_encrypted: message.is_encrypted,
      is_pinned: message.is_pinned,
      is_deleted: message.is_deleted,
      media: serialize_media(message.media),
      reactions: Enum.map(message.reactions || [], &serialize_reaction/1),
      created_at: message.inserted_at,
      updated_at: message.updated_at
    }
  end

  defp serialize_reaction(reaction) do
    %{
      id: reaction.id,
      emoji: reaction.emoji,
      user: serialize_user(reaction.user),
      created_at: reaction.inserted_at
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

