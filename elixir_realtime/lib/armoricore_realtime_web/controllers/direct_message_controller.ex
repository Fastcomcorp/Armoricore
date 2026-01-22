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

defmodule ArmoricoreRealtimeWeb.DirectMessageController do
  @moduledoc """
  Controller for direct message operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Messaging
  alias ArmoricoreRealtime.Repo

  @doc """
  Send a direct message (protected endpoint).
  POST /api/v1/direct-messages
  """
  def create(conn, %{"direct_message" => dm_params}) do
    user_id = conn.assigns.current_user_id

    dm_params =
      dm_params
      |> Map.put("sender_id", user_id)

    case Messaging.send_direct_message(dm_params) do
      {:ok, dm} ->
        dm = Repo.preload(dm, [:sender, :recipient, :media])
        conn
        |> put_status(:created)
        |> json(%{data: serialize_direct_message(dm)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  @doc """
  Get conversation between two users (protected endpoint).
  GET /api/v1/direct-messages/conversation/:user_id
  """
  def conversation(conn, %{"user_id" => other_user_id} = params) do
    user_id = conn.assigns.current_user_id
    opts = parse_list_params(params)
    messages = Messaging.get_conversation(user_id, other_user_id, opts)
    json(conn, %{
      data: Enum.map(messages, &serialize_direct_message/1),
      count: length(messages)
    })
  end

  @doc """
  List conversations for current user (protected endpoint).
  GET /api/v1/direct-messages/conversations
  """
  def conversations(conn, params) do
    user_id = conn.assigns.current_user_id
    opts = parse_list_params(params)
    conversations = Messaging.list_conversations(user_id, opts)
    json(conn, %{
      data: conversations,
      count: length(conversations)
    })
  end

  @doc """
  Mark message as read (protected endpoint).
  PUT /api/v1/direct-messages/:id/read
  """
  def mark_read(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case Messaging.mark_dm_read(id, user_id) do
      {:ok, dm} ->
        json(conn, %{data: serialize_direct_message(dm)})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Message not found"})

      {:error, :unauthorized} ->
        conn
        |> put_status(:forbidden)
        |> json(%{error: "You don't have permission to mark this message as read"})
    end
  end

  @doc """
  Get unread message count (protected endpoint).
  GET /api/v1/direct-messages/unread-count
  """
  def unread_count(conn, _params) do
    user_id = conn.assigns.current_user_id
    count = Messaging.get_unread_dm_count(user_id)
    json(conn, %{unread_count: count})
  end

  # Helper functions

  defp parse_list_params(params) do
    [
      status: params["status"],
      message_type: params["message_type"],
      page: parse_page(params["page"]),
      limit: parse_limit(params["limit"])
    ]
    |> Enum.filter(fn {_key, value} -> not is_nil(value) end)
  end

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

  defp serialize_direct_message(dm) do
    %{
      id: dm.id,
      content: dm.content,
      message_type: dm.message_type,
      sender_id: dm.sender_id,
      recipient_id: dm.recipient_id,
      sender: serialize_user(dm.sender),
      recipient: serialize_user(dm.recipient),
      status: dm.status,
      is_encrypted: dm.is_encrypted,
      media: serialize_media(dm.media),
      read_at: dm.read_at,
      created_at: dm.inserted_at,
      updated_at: dm.updated_at
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

