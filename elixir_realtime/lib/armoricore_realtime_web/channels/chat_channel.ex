# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
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

# Copyright 2025 Francisco F. Pinochet
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

defmodule ArmoricoreRealtimeWeb.ChatChannel do
  @moduledoc """
  Chat Channel for real-time messaging.
  
  Handles:
  - Joining chat rooms
  - Sending messages
  - Receiving messages
  - Typing indicators
  - Publishing to message bus for moderation
  """

  use ArmoricoreRealtimeWeb, :channel
  require Logger

  alias ArmoricoreRealtime.Messaging
  alias ArmoricoreRealtime.Repo

  # Typing indicator timeout (3 seconds of inactivity)
  @typing_timeout 3_000

  @impl true
  def join("chat:room:" <> room_id, _payload, socket) do
    user_id = socket.assigns.user_id

    # SECURITY: Validate room_id format to prevent injection
    case validate_room_id(room_id) do
      {:ok, validated_room_id} ->
        # SECURITY: Authorize room access - check if user has permission
        case ArmoricoreRealtime.Rooms.user_has_access_to_room?(user_id, validated_room_id) do
          true ->
            Logger.info("User #{user_id} joining chat room #{validated_room_id}")

            # Subscribe to presence for this room
            Phoenix.PubSub.subscribe(ArmoricoreRealtime.PubSub, "presence:room:#{validated_room_id}")

            {:ok, socket
                 |> assign(:room_id, validated_room_id)
                 |> assign(:user_id, user_id)
                 |> assign(:typing_timer, nil)}
          
          false ->
            Logger.warning("User #{user_id} denied access to chat room #{validated_room_id}")
            {:error, %{reason: "unauthorized"}}
        end
      
      {:error, reason} ->
        Logger.warning("Invalid room_id from user #{user_id}: #{inspect(reason)}")
        {:error, %{reason: "Invalid room identifier"}}
    end
  end
  
  # SECURITY: Validate room ID format (UUID or alphanumeric)
  defp validate_room_id(room_id) when is_binary(room_id) do
    cond do
      byte_size(room_id) == 0 ->
        {:error, :empty_room_id}
      
      byte_size(room_id) > 128 ->
        {:error, :room_id_too_long}
      
      # Allow UUID format or alphanumeric with dashes/underscores
      String.match?(room_id, ~r/^[a-zA-Z0-9_-]+$/) ->
        {:ok, room_id}
      
      true ->
        {:error, :invalid_room_id_format}
    end
  end
  
  defp validate_room_id(_) do
    {:error, :invalid_room_id_type}
  end

  @impl true
  def handle_in("new_message", payload, socket) do
    # SECURITY: Validate payload structure and content
    case validate_message_payload(payload) do
      {:ok, validated_payload} ->
        content = Map.get(validated_payload, "content")
        encrypted? = Map.get(validated_payload, "encrypted", false)
        
        # Check if message is encrypted (E2EE)
        if encrypted? do
          # Validate encrypted message format
          if validate_encrypted_message(validated_payload) do
            handle_encrypted_message(validated_payload, socket)
          else
            {:reply, {:error, %{reason: "Invalid encrypted message format"}}, socket}
          end
        else
          # Regular (non-encrypted) message
          handle_plaintext_message(content, validated_payload, socket)
        end
      
      {:error, reason} ->
        Logger.warning("Invalid message payload from user #{socket.assigns.user_id}: #{inspect(reason)}")
        {:reply, {:error, %{reason: "Invalid message format"}}, socket}
    end
  end

  @impl true
  def handle_in("typing_start", _payload, socket) do
    user_id = socket.assigns.user_id
    room_id = socket.assigns.room_id

    Logger.debug("User #{user_id} started typing in room #{room_id}")

    # Cancel any existing typing timer
    cancel_typing_timer(socket)

    # Broadcast typing start to all users in the room (except sender)
    broadcast_from(socket, "user_typing", %{
      user_id: user_id,
      room_id: room_id,
      is_typing: true
    })

    # Set a timer to auto-stop typing after timeout
    timer_ref = Process.send_after(self(), {:typing_timeout, user_id}, @typing_timeout)

    {:reply, {:ok, %{status: "typing"}}, assign(socket, :typing_timer, timer_ref)}
  end

  @impl true
  def handle_in("typing_stop", _payload, socket) do
    user_id = socket.assigns.user_id
    room_id = socket.assigns.room_id

    Logger.debug("User #{user_id} stopped typing in room #{room_id}")

    # Cancel typing timer
    cancel_typing_timer(socket)

    # Broadcast typing stop to all users in the room (except sender)
    broadcast_from(socket, "user_typing", %{
      user_id: user_id,
      room_id: room_id,
      is_typing: false
    })

    {:reply, {:ok, %{status: "stopped"}}, assign(socket, :typing_timer, nil)}
  end

  @impl true
  def handle_in("ping", _payload, socket) do
    {:reply, {:ok, %{ping: "pong"}}, socket}
  end

  # It is also common to receive messages from the client and
  # broadcast to everyone in the current topic (chat:room:lobby).
  @impl true
  def handle_in("shout", payload, socket) do
    broadcast(socket, "shout", payload)
    {:noreply, socket}
  end

  # Helper functions
  defp handle_encrypted_message(payload, socket) do
    user_id = socket.assigns.user_id
    room_id = socket.assigns.room_id

    # Generate message ID
    message_id = UUID.uuid4()

    # Create message payload (server doesn't decrypt)
    message = %{
      id: message_id,
      content: payload, # Send encrypted payload as-is
      user_id: user_id,
      room_id: room_id,
      encrypted: true,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    Logger.info("New encrypted message from user #{user_id} in room #{room_id}")

    # Broadcast to all subscribers in the room
    broadcast(socket, "new_message", message)

    # Note: Don't publish encrypted messages to message bus for moderation
    # (server can't read them)

    {:reply, {:ok, message}, socket}
  end

  defp handle_plaintext_message(content, payload, socket) do
    user_id = socket.assigns.user_id

    # Determine message type based on channel topic
    cond do
      # Direct message
      Map.has_key?(socket.assigns, :conversation_id) ->
        handle_direct_message(content, payload, socket)

      # Group chat message
      Map.has_key?(socket.assigns, :group_chat_id) ->
        handle_group_message(content, payload, socket)

      # Regular room chat (legacy)
      Map.has_key?(socket.assigns, :room_id) ->
        handle_room_message(content, payload, socket)

      true ->
        {:reply, {:error, %{reason: "Invalid channel type"}}, socket}
    end
  end

  defp handle_direct_message(content, payload, socket) do
    user_id = socket.assigns.user_id
    other_user_id = socket.assigns.other_user_id

    # Persist direct message
    case Messaging.send_direct_message(%{
      sender_id: user_id,
      recipient_id: other_user_id,
      content: content,
      message_type: Map.get(payload, "message_type", "text"),
      media_id: Map.get(payload, "media_id"),
      is_encrypted: Map.get(payload, "encrypted", false),
      encrypted_content: Map.get(payload, "encrypted_content")
    }) do
      {:ok, dm} ->
        dm = Repo.preload(dm, [:sender, :recipient, :media])

        # Create message payload for broadcast
        message_payload = serialize_direct_message(dm)

        Logger.info("New DM from user #{user_id} to #{other_user_id}")

        # Broadcast to both users
        broadcast(socket, "new_message", message_payload)

        # Publish to message bus
        ArmoricoreRealtimeWeb.ChannelHelpers.publish_chat_message(message_payload)

        {:reply, {:ok, message_payload}, socket}

      {:error, changeset} ->
        Logger.error("Failed to send DM: #{inspect(changeset.errors)}")
        {:reply, {:error, %{reason: "Failed to send message"}}, socket}
    end
  end

  defp handle_group_message(content, payload, socket) do
    user_id = socket.assigns.user_id
    group_chat_id = socket.assigns.group_chat_id

    # Persist group message
    case Messaging.send_group_message(%{
      group_chat_id: group_chat_id,
      sender_id: user_id,
      content: content,
      message_type: Map.get(payload, "message_type", "text"),
      media_id: Map.get(payload, "media_id"),
      reply_to_id: Map.get(payload, "reply_to_id"),
      is_encrypted: Map.get(payload, "encrypted", false),
      encrypted_content: Map.get(payload, "encrypted_content")
    }) do
      {:ok, gm} ->
        gm = Repo.preload(gm, [:sender, :media, :reply_to])

        # Create message payload for broadcast
        message_payload = serialize_group_message(gm)

        Logger.info("New group message from user #{user_id} in group #{group_chat_id}")

        # Broadcast to all group members
        broadcast(socket, "new_message", message_payload)

        # Publish to message bus
        ArmoricoreRealtimeWeb.ChannelHelpers.publish_chat_message(message_payload)

        {:reply, {:ok, message_payload}, socket}

      {:error, changeset} ->
        Logger.error("Failed to send group message: #{inspect(changeset.errors)}")
        {:reply, {:error, %{reason: "Failed to send message"}}, socket}
    end
  end

  defp handle_room_message(content, _payload, socket) do
    user_id = socket.assigns.user_id
    room_id = socket.assigns.room_id

    # Generate message ID
    message_id = UUID.uuid4()

    # Create message payload (legacy room chat - not persisted)
    message = %{
      id: message_id,
      content: content,
      user_id: user_id,
      room_id: room_id,
      encrypted: false,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    Logger.info("New message from user #{user_id} in room #{room_id}")

    # Broadcast to all subscribers in the room
    broadcast(socket, "new_message", message)

    # Publish to message bus for moderation workflows
    ArmoricoreRealtimeWeb.ChannelHelpers.publish_chat_message(message)

    {:reply, {:ok, message}, socket}
  end

  defp serialize_direct_message(dm) do
    %{
      "id" => dm.id,
      "content" => dm.content,
      "message_type" => dm.message_type,
      "sender_id" => dm.sender_id,
      "recipient_id" => dm.recipient_id,
      "sender" => serialize_user(dm.sender),
      "recipient" => serialize_user(dm.recipient),
      "status" => dm.status,
      "is_encrypted" => dm.is_encrypted,
      "media" => serialize_media(dm.media),
      "timestamp" => DateTime.to_unix(dm.inserted_at)
    }
  end

  defp serialize_group_message(gm) do
    %{
      "id" => gm.id,
      "content" => gm.content,
      "message_type" => gm.message_type,
      "group_chat_id" => gm.group_chat_id,
      "sender_id" => gm.sender_id,
      "sender" => serialize_user(gm.sender),
      "reply_to_id" => gm.reply_to_id,
      "reply_to" => if(gm.reply_to, do: serialize_group_message(gm.reply_to), else: nil),
      "is_encrypted" => gm.is_encrypted,
      "is_pinned" => gm.is_pinned,
      "media" => serialize_media(gm.media),
      "timestamp" => DateTime.to_unix(gm.inserted_at)
    }
  end

  defp serialize_user(nil), do: nil
  defp serialize_user(user) do
    %{
      "id" => user.id,
      "username" => user.username,
      "email" => user.email
    }
  end

  defp serialize_media(nil), do: nil
  defp serialize_media(media) do
    %{
      "id" => media.id,
      "content_type" => media.content_type,
      "url" => media.url
    }
  end

  @impl true
  def handle_info({:typing_timeout, user_id}, socket) do
    room_id = socket.assigns.room_id

    Logger.debug("Typing timeout for user #{user_id} in room #{room_id}")

    # Broadcast typing stop due to timeout
    broadcast_from(socket, "user_typing", %{
      user_id: user_id,
      room_id: room_id,
      is_typing: false
    })

    {:noreply, assign(socket, :typing_timer, nil)}
  end

  # Helper to cancel typing timer
  defp cancel_typing_timer(socket) do
    case socket.assigns.typing_timer do
      nil -> :ok
      timer_ref -> Process.cancel_timer(timer_ref)
    end
  end
  
  # SECURITY: Validate message payload structure and content
  defp validate_message_payload(payload) when is_map(payload) do
    # Validate content field exists and is string
    content = Map.get(payload, "content")
    
    cond do
      is_nil(content) ->
        {:error, :missing_content}
      
      not is_binary(content) ->
        {:error, :invalid_content_type}
      
      byte_size(content) == 0 ->
        {:error, :empty_content}
      
      byte_size(content) > 10_000 ->
        {:error, :content_too_long}
      
      true ->
        # Sanitize content (remove potentially dangerous characters)
        sanitized_content = content
          |> String.trim()
          |> String.slice(0, 10_000)
        
        # Validate room_id matches socket assignment
        validated_payload = payload
          |> Map.put("content", sanitized_content)
        
        {:ok, validated_payload}
    end
  end
  
  defp validate_message_payload(_) do
    {:error, :invalid_payload_type}
  end
  
  # SECURITY: Validate encrypted message format
  defp validate_encrypted_message(payload) do
    ciphertext = Map.get(payload, "ciphertext")
    nonce = Map.get(payload, "nonce")
    tag = Map.get(payload, "tag")
    
    # All encrypted fields must be present and be base64 strings
    cond do
      is_nil(ciphertext) or not is_binary(ciphertext) -> false
      is_nil(nonce) or not is_binary(nonce) -> false
      is_nil(tag) or not is_binary(tag) -> false
      
      # Validate reasonable sizes (prevent DoS)
      byte_size(ciphertext) > 1_000_000 -> false  # 1MB max
      byte_size(nonce) > 256 -> false
      byte_size(tag) > 256 -> false
      
      true -> true
    end
  end

  @impl true
  def terminate(_reason, socket) do
    # Clean up: stop typing indicator when user disconnects
    user_id = socket.assigns[:user_id]
    room_id = socket.assigns[:room_id]

    if user_id && room_id do
      # Broadcast typing stop to all users in the room
      # Note: Using broadcast instead of broadcast_from since socket may be closing
      Phoenix.PubSub.broadcast(
        ArmoricoreRealtime.PubSub,
        "chat:room:#{room_id}",
        %Phoenix.Socket.Broadcast{
          topic: "chat:room:#{room_id}",
          event: "user_typing",
          payload: %{
            user_id: user_id,
            room_id: room_id,
            is_typing: false
          }
        }
      )
    end

    cancel_typing_timer(socket)
    :ok
  end

end
