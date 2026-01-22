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

defmodule ArmoricoreRealtimeWeb.CommentsChannel do
  @moduledoc """
  Live Comments Channel for streaming comments.
  
  Handles:
  - High-frequency comment broadcasting
  - Rate limiting
  - Stream-specific comments
  """

  use ArmoricoreRealtimeWeb, :channel
  require Logger

  alias ArmoricoreRealtime.Social
  alias ArmoricoreRealtime.Content

  @impl true
  def join("comments:stream:" <> stream_id, _payload, socket) do
    user_id = socket.assigns.user_id

    # SECURITY: Validate stream_id format to prevent injection
    case validate_stream_id(stream_id) do
      {:ok, validated_stream_id} ->
        # SECURITY: Authorize stream access - check if user has permission
        case ArmoricoreRealtime.Rooms.user_has_access_to_stream?(user_id, validated_stream_id) do
          true ->
            Logger.info("User #{user_id} joining comments for stream #{validated_stream_id}")

            {:ok, socket
                 |> assign(:stream_id, validated_stream_id)
                 |> assign(:user_id, user_id)
                 |> assign(:last_comment_time, 0)}
          
          false ->
            Logger.warning("User #{user_id} denied access to stream #{validated_stream_id}")
            {:error, %{reason: "unauthorized"}}
        end
      
      {:error, reason} ->
        Logger.warning("Invalid stream_id from user #{user_id}: #{inspect(reason)}")
        {:error, %{reason: "Invalid stream identifier"}}
    end
  end
  
  # SECURITY: Validate stream ID format (UUID or alphanumeric)
  defp validate_stream_id(stream_id) when is_binary(stream_id) do
    cond do
      byte_size(stream_id) == 0 ->
        {:error, :empty_stream_id}
      
      byte_size(stream_id) > 128 ->
        {:error, :stream_id_too_long}
      
      # Allow UUID format or alphanumeric with dashes/underscores
      String.match?(stream_id, ~r/^[a-zA-Z0-9_-]+$/) ->
        {:ok, stream_id}
      
      true ->
        {:error, :invalid_stream_id_format}
    end
  end
  
  defp validate_stream_id(_) do
    {:error, :invalid_stream_id_type}
  end

  @impl true
  def handle_in("new_comment", payload, socket) do
    user_id = socket.assigns.user_id
    stream_id = socket.assigns.stream_id

    # SECURITY: Validate payload structure and content
    case validate_comment_payload(payload) do
      {:ok, validated_payload} ->
        content = Map.get(validated_payload, "content")
        
        # Rate limiting: prevent spam (max 1 comment per second)
        current_time = System.system_time(:second)
        last_time = socket.assigns.last_comment_time

        if current_time - last_time < 1 do
          {:reply, {:error, %{reason: "rate_limit"}}, socket}
        else
          # Map stream_id to video_id
          # In production, you might have a streams table or use stream_id directly as video_id
          # For now, we'll try to parse stream_id as UUID (video_id)
          case Ecto.UUID.cast(stream_id) do
            {:ok, video_id} ->
              # Persist comment to database
              case Social.create_comment(%{
                user_id: user_id,
                video_id: video_id,
                content: content
              }) do
                {:ok, comment} ->
                  # Preload associations
                  comment = Social.get_comment!(comment.id)

                  # Create comment payload for broadcast
                  comment_payload = %{
                    "id" => comment.id,
                    "content" => comment.content,
                    "user_id" => comment.user_id,
                    "user" => serialize_user(comment.user),
                    "video_id" => comment.video_id,
                    "likes" => comment.likes,
                    "dislikes" => comment.dislikes,
                    "is_pinned" => comment.is_pinned,
                    "parent_id" => comment.parent_id,
                    "timestamp" => DateTime.to_unix(comment.inserted_at)
                  }

                  Logger.info("New comment from user #{user_id} on video #{video_id}")

                  # Broadcast to all subscribers
                  broadcast(socket, "new_comment", comment_payload)

                  # Publish to message bus for analytics/moderation
                  ArmoricoreRealtimeWeb.ChannelHelpers.publish_comment_event(comment_payload)

                  {:reply, {:ok, comment_payload}, assign(socket, :last_comment_time, current_time)}

                {:error, changeset} ->
                  Logger.error("Failed to create comment: #{inspect(changeset.errors)}")
                  {:reply, {:error, %{reason: "Failed to save comment"}}, socket}
              end

            :error ->
              # stream_id is not a valid UUID - reject the comment
              Logger.warning("Invalid video_id format from user #{user_id}: #{stream_id}")
              {:reply, {:error, %{reason: "Invalid video identifier"}}, socket}
          end
        end
      
      {:error, reason} ->
        Logger.warning("Invalid comment payload from user #{user_id}: #{inspect(reason)}")
        {:reply, {:error, %{reason: "Invalid comment format"}}, socket}
    end
  end
  
  # SECURITY: Validate comment payload structure and content
  defp validate_comment_payload(payload) when is_map(payload) do
    content = Map.get(payload, "content")
    
    cond do
      is_nil(content) ->
        {:error, :missing_content}
      
      not is_binary(content) ->
        {:error, :invalid_content_type}
      
      byte_size(content) == 0 ->
        {:error, :empty_content}
      
      byte_size(content) > 5_000 ->
        {:error, :content_too_long}
      
      true ->
        # Sanitize content
        sanitized_content = content
          |> String.trim()
          |> String.slice(0, 5_000)
        
        # Validate timestamp if provided
        timestamp = case Map.get(payload, "timestamp") do
          nil -> nil
          ts when is_integer(ts) -> ts
          _ -> nil
        end
        
        validated_payload = payload
          |> Map.put("content", sanitized_content)
          |> Map.put("timestamp", timestamp)
        
        {:ok, validated_payload}
    end
  end
  
  defp validate_comment_payload(_) do
    {:error, :invalid_payload_type}
  end

  @impl true
  def handle_in("like_comment", %{"comment_id" => comment_id}, socket) do
    user_id = socket.assigns.user_id

    case Social.like_comment(user_id, comment_id, "like") do
      {:ok, _result} ->
        # Get updated comment
        comment = Social.get_comment!(comment_id)
        comment_payload = serialize_comment(comment)
        
        # Broadcast update to all subscribers
        broadcast(socket, "comment_updated", comment_payload)
        {:reply, {:ok, comment_payload}, socket}

      {:error, reason} ->
        Logger.warning("Failed to like comment #{comment_id}: #{inspect(reason)}")
        {:reply, {:error, %{reason: "Failed to like comment"}}, socket}
    end
  end

  @impl true
  def handle_in("dislike_comment", %{"comment_id" => comment_id}, socket) do
    user_id = socket.assigns.user_id

    case Social.like_comment(user_id, comment_id, "dislike") do
      {:ok, _result} ->
        # Get updated comment
        comment = Social.get_comment!(comment_id)
        comment_payload = serialize_comment(comment)
        
        # Broadcast update to all subscribers
        broadcast(socket, "comment_updated", comment_payload)
        {:reply, {:ok, comment_payload}, socket}

      {:error, reason} ->
        Logger.warning("Failed to dislike comment #{comment_id}: #{inspect(reason)}")
        {:reply, {:error, %{reason: "Failed to dislike comment"}}, socket}
    end
  end

  @impl true
  def handle_in("ping", _payload, socket) do
    {:reply, {:ok, %{ping: "pong"}}, socket}
  end

  # Helper functions

  defp serialize_user(nil), do: nil
  defp serialize_user(user) do
    %{
      id: user.id,
      username: user.username,
      email: user.email
    }
  end

  defp serialize_comment(comment) do
    %{
      id: comment.id,
      content: comment.content,
      user_id: comment.user_id,
      user: serialize_user(comment.user),
      video_id: comment.video_id,
      likes: comment.likes,
      dislikes: comment.dislikes,
      is_pinned: comment.is_pinned,
      parent_id: comment.parent_id,
      timestamp: DateTime.to_unix(comment.inserted_at)
    }
  end
end
