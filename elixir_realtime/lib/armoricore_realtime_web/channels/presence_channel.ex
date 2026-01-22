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

defmodule ArmoricoreRealtimeWeb.PresenceChannel do
  @moduledoc """
  Presence Channel for tracking user presence.
  
  Handles:
  - User online/offline status
  - Presence updates
  - Broadcasting presence changes
  """

  use ArmoricoreRealtimeWeb, :channel
  require Logger

  @impl true
  def join("presence:room:" <> room_id, payload, socket) do
    user_id_from_socket = socket.assigns.user_id
    user_id = payload["user_id"] || user_id_from_socket
    status = payload["status"] || "online"

    # SECURITY: Verify user_id matches socket (if provided)
    if user_id == user_id_from_socket do
      # SECURITY: Validate room_id format
      case validate_room_id(room_id) do
        {:ok, validated_room_id} ->
          # SECURITY: Authorize room access - check if user has permission
          case ArmoricoreRealtime.Rooms.user_has_access_to_room?(user_id, validated_room_id) do
            true ->
              Logger.info("User #{user_id} joining presence room #{validated_room_id}")

              # Track presence
              {:ok, _} = ArmoricoreRealtime.Presence.track(
                self(),
                "presence:room:#{validated_room_id}",
                user_id,
                %{
                  online_at: System.system_time(:second),
                  status: status,
                  user_id: user_id
                }
              )

              # Get current presence list
              presences = ArmoricoreRealtime.Presence.list("presence:room:#{validated_room_id}")

              # Push initial presence state
              push(socket, "presence_state", presences)

              {:ok, socket
                   |> assign(:room_id, validated_room_id)
                   |> assign(:user_id, user_id)}
            
            false ->
              Logger.warning("User #{user_id} denied access to presence room #{validated_room_id}")
              {:error, %{reason: "unauthorized"}}
          end
        
        {:error, reason} ->
          Logger.warning("Invalid room_id from user #{user_id}: #{inspect(reason)}")
          {:error, %{reason: "Invalid room identifier"}}
      end
    else
      Logger.warning("User ID mismatch in presence channel: socket=#{user_id_from_socket}, payload=#{user_id}")
      {:error, %{reason: "unauthorized"}}
    end
  end
  
  # SECURITY: Validate room ID format (same as chat channel)
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
  def handle_in("update_status", %{"status" => status}, socket) do
    user_id = socket.assigns.user_id
    room_id = socket.assigns.room_id

    Logger.info("User #{user_id} updating status to #{status} in room #{room_id}")

    # Update presence
    {:ok, _} = ArmoricoreRealtime.Presence.track(
      self(),
      "presence:room:#{room_id}",
      user_id,
      %{
        online_at: System.system_time(:second),
        status: status
      }
    )

    # Broadcast presence diff
    presences = ArmoricoreRealtime.Presence.list("presence:room:#{room_id}")
    broadcast(socket, "presence_diff", presences)

    {:reply, {:ok, %{status: status}}, socket}
  end

  @impl true
  def handle_in("ping", _payload, socket) do
    {:reply, {:ok, %{ping: "pong"}}, socket}
  end
end
