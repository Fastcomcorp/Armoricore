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

defmodule ArmoricoreRealtimeWeb.MediaChannel do
  @moduledoc """
  Media Channel for real-time media updates.
  
  Handles:
  - Media processing status updates
  - Media ready notifications
  - Transcription completion notifications
  """

  use ArmoricoreRealtimeWeb, :channel
  require Logger

  @impl true
  def join("media:" <> media_id, _payload, socket) do
    user_id = socket.assigns.user_id

    Logger.info("User #{user_id} joining media channel for media_id: #{media_id}")

    # Subscribe to PubSub topic for this media
    Phoenix.PubSub.subscribe(ArmoricoreRealtime.PubSub, "media:#{media_id}")
    Phoenix.PubSub.subscribe(ArmoricoreRealtime.PubSub, "user:#{user_id}")

    {:ok, socket
         |> assign(:media_id, media_id)
         |> assign(:user_id, user_id)}
  end

  @impl true
  def handle_info({:media_ready, event}, socket) do
    Logger.info("Media ready notification for media_id: #{socket.assigns.media_id}")
    
    # Push media_ready event to client
    push(socket, "media_ready", event["payload"])
    {:noreply, socket}
  end

  @impl true
  def handle_info({:transcription_complete, event}, socket) do
    Logger.info("Transcription complete notification for media_id: #{socket.assigns.media_id}")
    
    # Push transcription_complete event to client
    push(socket, "transcription_complete", event["payload"])
    {:noreply, socket}
  end

  @impl true
  def handle_info({:notification_sent, event}, socket) do
    Logger.info("Notification sent notification for user_id: #{socket.assigns.user_id}")
    
    # Push notification_sent event to client
    push(socket, "notification_sent", event["payload"])
    {:noreply, socket}
  end

  @impl true
  def handle_info(msg, socket) do
    Logger.debug("Received unhandled message: #{inspect(msg)}")
    {:noreply, socket}
  end

  @impl true
  def handle_in("ping", _payload, socket) do
    {:reply, {:ok, %{ping: "pong"}}, socket}
  end
end
