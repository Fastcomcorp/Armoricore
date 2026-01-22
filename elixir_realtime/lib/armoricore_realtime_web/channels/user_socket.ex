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

defmodule ArmoricoreRealtimeWeb.UserSocket do
  @moduledoc """
  Phoenix Socket for WebSocket connections with JWT authentication.
  """

  use Phoenix.Socket

  ## Channels
  channel "chat:*", ArmoricoreRealtimeWeb.ChatChannel
  channel "comments:*", ArmoricoreRealtimeWeb.CommentsChannel
  channel "presence:*", ArmoricoreRealtimeWeb.PresenceChannel
  channel "media:*", ArmoricoreRealtimeWeb.MediaChannel
  channel "signaling:*", ArmoricoreRealtimeWeb.SignalingChannel
  channel "e2ee:*", ArmoricoreRealtimeWeb.E2EEChannel

  # Socket params are passed from the client and can
  # be used to verify and authenticate a user. After
  # verification, you can put default assigns into
  # the socket that will be set for all channels, ie
  #
  #     {:ok, assign(socket, :user_id, verified_user_id)}
  #
  # To deny connection, return `:error`.
  #
  # See `Phoenix.Token` documentation for examples in
  # performing token verification on connect.
  @impl true
  def connect(%{"token" => token}, socket, _connect_info) do
    case ArmoricoreRealtime.JWT.validate_token(token) do
      {:ok, claims} ->
        user_id = ArmoricoreRealtime.JWT.get_user_id(claims)

        if user_id do
          {:ok, assign(socket, :user_id, user_id)}
        else
          {:error, %{reason: "invalid_token"}}
        end

      {:error, reason} ->
        {:error, %{reason: reason}}
    end
  end

  def connect(_params, _socket, _connect_info) do
    {:error, %{reason: "missing_token"}}
  end

  # Socket id's are topics that allow you to identify all sockets for a given user;
  # as such, allowing you to broadcast a message to all user's active sockets.
  #
  # Would be: `"user_socket:#{user.id}"`
  @impl true
  def id(socket), do: "user_socket:#{socket.assigns.user_id}"
end
