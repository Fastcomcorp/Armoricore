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

defmodule ArmoricoreRealtimeWeb.E2EEChannel do
  @moduledoc """
  Channel for E2EE key exchange and management.
  
  Handles:
  - Public key exchange
  - Key rotation
  - Key revocation
  """

  use ArmoricoreRealtimeWeb, :channel

  def join("e2ee:" <> _room_id, _payload, socket) do
    {:ok, socket}
  end

  def handle_in("publish_key", %{"public_key" => public_key, "key_type" => key_type} = payload, socket) do
    user_id = socket.assigns.user_id
    channel_id = Map.get(payload, "channel_id")

    # Decode base64 public key if provided as string
    decoded_key = if is_binary(public_key) and String.contains?(public_key, "=") do
      try do
        Base.decode64!(public_key)
      rescue
        _ -> public_key
      end
    else
      public_key
    end

    case ArmoricoreRealtime.E2EE.store_public_key(user_id, decoded_key, channel_id, key_type) do
      {:ok, key} ->
        # Broadcast key update to channel members
        if channel_id do
          broadcast(socket, "key_updated", %{
            user_id: user_id,
            key_id: key.id,
            key_type: key_type,
            timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
          })
        end

        {:reply, {:ok, %{key_id: key.id}}, socket}

      {:error, _changeset} ->
        {:reply, {:error, %{reason: "Failed to store key"}}, socket}
    end
  end

  def handle_in("get_key", %{"user_id" => target_user_id} = payload, socket) do
    channel_id = Map.get(payload, "channel_id")

    case ArmoricoreRealtime.E2EE.get_public_key(target_user_id, channel_id) do
      {:ok, key} ->
        {:reply, {:ok, %{
          user_id: key.user_id,
          public_key: Base.encode64(key.public_key),
          key_type: key.key_type,
          inserted_at: key.inserted_at
        }}, socket}

      {:error, :not_found} ->
        {:reply, {:error, %{reason: "Key not found"}}, socket}
    end
  end

  def handle_in("get_channel_keys", %{"channel_id" => channel_id}, socket) do
    keys = ArmoricoreRealtime.E2EE.get_channel_keys(channel_id)

    encoded_keys =
      Enum.map(keys, fn key ->
        %{
          user_id: key.user_id,
          public_key: Base.encode64(key.public_key),
          key_type: key.key_type,
          inserted_at: key.inserted_at
        }
      end)

    {:reply, {:ok, %{keys: encoded_keys}}, socket}
  end

  def handle_in("revoke_key", payload, socket) do
    user_id = socket.assigns.user_id
    channel_id = Map.get(payload, "channel_id")

    ArmoricoreRealtime.E2EE.revoke_key(user_id, channel_id)

    if channel_id do
      broadcast(socket, "key_revoked", %{
        user_id: user_id,
        timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
      })
    end

    {:reply, :ok, socket}
  end
end
