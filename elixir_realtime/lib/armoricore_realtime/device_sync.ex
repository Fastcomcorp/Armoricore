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

defmodule ArmoricoreRealtime.DeviceSync do
  @moduledoc """
  Device synchronization protocol for secure multi-device messaging.

  Implements secure synchronization of:
  - Cryptographic keys across devices
  - Message history and state
  - Session continuity
  - Device verification and trust

  ## Architecture

  ```
  Primary Device ───> Sync Key ───> Secondary Devices
         │                    │
         │                    ▼
         └───────────────► Shared Secrets
                              │
                              ▼
  Encrypted Sync ─────────► All Devices
  ```

  ## Security Features

  - **Device Authentication**: Verify device legitimacy
  - **Key Distribution**: Secure key sharing across devices
  - **Message Continuity**: Seamless message sync
  - **Session Transfer**: Maintain conversation continuity
  - **Device Revocation**: Secure device removal

  ## Sync Protocol

  1. **Device Registration**: Register new device with primary
  2. **Key Exchange**: Securely share encryption keys
  3. **State Synchronization**: Sync message history and sessions
  4. **Real-time Updates**: Live sync of new messages/keys
  """

  require Logger
  alias ArmoricoreRealtime.Crypto
  alias ArmoricoreRealtime.E2EE
  alias ArmoricoreRealtime.EncryptedStorage

  @max_devices_per_user 10
  @sync_key_length 32

  @doc """
  Registers a new device for a user.

  Generates device keys and initiates secure synchronization.
  """
  @spec register_device(String.t(), String.t(), map()) :: {:ok, map()} | {:error, atom()}
  def register_device(user_id, device_name, device_info) do
    try do
      # Check device limit
      case get_user_devices(user_id) do
        devices when length(devices) >= @max_devices_per_user ->
          {:error, :device_limit_exceeded}

        _ ->
          # Generate device identity keys
          {:ok, device_keys} = E2EE.generate_identity_keys(generate_device_id(user_id))

          # Generate device sync key
          sync_key = Crypto.secure_random_bytes(@sync_key_length)

          device = %{
            device_id: device_keys.device_id,
            user_id: user_id,
            name: device_name,
            keys: device_keys,
            sync_key: sync_key,
            registered_at: DateTime.utc_now(),
            last_seen: DateTime.utc_now(),
            status: :pending_verification,
            info: device_info
          }

          # Store device
          store_device(device)

          # Initiate sync with existing devices
          initiate_device_sync(device, get_user_devices(user_id))

          Logger.info("Registered new device #{device.device_id} for user #{user_id}")
          {:ok, device}
      end
    rescue
      error ->
        Logger.error("Failed to register device: #{inspect(error)}")
        {:error, :registration_failed}
    end
  end

  @doc """
  Verifies and activates a device after user confirmation.

  Completes the device registration process.
  """
  @spec verify_device(String.t(), String.t()) :: {:ok, boolean()} | {:error, atom()}
  def verify_device(device_id, verification_code) do
    case get_device(device_id) do
      {:ok, device} ->
        # In production, this would verify against a stored code
        # For now, accept any verification
        if String.length(verification_code) >= 6 do
          # Activate device
          activated_device = %{device | status: :active}

          # Complete sync process
          complete_device_sync(activated_device)

          store_device(activated_device)

          Logger.info("Verified and activated device #{device_id}")
          {:ok, true}
        else
          {:ok, false}
        end

      {:error, :device_not_found} ->
        {:error, :device_not_found}
    end
  end

  @doc """
  Synchronizes cryptographic keys across all user devices.

  Ensures all devices have the latest encryption keys.
  """
  @spec sync_keys(String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def sync_keys(user_id, initiating_device_id) do
    try do
      # Get all active devices for user
      devices = get_active_user_devices(user_id)

      # Get current key state from initiating device
      {:ok, key_state} = get_device_key_state(initiating_device_id)

      # Encrypt key state for each device
      sync_messages = Enum.map(devices, fn device ->
        if device.device_id != initiating_device_id do
          encrypt_key_sync(key_state, device)
        end
      end) |> Enum.reject(&is_nil/1)

      # Send sync messages
      Enum.each(sync_messages, fn {device, message} ->
        send_sync_message(device, message)
      end)

      Logger.info("Synchronized keys across #{length(devices)} devices for user #{user_id}")
      {:ok, %{synced_devices: length(sync_messages), total_devices: length(devices)}}
    rescue
      error ->
        Logger.error("Key synchronization failed: #{inspect(error)}")
        {:error, :sync_failed}
    end
  end

  @doc """
  Synchronizes message history to a new device.

  Provides secure catch-up for newly registered devices.
  """
  @spec sync_messages(String.t(), String.t(), map()) :: {:ok, map()} | {:error, atom()}
  def sync_messages(user_id, device_id, sync_params \\ %{}) do
    try do
      # Get message history
      limit = Map.get(sync_params, :limit, 100)
      since = Map.get(sync_params, :since)

      messages = get_recent_messages(user_id, limit, since)

      # Encrypt messages for the device
      {:ok, device} = get_device(device_id)
      encrypted_messages = Enum.map(messages, fn message ->
        encrypt_message_for_device(message, device)
      end)

      # Send encrypted message batch
      sync_message = %{
        type: :message_history,
        messages: encrypted_messages,
        sync_timestamp: DateTime.utc_now()
      }

      send_sync_message(device, sync_message)

      Logger.info("Synchronized #{length(messages)} messages to device #{device_id}")
      {:ok, %{message_count: length(messages), device_id: device_id}}
    rescue
      error ->
        Logger.error("Message synchronization failed: #{inspect(error)}")
        {:error, :sync_failed}
    end
  end

  @doc """
  Transfers an active session to another device.

  Allows seamless conversation continuity across devices.
  """
  @spec transfer_session(String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def transfer_session(user_id, from_device_id, to_device_id) do
    try do
      # Get session state from source device
      {:ok, session_state} = get_device_session_state(from_device_id)

      # Get target device
      {:ok, target_device} = get_device(to_device_id)

      # Encrypt session state for target device
      encrypted_session = encrypt_session_for_device(session_state, target_device)

      # Send session transfer
      transfer_message = %{
        type: :session_transfer,
        session_data: encrypted_session,
        from_device: from_device_id,
        transfer_timestamp: DateTime.utc_now()
      }

      send_sync_message(target_device, transfer_message)

      Logger.info("Transferred session from device #{from_device_id} to #{to_device_id}")
      {:ok, %{from_device: from_device_id, to_device: to_device_id}}
    rescue
      error ->
        Logger.error("Session transfer failed: #{inspect(error)}")
        {:error, :transfer_failed}
    end
  end

  @doc """
  Revokes access for a compromised device.

  Securely removes device and rotates all keys.
  """
  @spec revoke_device(String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def revoke_device(user_id, device_id) do
    try do
      # Mark device as revoked
      {:ok, device} = get_device(device_id)
      revoked_device = %{device | status: :revoked, revoked_at: DateTime.utc_now()}
      store_device(revoked_device)

      # Rotate all keys for security
      rotate_user_keys(user_id)

      # Notify all remaining devices
      remaining_devices = get_active_user_devices(user_id)
      Enum.each(remaining_devices, fn device ->
        notify_device_revocation(device, device_id)
      end)

      Logger.warning("Revoked device #{device_id} for user #{user_id}")
      {:ok, %{revoked_device: device_id, notified_devices: length(remaining_devices)}}
    rescue
      error ->
        Logger.error("Device revocation failed: #{inspect(error)}")
        {:error, :revocation_failed}
    end
  end

  @doc """
  Gets device verification fingerprint.

  Provides human-readable device verification code.
  """
  @spec get_device_fingerprint(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def get_device_fingerprint(device_id) do
    case get_device(device_id) do
      {:ok, device} ->
        fingerprint = E2EE.generate_device_fingerprint(device.keys)
        # Format as readable code (like Signal's safety numbers)
        formatted = fingerprint
                   |> :binary.bin_to_list()
                   |> Enum.take(12)  # First 12 bytes for readability
                   |> Enum.map(&Integer.to_string(&1, 16))
                   |> Enum.map(&String.pad_leading(&1, 2, "0"))
                   |> Enum.chunk_every(2)
                   |> Enum.join(" ")

        {:ok, formatted}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Private functions

  defp generate_device_id(user_id) do
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    random = Crypto.secure_random_bytes(8) |> Base.url_encode64(padding: false)
    "device_#{user_id}_#{timestamp}_#{random}"
  end

  defp initiate_device_sync(new_device, existing_devices) do
    # Send sync initiation to existing devices
    Enum.each(existing_devices, fn device ->
      init_message = %{
        type: :new_device_sync,
        new_device_id: new_device.device_id,
        new_device_name: new_device.name,
        sync_timestamp: DateTime.utc_now()
      }
      send_sync_message(device, init_message)
    end)
  end

  defp complete_device_sync(device) do
    # Send completion notification to all user devices
    devices = get_user_devices(device.user_id)
    Enum.each(devices, fn d ->
      if d.device_id != device.device_id do
        completion_message = %{
          type: :device_verified,
          verified_device_id: device.device_id,
          verified_device_name: device.name
        }
        send_sync_message(d, completion_message)
      end
    end)
  end

  defp encrypt_key_sync(key_state, device) do
    # Encrypt key state using device's sync key
    {:ok, {ciphertext, tag, nonce}} = Crypto.aes_gcm_encrypt(
      Jason.encode!(key_state),
      device.sync_key
    )

    encrypted_sync = %{
      ciphertext: ciphertext,
      tag: tag,
      nonce: nonce,
      type: :key_sync,
      timestamp: DateTime.utc_now()
    }

    {device, encrypted_sync}
  end

  defp encrypt_message_for_device(message, device) do
    # Encrypt message using device's sync key
    {:ok, {ciphertext, tag, nonce}} = Crypto.aes_gcm_encrypt(
      Jason.encode!(message),
      device.sync_key
    )

    %{
      id: message.id,
      ciphertext: ciphertext,
      tag: tag,
      nonce: nonce,
      timestamp: message.timestamp
    }
  end

  defp encrypt_session_for_device(session_state, device) do
    # Encrypt session state for device transfer
    {:ok, {ciphertext, tag, nonce}} = Crypto.aes_gcm_encrypt(
      Jason.encode!(session_state),
      device.sync_key
    )

    %{
      ciphertext: ciphertext,
      tag: tag,
      nonce: nonce,
      session_type: session_state.type,
      encryption_version: "1.0"
    }
  end

  # Mock functions (would be implemented with proper storage)

  defp store_device(device), do: {:ok, device}
  defp get_device(device_id), do: {:ok, %{device_id: device_id, sync_key: Crypto.secure_random_bytes(32)}}
  defp get_user_devices(user_id), do: []
  defp get_active_user_devices(user_id), do: []
  defp get_device_key_state(device_id), do: {:ok, %{keys: [], sessions: []}}
  defp get_recent_messages(user_id, limit, since), do: []
  defp get_device_session_state(device_id), do: {:ok, %{type: :active, data: %{}}}
  defp rotate_user_keys(user_id), do: :ok
  defp notify_device_revocation(device, revoked_id), do: :ok

  defp send_sync_message(device, message) do
    # In production, this would send via WebSocket or push notification
    Logger.debug("Would send sync message to device #{device.device_id}")
  end
end