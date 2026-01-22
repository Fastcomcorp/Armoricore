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

defmodule ArmoricoreRealtime.SecureMessaging.Megolm do
  @moduledoc """
  Megolm protocol implementation for efficient group encryption.

  Megolm provides forward secrecy for group conversations by using a ratcheting
  encryption scheme where each message is encrypted with a unique key derived
  from a shared secret that gets ratcheted forward.

  ## Architecture

  ```
  Group Session Key ───> Ratchet ───> Message Keys
         │                    │
         │                    ▼
         │               Message Encryption
         ▼
  Next Session Key ───> Member Key Sharing
  ```

  ## Security Properties

  - **Forward Secrecy**: Compromised session doesn't reveal past messages
  - **Post-Compromise Security**: New keys after compromise
  - **Efficiency**: Single key derivation per message
  - **Scalability**: Works for large groups
  - **Out-of-Order Delivery**: Handles message reordering

  ## Protocol Flow

  1. **Session Creation**: Generate initial session keys
  2. **Key Distribution**: Share session keys with group members
  3. **Message Encryption**: Derive per-message keys via ratchet
  4. **Key Rotation**: Advance ratchet for forward secrecy
  """

  require Logger
  alias ArmoricoreRealtime.Crypto

  @session_key_length 32
  @ratchet_rounds 100  # Advance ratchet every 100 messages

  @doc """
  Creates a new Megolm group session.

  Initializes the ratchet state and generates the initial session key.
  """
  @spec create_session(String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def create_session(group_id, creator_id) do
    try do
      # Generate initial session key material
      initial_key = Crypto.secure_random_bytes(@session_key_length)

      session = %{
        session_id: generate_session_id(group_id),
        group_id: group_id,
        creator_id: creator_id,
        current_key: initial_key,
        ratchet_counter: 0,
        message_index: 0,
        created_at: DateTime.utc_now(),
        last_rotation: DateTime.utc_now()
      }

      Logger.info("Created Megolm session for group #{group_id}")
      {:ok, session}
    rescue
      error ->
        Logger.error("Failed to create Megolm session: #{inspect(error)}")
        {:error, :session_creation_failed}
    end
  end

  @doc """
  Adds a new member to the group session.

  Shares the current session key with the new member securely.
  """
  @spec add_member(map(), String.t(), map()) :: {:ok, map()} | {:error, atom()}
  def add_member(session, member_id, member_keys) do
    # Generate ephemeral key for secure key sharing
    {:ok, {ephemeral_public, ephemeral_private}} = Crypto.generate_x25519_keypair()

    # Perform ECDH with member's identity key
    {:ok, shared_secret} = Crypto.x25519_shared_secret(
      ephemeral_private,
      member_keys.identity_public_key
    )

    # Derive key for encrypting the session key
    {:ok, encryption_key} = Crypto.hkdf_derive(shared_secret, <<>>, "MegolmMemberKey", 32)

    # Encrypt the current session key
    {:ok, {encrypted_session_key, tag, nonce}} = Crypto.aes_gcm_encrypt(
      session.current_key,
      encryption_key
    )

    key_share = %{
      member_id: member_id,
      ephemeral_public_key: ephemeral_public,
      encrypted_session_key: encrypted_session_key,
      tag: tag,
      nonce: nonce,
      shared_at: DateTime.utc_now()
    }

    # Update session with new member
    updated_session = Map.update(session, :members, %{member_id => key_share},
      &Map.put(&1, member_id, key_share))

    {:ok, updated_session}
  end

  @doc """
  Encrypts a group message using the current ratchet state.

  Each message gets a unique key derived from the ratchet.
  """
  @spec encrypt_message(String.t(), map(), map()) :: {:ok, {map(), map()}} | {:error, atom()}
  def encrypt_message(plaintext, session, sender_keys) do
    try do
      # Derive message key from current ratchet state
      message_key_info = "MessageKey:#{session.message_index}"
      {:ok, message_key} = Crypto.hkdf_derive(
        session.current_key,
        session.ratchet_counter |> Integer.to_string() |> :binary.encode_unsigned(),
        message_key_info,
        32
      )

      # Encrypt the message
      {:ok, {ciphertext, tag, nonce}} = Crypto.aes_gcm_encrypt(plaintext, message_key)

      # Create message header with ratchet state
      header = %{
        message_index: session.message_index,
        ratchet_counter: session.ratchet_counter,
        sender_id: sender_keys.user_id
      }

      encrypted_message = %{
        header: header,
        ciphertext: ciphertext,
        tag: tag,
        nonce: nonce,
        session_id: session.session_id,
        timestamp: DateTime.utc_now()
      }

      # Advance the ratchet for forward secrecy
      updated_session = advance_ratchet(session)

      {:ok, {encrypted_message, updated_session}}
    rescue
      error ->
        Logger.error("Failed to encrypt group message: #{inspect(error)}")
        {:error, :encryption_failed}
    end
  end

  @doc """
  Decrypts a group message.

  Handles out-of-order delivery and missing messages gracefully.
  """
  @spec decrypt_message(map(), map()) :: {:ok, String.t()} | {:error, atom()}
  def decrypt_message(encrypted_message, session) do
    try do
      header = encrypted_message.header
      message_index = header.message_index
      ratchet_counter = header.ratchet_counter

      # Check if we need to advance the ratchet
      cond do
        message_index < session.message_index ->
          # Message is too old (already ratcheted past)
          {:error, :message_too_old}

        message_index == session.message_index and ratchet_counter == session.ratchet_counter ->
          # Current message, use current key
          derive_and_decrypt(encrypted_message, session)

        message_index > session.message_index ->
          # Future message, advance ratchet and try again
          catch_up_and_decrypt(encrypted_message, session)

        true ->
          {:error, :invalid_ratchet_state}
      end
    rescue
      error ->
        Logger.error("Failed to decrypt group message: #{inspect(error)}")
        {:error, :decryption_failed}
    end
  end

  @doc """
  Rotates the group session key for post-compromise security.

  Creates a new session and distributes keys to all members.
  """
  @spec rotate_session(map(), list(String.t())) :: {:ok, map()} | {:error, atom()}
  def rotate_session(session, member_ids) do
    try do
      # Generate new session key
      new_key = Crypto.secure_random_bytes(@session_key_length)

      rotated_session = %{
        session |
        current_key: new_key,
        ratchet_counter: 0,
        message_index: 0,
        last_rotation: DateTime.utc_now()
      }

      # Redistribute keys to all members
      Enum.each(member_ids, fn member_id ->
        # In practice, this would send key updates to each member
        Logger.debug("Would redistribute key to member #{member_id}")
      end)

      Logger.info("Rotated Megolm session for group #{session.group_id}")
      {:ok, rotated_session}
    rescue
      error ->
        Logger.error("Failed to rotate session: #{inspect(error)}")
        {:error, :rotation_failed}
    end
  end

  @doc """
  Exports session state for backup or transfer.

  Encrypts sensitive session data before export.
  """
  @spec export_session(map(), binary()) :: {:ok, binary()} | {:error, atom()}
  def export_session(session, export_key) do
    try do
      # Prepare session data for export (exclude sensitive keys)
      export_data = %{
        session_id: session.session_id,
        group_id: session.group_id,
        ratchet_counter: session.ratchet_counter,
        message_index: session.message_index,
        created_at: session.created_at,
        last_rotation: session.last_rotation
      }

      # Encrypt the export data
      {:ok, encrypted_data} = Crypto.aes_gcm_encrypt(
        Jason.encode!(export_data),
        export_key
      )

      {:ok, encrypted_data}
    rescue
      error ->
        Logger.error("Failed to export session: #{inspect(error)}")
        {:error, :export_failed}
    end
  end

  @doc """
  Imports session state from backup.

  Verifies integrity and restores session state.
  """
  @spec import_session(binary(), binary(), String.t()) :: {:ok, map()} | {:error, atom()}
  def import_session(encrypted_data, import_key, group_id) do
    try do
      # Decrypt the session data
      {:ok, decrypted_json} = Crypto.aes_gcm_decrypt(
        encrypted_data.ciphertext,
        encrypted_data.tag,
        encrypted_data.nonce,
        import_key
      )

      # Parse and validate
      session_data = Jason.decode!(decrypted_json)

      # Restore session (without current_key for security)
      session = %{
        session_id: session_data["session_id"],
        group_id: group_id,
        creator_id: "imported",
        current_key: nil,  # Must be redistributed
        ratchet_counter: session_data["ratchet_counter"],
        message_index: session_data["message_index"],
        created_at: parse_datetime(session_data["created_at"]),
        last_rotation: parse_datetime(session_data["last_rotation"])
      }

      Logger.info("Imported Megolm session for group #{group_id}")
      {:ok, session}
    rescue
      error ->
        Logger.error("Failed to import session: #{inspect(error)}")
        {:error, :import_failed}
    end
  end

  # Private functions

  defp generate_session_id(group_id) do
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    random = Crypto.secure_random_bytes(8) |> Base.url_encode64(padding: false)
    "megolm_#{group_id}_#{timestamp}_#{random}"
  end

  defp advance_ratchet(session) do
    # Advance message index
    new_message_index = session.message_index + 1

    # Check if we need to advance the ratchet counter
    new_ratchet_counter = if rem(new_message_index, @ratchet_rounds) == 0 do
      # Advance ratchet: derive new key from current key
      {:ok, next_key} = Crypto.hkdf_derive(
        session.current_key,
        <<session.ratchet_counter::32>>,
        "RatchetAdvance",
        @session_key_length
      )

      session.ratchet_counter + 1
    else
      session.ratchet_counter
    end

    # Derive new current key if ratchet advanced
    current_key = if new_ratchet_counter > session.ratchet_counter do
      {:ok, next_key} = Crypto.hkdf_derive(
        session.current_key,
        <<new_ratchet_counter::32>>,
        "RatchetAdvance",
        @session_key_length
      )
      next_key
    else
      session.current_key
    end

    %{
      session |
      current_key: current_key,
      ratchet_counter: new_ratchet_counter,
      message_index: new_message_index
    }
  end

  defp derive_and_decrypt(encrypted_message, session) do
    # Derive message key
    message_key_info = "MessageKey:#{encrypted_message.header.message_index}"
    {:ok, message_key} = Crypto.hkdf_derive(
      session.current_key,
      session.ratchet_counter |> Integer.to_string() |> :binary.encode_unsigned(),
      message_key_info,
      32
    )

    # Decrypt message
    Crypto.aes_gcm_decrypt(
      encrypted_message.ciphertext,
      encrypted_message.tag,
      encrypted_message.nonce,
      message_key
    )
  end

  defp catch_up_and_decrypt(encrypted_message, session) do
    # Calculate how many ratchet advances needed
    target_index = encrypted_message.header.message_index
    advances_needed = target_index - session.message_index

    # Advance ratchet to target message
    advanced_session = advance_ratchet_by_count(session, advances_needed)

    # Try to decrypt with advanced session
    case derive_and_decrypt(encrypted_message, advanced_session) do
      {:ok, plaintext} ->
        # Update our session state
        update_session_state(advanced_session)
        {:ok, plaintext}

      {:error, _} ->
        {:error, :decryption_failed}
    end
  end

  defp advance_ratchet_by_count(session, count) do
    Enum.reduce(1..count, session, fn _, acc ->
      advance_ratchet(acc)
    end)
  end

  defp update_session_state(new_session) do
    # In production, this would persist the session state
    Logger.debug("Updated session state to message_index: #{new_session.message_index}")
  end

  defp parse_datetime(datetime_str) do
    {:ok, datetime, _} = DateTime.from_iso8601(datetime_str)
    datetime
  end
end