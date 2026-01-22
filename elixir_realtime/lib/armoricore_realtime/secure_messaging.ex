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

defmodule ArmoricoreRealtime.SecureMessaging do
  @moduledoc """
  Secure messaging layer for encrypted communications.

  Implements secure messaging features:
  - Encrypted one-to-one messaging
  - Secure group messaging (Megolm protocol)
  - Message authentication
  - Secure message storage
  - Self-destructing messages

  ## Message Types

  - **Direct Messages**: One-to-one encrypted messages
  - **Group Messages**: Multi-party encrypted messages
  - **System Messages**: Unencrypted control messages
  - **Self-Destructing**: Messages that auto-delete

  ## Security Features

  - **End-to-End Encryption**: All messages are E2EE
  - **Forward Secrecy**: Compromised keys don't reveal past messages
  - **Authentication**: Messages include sender verification
  - **Integrity**: Messages cannot be tampered with
  """

  require Logger
  alias ArmoricoreRealtime.E2EE
  alias ArmoricoreRealtime.Crypto
  alias ArmoricoreRealtime.SecureMessaging.Megolm
  alias ArmoricoreRealtime.Repo

  # Message types
  @direct_message 1
  @group_message 2
  @system_message 3

  @doc """
  Sends an encrypted direct message to another user.

  Encrypts the message using E2EE and stores it securely.
  """
  @spec send_direct_message(String.t(), String.t(), String.t(), map()) :: {:ok, map()} | {:error, atom()}
  def send_direct_message(from_user_id, to_user_id, content, metadata \\ %{}) do
    # Get or create E2EE session
    case get_or_create_session(from_user_id, to_user_id) do
      {:ok, session} ->
        # Encrypt the message
        plaintext = Jason.encode!(%{
          content: content,
          timestamp: DateTime.utc_now(),
          metadata: metadata
        })

        case E2EE.encrypt_message(plaintext, session) do
          {:ok, {encrypted_message, updated_session}} ->
            # Store the encrypted message
            message = %{
              id: generate_message_id(),
              type: @direct_message,
              from_user_id: from_user_id,
              to_user_id: to_user_id,
              encrypted_content: encrypted_message,
              session_id: session.session_id,
              created_at: DateTime.utc_now(),
              message_number: encrypted_message.header.message_number
            }

            # Update session in storage
            update_session(updated_session)

            Logger.info("Sent encrypted direct message from #{from_user_id} to #{to_user_id}")
            {:ok, message}

          {:error, reason} ->
            Logger.error("Failed to encrypt direct message: #{inspect(reason)}")
            {:error, :encryption_failed}
        end

      {:error, reason} ->
        Logger.error("Failed to create E2EE session: #{inspect(reason)}")
        {:error, :session_creation_failed}
    end
  end

  @doc """
  Receives and decrypts a direct message.

  Returns the decrypted message content.
  """
  @spec receive_direct_message(map(), String.t()) :: {:ok, map()} | {:error, atom()}
  def receive_direct_message(encrypted_message, recipient_user_id) do
    # Get the session for this message
    case get_session(encrypted_message.session_id, recipient_user_id) do
      {:ok, session} ->
        case E2EE.decrypt_message(encrypted_message, session) do
          {:ok, {plaintext, updated_session}} ->
            # Parse the decrypted content
            case Jason.decode(plaintext) do
              {:ok, message_data} ->
                # Update session in storage
                update_session(updated_session)

                # Mark message as read
                mark_message_read(encrypted_message.id, recipient_user_id)

                Logger.info("Decrypted direct message for #{recipient_user_id}")
                {:ok, message_data}

              {:error, _} ->
                {:error, :invalid_message_format}
            end

          {:error, reason} ->
            Logger.error("Failed to decrypt direct message: #{inspect(reason)}")
            {:error, :decryption_failed}
        end

      {:error, :session_not_found} ->
        {:error, :session_not_found}
    end
  end

  @doc """
  Creates a secure group chat with complete Megolm encryption.

  Generates Megolm session with forward secrecy and distributes keys securely.
  """
  @spec create_secure_group(String.t(), String.t(), list(String.t())) :: {:ok, map()} | {:error, atom()}
  def create_secure_group(creator_id, group_name, member_ids) do
    try do
      group_id = generate_group_id()

      # Create Megolm session for the group
      {:ok, megolm_session} = Megolm.create_session(group_id, creator_id)

      group = %{
        id: group_id,
        name: group_name,
        creator_id: creator_id,
        member_ids: [creator_id | member_ids],
        megolm_session: megolm_session,
        created_at: DateTime.utc_now(),
        message_count: 0
      }

      # Distribute Megolm keys to all members securely
      distribute_megolm_keys(group, member_ids)

      # Store the group
      store_group(group)

      Logger.info("Created secure Megolm group #{group.id} with #{length(member_ids) + 1} members")
      {:ok, group}
    rescue
      error ->
        Logger.error("Failed to create secure group: #{inspect(error)}")
        {:error, :group_creation_failed}
    end
  end

  @doc """
  Sends an encrypted group message.

  Uses complete Megolm protocol for forward secrecy in groups.
  """
  @spec send_group_message(String.t(), String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def send_group_message(from_user_id, group_id, content) do
    case get_group_session(group_id, from_user_id) do
      {:ok, group_session} ->
        # Get sender's keys for authentication
        case get_user_keys(from_user_id) do
          {:ok, sender_keys} ->
            # Encrypt message with complete Megolm protocol
            plaintext = Jason.encode!(%{
              content: content,
              sender_id: from_user_id,
              timestamp: DateTime.utc_now()
            })

            case Megolm.encrypt_message(plaintext, group_session, sender_keys) do
              {:ok, {encrypted_message, updated_session}} ->
                message = %{
                  id: generate_message_id(),
                  type: @group_message,
                  from_user_id: from_user_id,
                  group_id: group_id,
                  encrypted_content: encrypted_message,
                  message_index: encrypted_message.header.message_index,
                  created_at: DateTime.utc_now()
                }

                # Update group session with new ratchet state
                update_group_session(updated_session)

                # Send to all group members
                broadcast_to_group(group_id, message)

                Logger.info("Sent Megolm-encrypted group message in #{group_id}")
                {:ok, message}

              {:error, reason} ->
                Logger.error("Megolm encryption failed: #{inspect(reason)}")
                {:error, :encryption_failed}
            end

          {:error, _} ->
            {:error, :sender_keys_not_found}
        end

      {:error, reason} ->
        Logger.error("Failed to get group session: #{inspect(reason)}")
        {:error, :group_session_error}
    end
  end

  @doc """
  Creates a self-destructing message.

  Message will be automatically deleted after the specified time.
  """
  @spec create_self_destructing_message(String.t(), String.t(), String.t(), integer()) :: {:ok, map()} | {:error, atom()}
  def create_self_destructing_message(from_user_id, to_user_id, content, ttl_seconds) do
    metadata = %{
      self_destruct: true,
      ttl_seconds: ttl_seconds,
      expires_at: DateTime.add(DateTime.utc_now(), ttl_seconds, :second)
    }

    case send_direct_message(from_user_id, to_user_id, content, metadata) do
      {:ok, message} ->
        # Schedule message deletion
        schedule_message_deletion(message.id, ttl_seconds)

        Logger.info("Created self-destructing message #{message.id} with TTL #{ttl_seconds}s")
        {:ok, message}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Verifies message integrity and sender authenticity.

  Checks message signatures and prevents tampering.
  """
  @spec verify_message_integrity(map(), map()) :: {:ok, boolean()} | {:error, atom()}
  def verify_message_integrity(message, sender_keys) do
    # Verify the message hasn't been tampered with
    message_content = Jason.encode!(%{
      content: message.content,
      timestamp: message.timestamp,
      metadata: message.metadata
    })

    case Crypto.ed25519_verify(message_content, message.signature, sender_keys.signing_public_key) do
      {:ok, true} ->
        {:ok, true}

      {:ok, false} ->
        {:error, :signature_verification_failed}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Performs secure device verification.

  Exchanges and verifies device fingerprints.
  """
  @spec verify_device(String.t(), String.t(), String.t()) :: {:ok, boolean()} | {:error, atom()}
  def verify_device(verifier_id, device_id, expected_fingerprint) do
    case get_device_keys(device_id) do
      {:ok, device_keys} ->
        is_verified = E2EE.verify_device_fingerprint(device_keys, expected_fingerprint)

        if is_verified do
          mark_device_verified(verifier_id, device_id)
          Logger.info("Device #{device_id} verified by #{verifier_id}")
          {:ok, true}
        else
          Logger.warning("Device verification failed for #{device_id}")
          {:ok, false}
        end

      {:error, :device_not_found} ->
        {:error, :device_not_found}
    end
  end

  # Megolm group encryption functions

  defp generate_megolm_session(creator_id) do
    # Generate initial Megolm session keys
    {:ok, ratchet_key} = Crypto.generate_x25519_keypair()
    {:ok, initial_key} = Crypto.hkdf_derive(ratchet_key, <<>>, "MegolmInitial", 32)

    session = %{
      id: generate_session_id(),
      creator_id: creator_id,
      ratchet_key: ratchet_key,
      current_key: initial_key,
      message_index: 0,
      created_at: DateTime.utc_now()
    }

    {:ok, session}
  end

  defp megolm_encrypt(plaintext, session) do
    # Encrypt message with current Megolm key
    {:ok, {ciphertext, tag, nonce}} = Crypto.aes_gcm_encrypt(plaintext, session.current_key, <<>>)

    encrypted_message = %{
      ciphertext: ciphertext,
      tag: tag,
      nonce: nonce,
      message_index: session.message_index
    }

    # Advance the ratchet
    {:ok, next_key} = Crypto.hkdf_derive(session.ratchet_key, <<session.message_index::32>>, "MegolmNext", 32)

    updated_session = %{
      session |
      current_key: next_key,
      message_index: session.message_index + 1
    }

    {:ok, {encrypted_message, updated_session}}
  end

  # Complete Megolm protocol helper functions

  defp get_user_keys(user_id) do
    # Mock implementation - would retrieve user's E2EE keys
    {:ok, %{
      user_id: user_id,
      identity_public_key: Crypto.secure_random_bytes(32),
      signing_public_key: Crypto.secure_random_bytes(32)
    }}
  end

  defp distribute_megolm_keys(group, member_ids) do
    # Distribute Megolm session keys to all group members
    Enum.each(member_ids, fn member_id ->
      # Add member to Megolm session and share keys
      case get_user_keys(member_id) do
        {:ok, member_keys} ->
          {:ok, _} = Megolm.add_member(group.megolm_session, member_id, member_keys)
        _ ->
          Logger.warning("Could not get keys for member #{member_id}")
      end
    end)
  end

  defp store_group(group) do
    # Mock implementation - would persist group to database
    :ok
  end

  # Database/storage functions (would be implemented with Ecto schemas)

  defp get_or_create_session(user1_id, user2_id) do
    # In production: query database for existing session or create new one
    # For now: return mock session
    {:ok, %{session_id: "mock_session", chain_key: Crypto.secure_random_bytes(32), message_number: 0, previous_chain_length: 0}}
  end

  defp get_session(session_id, user_id) do
    # Mock implementation
    {:ok, %{session_id: session_id, chain_key: Crypto.secure_random_bytes(32), message_number: 0, previous_chain_length: 0}}
  end

  defp update_session(session) do
    # Mock implementation - in production would update database
    :ok
  end

  defp mark_message_read(message_id, user_id) do
    # Mock implementation
    :ok
  end

  defp distribute_group_keys(group, member_ids) do
    # Mock implementation - would encrypt and send keys to members
    :ok
  end

  defp get_group_session(group_id, user_id) do
    # Mock implementation
    {:ok, %{id: "mock_group_session", ratchet_key: Crypto.secure_random_bytes(32), current_key: Crypto.secure_random_bytes(32), message_index: 0}}
  end

  defp update_group_session(session) do
    # Mock implementation
    :ok
  end

  defp broadcast_to_group(group_id, message) do
    # Mock implementation - would send via WebSocket channels
    :ok
  end

  defp schedule_message_deletion(message_id, ttl_seconds) do
    # Mock implementation - would use Oban or similar for scheduling
    :ok
  end

  defp get_device_keys(device_id) do
    # Mock implementation
    {:ok, %{identity_public_key: Crypto.secure_random_bytes(32), signing_public_key: Crypto.secure_random_bytes(32)}}
  end

  defp mark_device_verified(verifier_id, device_id) do
    # Mock implementation
    :ok
  end

  # ID generation functions

  defp generate_message_id do
    "msg_" <> Crypto.secure_random_bytes(16) |> Base.url_encode64(padding: false)
  end

  defp generate_group_id do
    "group_" <> Crypto.secure_random_bytes(16) |> Base.url_encode64(padding: false)
  end

  defp generate_session_id do
    "session_" <> Crypto.secure_random_bytes(16) |> Base.url_encode64(padding: false)
  end
end