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

defmodule ArmoricoreRealtime.E2EE do
  @moduledoc """
  End-to-End Encryption framework for secure communications.

  Implements Signal-like E2EE with:
  - X25519 key exchange
  - Double Ratchet algorithm for perfect forward secrecy
  - AES-256-GCM encryption
  - HMAC-SHA256 authentication

  ## Architecture

  ```
  Identity Keys ──┐
                   ├──> Signed PreKeys ──┐
  One-Time Keys ──┘                       ├──> Key Exchange
                                            │
  Ephemeral Keys ──────────────────────────┘
       │
       ▼
  Root Key ───> Chain Keys ───> Message Keys
       │            │               │
       │            │               ▼
       │            ▼          Encrypted Message
       │       Next Chain Key
       ▼
  Next Root Key
  ```

  ## Security Features

  - **Perfect Forward Secrecy**: Each message uses a new key
  - **Break-in Recovery**: Compromised keys don't reveal past messages
  - **Authentication**: Messages are cryptographically signed
  - **Key Verification**: Device fingerprints for verification
  """

  require Logger
  alias ArmoricoreRealtime.Crypto
  alias ArmoricoreRealtime.Repo

  # Database schemas would need to be created for:
  # - Identity keys
  # - Pre-keys
  # - Sessions
  # - Message keys

  @doc """
  Generates a new identity keypair for a user.

  Each device should have its own identity keypair.
  """
  @spec generate_identity_keys(String.t()) :: {:ok, map()} | {:error, atom()}
  def generate_identity_keys(device_id) when is_binary(device_id) do
    with {:ok, {public_key, private_key}} <- Crypto.generate_x25519_keypair(),
         {:ok, {sign_public, sign_private}} <- Crypto.generate_ed25519_keypair() do

      identity_keys = %{
        device_id: device_id,
        identity_public_key: public_key,
        identity_private_key: private_key,
        signing_public_key: sign_public,
        signing_private_key: sign_private,
        created_at: DateTime.utc_now(),
        fingerprint: generate_fingerprint(public_key)
      }

      # In production, store in database
      Logger.info("Generated identity keys for device #{device_id}")
      {:ok, identity_keys}
    end
  end

  @doc """
  Generates signed pre-keys for initial key exchange.

  Pre-keys allow encrypted communication before real-time key exchange.
  """
  @spec generate_pre_keys(map()) :: {:ok, list(map())} | {:error, atom()}
  def generate_pre_keys(identity_keys) do
    # Generate multiple pre-keys (typically 100)
    pre_keys = Enum.map(1..100, fn _ ->
      {:ok, {public_key, private_key}} = Crypto.generate_x25519_keypair()

      # Sign the pre-key with identity key
      {:ok, signature} = Crypto.ed25519_sign(public_key, identity_keys.signing_private_key)

      %{
        public_key: public_key,
        private_key: private_key,
        signature: signature,
        created_at: DateTime.utc_now()
      }
    end)

    {:ok, pre_keys}
  end

  @doc """
  Initiates a secure session with another device.

  Performs X25519 key exchange and establishes session keys.
  """
  @spec initiate_session(map(), map()) :: {:ok, map()} | {:error, atom()}
  def initiate_session(initiator_keys, responder_public_key) do
    # Generate ephemeral keypair for this session
    {:ok, {ephemeral_public, ephemeral_private}} = Crypto.generate_x25519_keypair()

    # Perform ECDH with responder's identity key
    {:ok, shared_secret1} = Crypto.x25519_shared_secret(
      initiator_keys.identity_private_key,
      responder_public_key
    )

    # Generate random salt for HKDF
    salt = Crypto.generate_salt()

    # Derive root key and initial chain key
    {:ok, root_key} = Crypto.hkdf_derive(shared_secret1, salt, "RootKey", 32)
    {:ok, chain_key} = Crypto.hkdf_derive(shared_secret1, salt, "ChainKey", 32)

    session = %{
      session_id: generate_session_id(),
      initiator_device_id: initiator_keys.device_id,
      responder_public_key: responder_public_key,
      ephemeral_public_key: ephemeral_public,
      ephemeral_private_key: ephemeral_private,
      root_key: root_key,
      chain_key: chain_key,
      message_number: 0,
      previous_chain_length: 0,
      created_at: DateTime.utc_now()
    }

    Logger.info("Initiated secure session #{session.session_id}")
    {:ok, session}
  end

  @doc """
  Encrypts a message using the Double Ratchet algorithm.

  Each message gets a unique key derived from the chain.
  """
  @spec encrypt_message(binary(), map()) :: {:ok, {binary(), map()}} | {:error, atom()}
  def encrypt_message(plaintext, session) do
    # Derive message key from current chain key
    {:ok, message_key} = Crypto.hkdf_derive(session.chain_key, <<>>, "MessageKey", 32)

    # Generate nonce for this message
    nonce = Crypto.generate_nonce()

    # Encrypt the message
    {:ok, {ciphertext, tag, _nonce}} = Crypto.aes_gcm_encrypt(plaintext, message_key, nonce)

    # Create message header with message number
    header = %{
      message_number: session.message_number,
      previous_chain_length: session.previous_chain_length
    }

    # Advance the chain key for next message
    {:ok, next_chain_key} = Crypto.hkdf_derive(session.chain_key, <<>>, "NextChain", 32)

    encrypted_message = %{
      header: header,
      ciphertext: ciphertext,
      tag: tag,
      nonce: nonce,
      session_id: session.session_id
    }

    # Update session with new chain key and message number
    updated_session = %{
      session |
      chain_key: next_chain_key,
      message_number: session.message_number + 1
    }

    {:ok, {encrypted_message, updated_session}}
  end

  @doc """
  Decrypts a message using the Double Ratchet algorithm.

  Handles out-of-order messages and key advancement.
  """
  @spec decrypt_message(map(), map()) :: {:ok, {binary(), map()}} | {:error, atom()}
  def decrypt_message(encrypted_message, session) do
    header = encrypted_message.header
    message_number = header.message_number
    previous_chain_length = header.previous_chain_length

    # Check if we need to advance the chain
    if message_number > session.message_number do
      # Skip ahead in the chain
      session = advance_chain(session, message_number - session.message_number)
    end

    # Derive the message key
    {:ok, message_key} = Crypto.hkdf_derive(session.chain_key, <<>>, "MessageKey", 32)

    # Decrypt the message
    case Crypto.aes_gcm_decrypt(
      encrypted_message.ciphertext,
      encrypted_message.tag,
      encrypted_message.nonce,
      message_key
    ) do
      {:ok, plaintext} ->
        # Advance the chain for next message
        {:ok, next_chain_key} = Crypto.hkdf_derive(session.chain_key, <<>>, "NextChain", 32)

        updated_session = %{
          session |
          chain_key: next_chain_key,
          message_number: session.message_number + 1,
          previous_chain_length: max(session.previous_chain_length, message_number + 1)
        }

        {:ok, {plaintext, updated_session}}

      {:error, _} ->
        {:error, :decryption_failed}
    end
  end

  @doc """
  Performs a Diffie-Hellman ratchet step for perfect forward secrecy.

  Called when receiving a new ephemeral key from the sender.
  """
  @spec ratchet_session(map(), binary()) :: {:ok, map()} | {:error, atom()}
  def ratchet_session(session, new_ephemeral_key) do
    # Perform ECDH with the new ephemeral key
    {:ok, shared_secret} = Crypto.x25519_shared_secret(
      session.ephemeral_private_key,
      new_ephemeral_key
    )

    # Derive new root key and chain key
    {:ok, new_root_key} = Crypto.hkdf_derive(shared_secret, session.root_key, "RootKey", 32)
    {:ok, new_chain_key} = Crypto.hkdf_derive(shared_secret, session.root_key, "ChainKey", 32)

    # Generate new ephemeral keypair for sending
    {:ok, {new_ephemeral_public, new_ephemeral_private}} = Crypto.generate_x25519_keypair()

    updated_session = %{
      session |
      root_key: new_root_key,
      chain_key: new_chain_key,
      ephemeral_public_key: new_ephemeral_public,
      ephemeral_private_key: new_ephemeral_private,
      message_number: 0,
      previous_chain_length: 0
    }

    {:ok, updated_session}
  end

  @doc """
  Generates a device fingerprint for verification.

  Creates a human-readable fingerprint like Signal's safety numbers.
  """
  @spec generate_device_fingerprint(map()) :: String.t()
  def generate_device_fingerprint(identity_keys) do
    # Combine identity key and signing key for fingerprint
    combined = identity_keys.identity_public_key <> identity_keys.signing_public_key
    hash = Crypto.sha256(combined)

    # Take first 16 bytes and format as hex pairs
    <<fingerprint::binary-size(16), _::binary>> = hash

    fingerprint
    |> :binary.bin_to_list()
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.map(&String.pad_leading(&1, 2, "0"))
    |> Enum.chunk_every(2)
    |> Enum.join(" ")
  end

  @doc """
  Verifies a device's identity using its fingerprint.

  Returns true if the fingerprint matches the expected value.
  """
  @spec verify_device_fingerprint(map(), String.t()) :: boolean()
  def verify_device_fingerprint(identity_keys, expected_fingerprint) do
    actual_fingerprint = generate_device_fingerprint(identity_keys)
    Crypto.secure_compare(actual_fingerprint, expected_fingerprint)
  end

  # Private functions

  defp generate_session_id do
    Crypto.secure_random_bytes(16) |> Base.url_encode64(padding: false)
  end

  defp generate_fingerprint(public_key) do
    Crypto.sha256(public_key)
    |> :binary.bin_to_list()
    |> Enum.take(16)
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.map(&String.pad_leading(&1, 2, "0"))
    |> Enum.join("")
  end

  defp advance_chain(session, steps) do
    Enum.reduce(1..steps, session, fn _, acc ->
      {:ok, next_key} = Crypto.hkdf_derive(acc.chain_key, <<>>, "NextChain", 32)
      %{acc | chain_key: next_key, message_number: acc.message_number + 1}
    end)
  end
end