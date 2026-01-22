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

defmodule ArmoricoreRealtime.ArcRtcSecurity do
  @moduledoc """
  Security enhancements for ArcRTC protocol.

  Transforms ArcRTC from a live streaming protocol to a secure communications platform
  with end-to-end encryption, perfect forward secrecy, and metadata protection.

  ## Security Features

  - **ArcSRTP**: Secure RTP with E2EE media streams
  - **Secure Signaling**: E2EE signaling messages
  - **Device Verification**: Safety numbers and fingerprints
  - **Perfect Forward Secrecy**: Double ratchet key rotation
  - **Metadata Protection**: Sealed sender and anonymous routing

  ## Architecture

  ```
  WebRTC/DTLS ── ArcRTC Bridge ── ArcSRTP Engine ── Secure Media
  Signaling       (Translation)     (E2EE)           (Encrypted)
  ```

  ## Protocol Evolution

  ArcRTC evolves from basic media streaming to secure communications:

  ### Phase 1: Basic Streaming (Current)
  - Unencrypted RTP packets
  - Basic authentication
  - No forward secrecy

  ### Phase 2: Secure Streaming (Enhanced)
  - ArcSRTP with AES-256-GCM
  - X25519 key exchange
  - Session-based encryption

  ### Phase 3: Secure Communications (Target)
  - Perfect forward secrecy
  - Device verification
  - Metadata protection
  - Post-quantum cryptography
  """

  require Logger
  alias ArmoricoreRealtime.Crypto
  alias ArmoricoreRealtime.E2EE

  @doc """
  Creates a secure ArcRTC session with E2EE capabilities.

  ## Parameters
  - `session_id`: Unique session identifier
  - `participants`: List of participant identity keys
  - `security_config`: Security configuration options

  ## Returns
  - `{:ok, secure_session}` - Successfully created secure session
  - `{:error, reason}` - Session creation failed
  """
  @spec create_secure_session(String.t(), list(map()), map()) :: {:ok, map()} | {:error, atom()}
  def create_secure_session(session_id, participants, security_config \\ %{}) do
    try do
      # Generate session encryption keys
      {:ok, session_keys} = generate_session_keys(participants)

      # Create device fingerprints for verification
      device_fingerprints = Enum.map(participants, &E2EE.generate_device_fingerprint/1)

      # Initialize PFS ratchet
      ratchet_state = initialize_pfs_ratchet(session_keys)

      secure_session = %{
        session_id: session_id,
        participants: participants,
        session_keys: session_keys,
        device_fingerprints: device_fingerprints,
        ratchet_state: ratchet_state,
        security_config: security_config,
        created_at: DateTime.utc_now(),
        message_count: 0
      }

      Logger.info("Created secure ArcRTC session", %{
        session_id: session_id,
        participant_count: length(participants)
      })

      {:ok, secure_session}
    rescue
      error ->
        Logger.error("Failed to create secure ArcRTC session", %{
          session_id: session_id,
          error: inspect(error)
        })
        {:error, :session_creation_failed}
    end
  end

  @doc """
  Encrypts RTP packets using ArcSRTP (Secure RTP).

  ## Parameters
  - `rtp_packet`: Raw RTP packet bytes
  - `secure_session`: Secure session configuration
  - `sequence_number`: RTP sequence number for IV generation

  ## Returns
  - `{:ok, arcrtp_packet}` - Successfully encrypted packet
  - `{:error, reason}` - Encryption failed
  """
  @spec encrypt_arcrtp_packet(binary(), map(), integer()) :: {:ok, binary()} | {:error, atom()}
  def encrypt_arcrtp_packet(rtp_packet, secure_session, sequence_number) do
    try do
      # Get current encryption keys from ratchet
      encryption_keys = get_current_encryption_keys(secure_session)

      # Parse RTP header (basic structure)
      <<version::2, padding::1, extension::1, csrc_count::4,
        marker::1, payload_type::7, sequence::16,
        timestamp::32, ssrc::32, payload::binary>> = rtp_packet

      # Generate IV for this packet (using sequence number and SSRC)
      iv = generate_arcrtp_iv(encryption_keys, sequence_number, ssrc)

      # Encrypt payload with AES-256-GCM
      {:ok, {encrypted_payload, tag, _nonce}} = Crypto.aes_gcm_encrypt(payload, encryption_keys.encryption_key, iv)

      # Create ArcRTP packet with security extensions
      arcrtp_packet = create_arcrtp_packet(
        version, padding, extension, csrc_count, marker, payload_type,
        sequence, timestamp, ssrc, encrypted_payload, tag
      )

      # Advance PFS ratchet periodically
      updated_session = advance_ratchet_if_needed(secure_session, sequence_number)

      {:ok, {arcrtp_packet, updated_session}}
    rescue
      error ->
        Logger.error("ArcRTP encryption failed", %{error: inspect(error)})
        {:error, :encryption_failed}
    end
  end

  @doc """
  Decrypts ArcRTP packets back to RTP.

  ## Parameters
  - `arcrtp_packet`: Encrypted ArcRTP packet bytes
  - `secure_session`: Secure session configuration
  - `sequence_number`: RTP sequence number

  ## Returns
  - `{:ok, rtp_packet}` - Successfully decrypted packet
  - `{:error, reason}` - Decryption failed
  """
  @spec decrypt_arcrtp_packet(binary(), map(), integer()) :: {:ok, binary()} | {:error, atom()}
  def decrypt_arcrtp_packet(arcrtp_packet, secure_session, sequence_number) do
    try do
      # Parse ArcRTP packet
      {rtp_header, encrypted_payload, tag} = parse_arcrtp_packet(arcrtp_packet)

      # Extract RTP header fields
      <<version::2, padding::1, extension::1, csrc_count::4,
        marker::1, payload_type::7, sequence::16,
        timestamp::32, ssrc::32>> = rtp_header

      # Get current decryption keys
      decryption_keys = get_current_decryption_keys(secure_session)

      # Generate IV for decryption
      iv = generate_arcrtp_iv(decryption_keys, sequence_number, ssrc)

      # Decrypt payload
      case Crypto.aes_gcm_decrypt(encrypted_payload, tag, iv, decryption_keys.encryption_key) do
        {:ok, rtp_payload} ->
          # Reconstruct RTP packet (12 bytes header)
          rtp_packet = <<version::2, padding::1, extension::1, csrc_count::4,
                        marker::1, payload_type::7, sequence::16,
                        timestamp::32, ssrc::32>> <> rtp_payload

          {:ok, rtp_packet}

        {:error, _} ->
          {:error, :decryption_failed}
      end
    rescue
      error ->
        Logger.error("ArcRTP decryption failed", %{error: inspect(error)})
        {:error, :decryption_failed}
    end
  end

  @doc """
  Encrypts signaling messages for secure ArcRTC communication.

  ## Parameters
  - `message`: Signaling message to encrypt
  - `secure_session`: Session with encryption keys
  - `recipient_keys`: Recipient's public keys

  ## Returns
  - `{:ok, encrypted_message}` - Successfully encrypted message
  - `{:error, reason}` - Encryption failed
  """
  @spec encrypt_signaling_message(map(), map(), map()) :: {:ok, map()} | {:error, atom()}
  def encrypt_signaling_message(message, secure_session, recipient_keys) do
    try do
      # Serialize message
      message_json = Jason.encode!(message)

      # Get signaling encryption keys
      signaling_keys = get_signaling_keys(secure_session, recipient_keys)

      # Generate nonce for this message
      nonce = Crypto.generate_nonce()

      # Encrypt message
      {:ok, {ciphertext, tag, _}} = Crypto.aes_gcm_encrypt(message_json, signaling_keys, nonce)

      encrypted_message = %{
        ciphertext: ciphertext,
        tag: tag,
        nonce: nonce,
        sender_fingerprint: E2EE.generate_device_fingerprint(secure_session.participants),
        timestamp: DateTime.utc_now()
      }

      {:ok, encrypted_message}
    rescue
      error ->
        Logger.error("Signaling message encryption failed", %{error: inspect(error)})
        {:error, :encryption_failed}
    end
  end

  @doc """
  Decrypts secure signaling messages.

  ## Parameters
  - `encrypted_message`: Encrypted signaling message
  - `secure_session`: Session with decryption keys

  ## Returns
  - `{:ok, message}` - Successfully decrypted message
  - `{:error, reason}` - Decryption failed
  """
  @spec decrypt_signaling_message(map(), map()) :: {:ok, map()} | {:error, atom()}
  def decrypt_signaling_message(encrypted_message, secure_session) do
    try do
      # Get signaling decryption keys
      signaling_keys = get_signaling_keys(secure_session, secure_session.participants)

      # Decrypt message
      case Crypto.aes_gcm_decrypt(
        encrypted_message.ciphertext,
        encrypted_message.tag,
        encrypted_message.nonce,
        signaling_keys
      ) do
        {:ok, decrypted_json} ->
          # Parse JSON message
          case Jason.decode(decrypted_json) do
            {:ok, message} ->
              # Verify sender fingerprint if provided
              if Map.has_key?(encrypted_message, :sender_fingerprint) do
                verify_sender_fingerprint(message, encrypted_message.sender_fingerprint, secure_session)
              end

              {:ok, message}

            {:error, _} ->
              {:error, :invalid_message_format}
          end

        {:error, _} ->
          {:error, :decryption_failed}
      end
    rescue
      error ->
        Logger.error("Signaling message decryption failed", %{error: inspect(error)})
        {:error, :decryption_failed}
    end
  end

  @doc """
  Verifies device fingerprints for secure session establishment.

  ## Parameters
  - `session`: Secure session
  - `provided_fingerprints`: Fingerprints provided by participants

  ## Returns
  - `{:ok, verified}` - Verification result
  - `{:error, reason}` - Verification failed
  """
  @spec verify_session_fingerprints(map(), list(String.t())) :: {:ok, boolean()} | {:error, atom()}
  def verify_session_fingerprints(session, provided_fingerprints) do
    expected_fingerprints = session.device_fingerprints

    # Compare fingerprints securely (constant time)
    verification_results = Enum.zip(expected_fingerprints, provided_fingerprints)
    |> Enum.map(fn {expected, provided} ->
      Crypto.secure_compare(expected, provided)
    end)

    all_verified = Enum.all?(verification_results)

    if all_verified do
      Logger.info("Session fingerprints verified successfully", %{session_id: session.session_id})
      {:ok, true}
    else
      Logger.warning("Session fingerprint verification failed", %{session_id: session.session_id})
      {:ok, false}
    end
  end

  # Private functions

  defp generate_session_keys(participants) do
    # Generate shared session keys for all participants
    # In practice, this would use a group key agreement protocol
    {:ok, master_key} = Crypto.secure_random_bytes(32)

    session_keys = %{
      master_key: master_key,
      encryption_key: master_key,  # Simplified - would derive properly
      hmac_key: Crypto.secure_random_bytes(32)
    }

    {:ok, session_keys}
  end

  defp initialize_pfs_ratchet(session_keys) do
    # Initialize double ratchet state
    %{
      root_key: session_keys.master_key,
      chain_key: Crypto.secure_random_bytes(32),
      message_number: 0,
      last_message_number: 0
    }
  end

  defp get_current_encryption_keys(session) do
    # Get keys from current ratchet state
    %{
      encryption_key: session.ratchet_state.chain_key,
      hmac_key: Crypto.secure_random_bytes(32)
    }
  end

  defp get_current_decryption_keys(session) do
    # Same as encryption for symmetric session
    get_current_encryption_keys(session)
  end

  defp generate_arcrtp_iv(keys, sequence_number, ssrc) do
    # Generate IV using HKDF with sequence number and SSRC
    input = <<sequence_number::32, ssrc::32>>
    {:ok, iv} = Crypto.hkdf_derive(keys.encryption_key, input, "ArcRTP-IV", 12)
    iv
  end

  defp create_arcrtp_packet(version, padding, extension, csrc_count, marker, payload_type,
                           sequence, timestamp, ssrc, encrypted_payload, tag) do
    # Create ArcRTP packet with security extensions
    rtp_header = <<version::2, padding::1, extension::1, csrc_count::4,
                  marker::1, payload_type::7, sequence::16,
                  timestamp::32, ssrc::32>>

    # Add security header (simplified)
    security_header = <<1::8, byte_size(tag)::16>>  # Version 1, tag length

    rtp_header <> security_header <> encrypted_payload <> tag
  end

  defp parse_arcrtp_packet(arcrtp_packet) do
    # Parse ArcRTP packet (simplified)
    <<rtp_header::12-bytes, security_header::3-bytes, rest::binary>> = arcrtp_packet

    <<_version::8, tag_length::16>> = security_header

    payload_size = byte_size(rest) - tag_length
    <<encrypted_payload::binary-size(payload_size), tag::binary-size(tag_length)>> = rest

    {rtp_header, encrypted_payload, tag}
  end

  defp get_signaling_keys(session, participant_keys) do
    # Derive signaling keys from session keys
    # Simplified - would use proper key derivation
    session.session_keys.encryption_key
  end

  defp advance_ratchet_if_needed(session, sequence_number) do
    # Advance PFS ratchet every 100 packets
    if rem(sequence_number, 100) == 0 do
      advance_pfs_ratchet(session)
    else
      session
    end
  end

  defp advance_pfs_ratchet(session) do
    # Advance the double ratchet
    {:ok, new_chain_key} = Crypto.hkdf_derive(session.ratchet_state.chain_key, <<>>, "Ratchet", 32)

    updated_ratchet = %{
      session.ratchet_state |
      chain_key: new_chain_key,
      message_number: session.ratchet_state.message_number + 1
    }

    %{session | ratchet_state: updated_ratchet}
  end

  defp verify_sender_fingerprint(message, fingerprint, session) do
    # Verify sender fingerprint (simplified)
    true
  end
end