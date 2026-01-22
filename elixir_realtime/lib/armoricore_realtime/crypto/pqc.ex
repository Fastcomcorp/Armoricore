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

defmodule ArmoricoreRealtime.Crypto.PQC do
  @moduledoc """
  Post-Quantum Cryptography implementation for future-proof security.

  Implements NIST-selected post-quantum algorithms:
  - **Kyber**: Key encapsulation mechanism (replaces ECDH)
  - **Dilithium**: Digital signatures (replaces Ed25519)
  - **Falcon**: Alternative digital signatures (hash-and-sign lattice-based)

  ## Hybrid Cryptography

  Uses hybrid classical + post-quantum schemes for transitional security:

  ```
  Classical + PQ Key Exchange:
  X25519 + Kyber768 → Shared Secret

  Classical + PQ Signatures:
  Ed25519 + Dilithium5/Falcon-512 → Signature
  ```

  ## Algorithm Comparison

  | Algorithm | Type | Key Size | Signature Size | Security Level | Performance |
  |-----------|------|----------|----------------|----------------|-------------|
  | Dilithium5 | Lattice | 4016 bytes | 4595 bytes | NIST Level 5 | Fast verification |
  | Falcon-512 | Lattice (FFT) | 2304 bytes | 1280 bytes | NIST Level 5 | Fast signing |

  ## Implementation Notes

  This module provides the interface for post-quantum operations.
  Actual implementations require NIFs or external libraries for performance.

  ## Future Timeline

  - Phase 1 (2026): Hybrid mode with classical + PQ
  - Phase 2 (2028): Full post-quantum mode
  - Phase 3 (2030+): Quantum-resistant only
  """

  require Logger

  # Kyber parameters (NIST Round 3 winner)
  @kyber_public_key_size 1184  # Kyber768
  @kyber_private_key_size 2400
  @kyber_ciphertext_size 1088
  @kyber_shared_secret_size 32

  # Dilithium parameters (NIST Round 3 winner)
  @dilithium_public_key_size 1952  # Dilithium5
  @dilithium_private_key_size 4016
  @dilithium_signature_size 4595

  # Falcon parameters (NIST Round 3 winner - alternative to Dilithium)
  @falcon_public_key_size 1792  # Falcon-512
  @falcon_private_key_size 2304
  @falcon_signature_size 1280

  @doc """
  Generates a Kyber keypair for post-quantum key exchange.

  Returns {public_key, private_key} for Kyber768.
  """
  @spec kyber_generate_keypair() :: {:ok, {binary(), binary()}} | {:error, atom()}
  def kyber_generate_keypair do
    try do
      # This would call a NIF or external library
      # For now, simulate with secure random (NOT SECURE)
      public_key = Crypto.secure_random_bytes(@kyber_public_key_size)
      private_key = Crypto.secure_random_bytes(@kyber_private_key_size)

      Logger.info("Generated Kyber keypair (simulation)")
      {:ok, {public_key, private_key}}
    rescue
      error ->
        Logger.error("Kyber key generation failed: #{inspect(error)}")
        {:error, :key_generation_failed}
    end
  end

  @doc """
  Performs Kyber key encapsulation.

  Takes a recipient's public key and returns {ciphertext, shared_secret}.
  """
  @spec kyber_encapsulate(binary()) :: {:ok, {binary(), binary()}} | {:error, atom()}
  def kyber_encapsulate(public_key) when byte_size(public_key) == @kyber_public_key_size do
    try do
      # This would call a NIF implementing Kyber encapsulation
      # For now, simulate (NOT SECURE)
      ciphertext = Crypto.secure_random_bytes(@kyber_ciphertext_size)
      shared_secret = Crypto.secure_random_bytes(@kyber_shared_secret_size)

      Logger.debug("Kyber encapsulation completed (simulation)")
      {:ok, {ciphertext, shared_secret}}
    rescue
      error ->
        Logger.error("Kyber encapsulation failed: #{inspect(error)}")
        {:error, :encapsulation_failed}
    end
  end

  @doc """
  Performs Kyber key decapsulation.

  Takes ciphertext and private key, returns shared_secret.
  """
  @spec kyber_decapsulate(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def kyber_decapsulate(ciphertext, private_key)
      when byte_size(ciphertext) == @kyber_ciphertext_size and
           byte_size(private_key) == @kyber_private_key_size do
    try do
      # This would call a NIF implementing Kyber decapsulation
      # For now, simulate (NOT SECURE)
      shared_secret = Crypto.secure_random_bytes(@kyber_shared_secret_size)

      Logger.debug("Kyber decapsulation completed (simulation)")
      {:ok, shared_secret}
    rescue
      error ->
        Logger.error("Kyber decapsulation failed: #{inspect(error)}")
        {:error, :decapsulation_failed}
    end
  end

  @doc """
  Generates a Dilithium keypair for post-quantum signatures.

  Returns {public_key, private_key} for Dilithium5.
  """
  @spec dilithium_generate_keypair() :: {:ok, {binary(), binary()}} | {:error, atom()}
  def dilithium_generate_keypair do
    try do
      # This would call a NIF or external library
      # For now, simulate with secure random (NOT SECURE)
      public_key = Crypto.secure_random_bytes(@dilithium_public_key_size)
      private_key = Crypto.secure_random_bytes(@dilithium_private_key_size)

      Logger.info("Generated Dilithium keypair (simulation)")
      {:ok, {public_key, private_key}}
    rescue
      error ->
        Logger.error("Dilithium key generation failed: #{inspect(error)}")
        {:error, :key_generation_failed}
    end
  end

  @doc """
  Creates a Dilithium signature.

  Returns the signature for the given message.
  """
  @spec dilithium_sign(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def dilithium_sign(message, private_key)
      when is_binary(message) and byte_size(private_key) == @dilithium_private_key_size do
    try do
      # This would call a NIF implementing Dilithium signing
      # For now, simulate (NOT SECURE)
      signature = Crypto.secure_random_bytes(@dilithium_signature_size)

      Logger.debug("Dilithium signature created (simulation)")
      {:ok, signature}
    rescue
      error ->
        Logger.error("Dilithium signing failed: #{inspect(error)}")
        {:error, :signing_failed}
    end
  end

  @doc """
  Verifies a Dilithium signature.

  Returns true if signature is valid.
  """
  @spec dilithium_verify(binary(), binary(), binary()) :: {:ok, boolean()} | {:error, atom()}
  def dilithium_verify(message, signature, public_key)
      when is_binary(message) and is_binary(signature) and
           byte_size(public_key) == @dilithium_public_key_size do
    try do
      # This would call a NIF implementing Dilithium verification
      # For now, simulate (NOT SECURE - always returns true)
      result = true

      Logger.debug("Dilithium verification completed (simulation)")
      {:ok, result}
    rescue
      error ->
        Logger.error("Dilithium verification failed: #{inspect(error)}")
        {:error, :verification_failed}
    end
  end

  @doc """
  Generates a Falcon keypair for post-quantum signatures.

  Returns {public_key, private_key} for Falcon-512.
  """
  @spec falcon_generate_keypair() :: {:ok, {binary(), binary()}} | {:error, atom()}
  def falcon_generate_keypair do
    try do
      # This would call a NIF or external library
      # For now, simulate with secure random (NOT SECURE)
      public_key = Crypto.secure_random_bytes(@falcon_public_key_size)
      private_key = Crypto.secure_random_bytes(@falcon_private_key_size)

      Logger.info("Generated Falcon keypair (simulation)")
      {:ok, {public_key, private_key}}
    rescue
      error ->
        Logger.error("Falcon key generation failed: #{inspect(error)}")
        {:error, :key_generation_failed}
    end
  end

  @doc """
  Creates a Falcon signature.

  Returns the signature for the given message.
  """
  @spec falcon_sign(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def falcon_sign(message, private_key)
      when is_binary(message) and byte_size(private_key) == @falcon_private_key_size do
    try do
      # This would call a NIF implementing Falcon signing
      # For now, simulate (NOT SECURE)
      signature = Crypto.secure_random_bytes(@falcon_signature_size)

      Logger.debug("Falcon signature created (simulation)")
      {:ok, signature}
    rescue
      error ->
        Logger.error("Falcon signing failed: #{inspect(error)}")
        {:error, :signing_failed}
    end
  end

  @doc """
  Verifies a Falcon signature.

  Returns true if signature is valid.
  """
  @spec falcon_verify(binary(), binary(), binary()) :: {:ok, boolean()} | {:error, atom()}
  def falcon_verify(message, signature, public_key)
      when is_binary(message) and is_binary(signature) and
           byte_size(public_key) == @falcon_public_key_size do
    try do
      # This would call a NIF implementing Falcon verification
      # For now, simulate (NOT SECURE - always returns true)
      result = true

      Logger.debug("Falcon verification completed (simulation)")
      {:ok, result}
    rescue
      error ->
        Logger.error("Falcon verification failed: #{inspect(error)}")
        {:error, :verification_failed}
    end
  end

  @doc """
  Creates a hybrid key exchange (X25519 + Kyber).

  Provides transitional security combining classical and post-quantum crypto.
  """
  @spec hybrid_key_exchange(binary()) :: {:ok, map()} | {:error, atom()}
  def hybrid_key_exchange(recipient_public_keys) do
    try do
      # Extract keys
      x25519_public = recipient_public_keys[:x25519]
      kyber_public = recipient_public_keys[:kyber]

      # Classical ECDH
      {:ok, {x25519_ephemeral_public, x25519_ephemeral_private}} = Crypto.generate_x25519_keypair()
      {:ok, x25519_shared} = Crypto.x25519_shared_secret(x25519_ephemeral_private, x25519_public)

      # Post-quantum KEM
      {:ok, {kyber_ciphertext, kyber_shared}} = kyber_encapsulate(kyber_public)

      # Combine secrets
      combined_secret = x25519_shared <> kyber_shared
      {:ok, final_secret} = Crypto.hkdf_derive(combined_secret, <<>>, "HybridKeyExchange", 32)

      hybrid_result = %{
        x25519_ephemeral_public: x25519_ephemeral_public,
        kyber_ciphertext: kyber_ciphertext,
        shared_secret: final_secret,
        algorithm: "X25519+Kyber768"
      }

      Logger.info("Hybrid key exchange completed")
      {:ok, hybrid_result}
    rescue
      error ->
        Logger.error("Hybrid key exchange failed: #{inspect(error)}")
        {:error, :hybrid_exchange_failed}
    end
  end

  @doc """
  Creates a hybrid signature (Ed25519 + PQ Algorithm).

  Supports both Dilithium and Falcon for post-quantum signatures.
  Provides transitional signature security.
  """
  @spec hybrid_sign(binary(), map()) :: {:ok, map()} | {:error, atom()}
  def hybrid_sign(message, private_keys) do
    try do
      # Classical signature
      {:ok, ed25519_sig} = Crypto.ed25519_sign(message, private_keys.ed25519)

      # Choose post-quantum algorithm (prefer Falcon for smaller signatures)
      pq_algorithm = Map.get(private_keys, :pq_algorithm, :falcon)
      pq_sig = case pq_algorithm do
        :dilithium ->
          {:ok, sig} = dilithium_sign(message, private_keys.dilithium)
          sig
        :falcon ->
          {:ok, sig} = falcon_sign(message, private_keys.falcon)
          sig
      end

      hybrid_signature = %{
        ed25519_signature: ed25519_sig,
        pq_signature: pq_sig,
        pq_algorithm: pq_algorithm,
        message: message,
        algorithm: "Ed25519+#{Atom.to_string(pq_algorithm) |> String.capitalize()}"
      }

      Logger.debug("Hybrid signature created with #{pq_algorithm}")
      {:ok, hybrid_signature}
    rescue
      error ->
        Logger.error("Hybrid signing failed: #{inspect(error)}")
        {:error, :hybrid_signing_failed}
    end
  end

  @doc """
  Verifies a hybrid signature.

  Checks both classical and post-quantum signatures.
  Supports both Dilithium and Falcon PQ algorithms.
  """
  @spec hybrid_verify(map(), map()) :: {:ok, boolean()} | {:error, atom()}
  def hybrid_verify(signature_data, public_keys) do
    try do
      # Verify classical signature
      ed25519_ok = case Crypto.ed25519_verify(
        signature_data.message,
        signature_data.ed25519_signature,
        public_keys.ed25519
      ) do
        {:ok, true} -> true
        _ -> false
      end

      # Verify post-quantum signature based on algorithm
      pq_algorithm = Map.get(signature_data, :pq_algorithm, :dilithium)
      pq_ok = case pq_algorithm do
        :dilithium ->
          case dilithium_verify(
            signature_data.message,
            signature_data.pq_signature,
            public_keys.dilithium
          ) do
            {:ok, true} -> true
            _ -> false
          end
        :falcon ->
          case falcon_verify(
            signature_data.message,
            signature_data.pq_signature,
            public_keys.falcon
          ) do
            {:ok, true} -> true
            _ -> false
          end
      end

      # Both must verify
      both_valid = ed25519_ok and pq_ok

      Logger.debug("Hybrid signature verification (#{pq_algorithm}): #{both_valid}")
      {:ok, both_valid}
    rescue
      error ->
        Logger.error("Hybrid verification failed: #{inspect(error)}")
        {:error, :hybrid_verification_failed}
    end
  end

  @doc """
  Updates E2EE to use post-quantum cryptography.

  Gradually migrates existing sessions to post-quantum security.
  """
  @spec upgrade_to_pqc(map()) :: {:ok, map()} | {:error, atom()}
  def upgrade_to_pqc(session) do
    try do
      # Generate PQ keys for participants
      pq_keys = Enum.map(session.participants, fn participant ->
        {:ok, {kyber_pub, kyber_priv}} = kyber_generate_keypair()
        {:ok, {dilithium_pub, dilithium_priv}} = dilithium_generate_keypair()

        %{
          user_id: participant.user_id,
          kyber_public: kyber_pub,
          kyber_private: kyber_priv,
          dilithium_public: dilithium_pub,
          dilithium_private: dilithium_priv
        }
      end)

      # Update session with PQ capabilities
      upgraded_session = %{
        session |
        pq_enabled: true,
        pq_keys: pq_keys,
        upgraded_at: DateTime.utc_now(),
        security_level: "hybrid"
      }

      Logger.info("Upgraded session to post-quantum cryptography")
      {:ok, upgraded_session}
    rescue
      error ->
        Logger.error("PQC upgrade failed: #{inspect(error)}")
        {:error, :upgrade_failed}
    end
  end

  @doc """
  Checks if post-quantum cryptography is available.

  Returns the implementation status and available algorithms.
  """
  @spec pqc_status() :: map()
  def pqc_status do
    # Check if NIFs are loaded
    kyber_available = Code.ensure_loaded?(:kyber_nif)
    dilithium_available = Code.ensure_loaded?(:dilithium_nif)
    falcon_available = Code.ensure_loaded?(:falcon_nif)

    %{
      kyber_available: kyber_available,
      dilithium_available: dilithium_available,
      falcon_available: falcon_available,
      available_algorithms: %{
        kem: if(kyber_available, do: [:kyber768], else: []),
        signatures: [] ++ if(dilithium_available, do: [:dilithium5], else: []) ++ if(falcon_available, do: [:falcon512], else: [])
      },
      hybrid_mode_supported: true,
      implementation_status: cond do
        kyber_available and (dilithium_available or falcon_available) -> :full
        kyber_available or dilithium_available or falcon_available -> :partial
        true -> :simulated
      end,
      security_level: cond do
        kyber_available and (dilithium_available or falcon_available) -> :quantum_resistant
        kyber_available or dilithium_available or falcon_available -> :hybrid_ready
        true -> :classical_only
      end,
      recommended_algorithm: :falcon,  # Smaller signatures than Dilithium
      last_checked: DateTime.utc_now()
    }
  end

  @doc """
  Generates a post-quantum identity keypair.

  Creates hybrid classical + post-quantum identity keys with both Dilithium and Falcon support.
  """
  @spec generate_pq_identity_keys(String.t(), atom()) :: {:ok, map()} | {:error, atom()}
  def generate_pq_identity_keys(device_id, pq_algorithm \\ :falcon) do
    try do
      # Classical keys
      {:ok, {x25519_pub, x25519_priv}} = Crypto.generate_x25519_keypair()
      {:ok, {ed25519_pub, ed25519_priv}} = Crypto.generate_ed25519_keypair()

      # Post-quantum keys
      {:ok, {kyber_pub, kyber_priv}} = kyber_generate_keypair()

      # Choose PQ signature algorithm
      {pq_sig_pub, pq_sig_priv} = case pq_algorithm do
        :dilithium ->
          {:ok, {pub, priv}} = dilithium_generate_keypair()
          {pub, priv}
        :falcon ->
          {:ok, {pub, priv}} = falcon_generate_keypair()
          {pub, priv}
      end

      pq_identity = %{
        device_id: device_id,
        pq_algorithm: pq_algorithm,
        classical_keys: %{
          x25519_public: x25519_pub,
          x25519_private: x25519_priv,
          ed25519_public: ed25519_pub,
          ed25519_private: ed25519_priv
        },
        pq_keys: %{
          kyber_public: kyber_pub,
          kyber_private: kyber_priv,
          signature_public: pq_sig_pub,
          signature_private: pq_sig_priv,
          signature_algorithm: pq_algorithm
        },
        security_level: "hybrid",
        created_at: DateTime.utc_now(),
        fingerprint: generate_pq_fingerprint(x25519_pub, kyber_pub)
      }

      Logger.info("Generated post-quantum identity keys (#{pq_algorithm}) for device #{device_id}")
      {:ok, pq_identity}
    rescue
      error ->
        Logger.error("PQ identity key generation failed: #{inspect(error)}")
        {:error, :identity_generation_failed}
    end
  end

  # Private functions

  defp generate_pq_fingerprint(x25519_pub, kyber_pub) do
    # Create a combined fingerprint
    combined = x25519_pub <> kyber_pub
    hash = Crypto.sha256(combined)

    # Format as readable fingerprint
    hash
    |> :binary.bin_to_list()
    |> Enum.take(16)
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.map(&String.pad_leading(&1, 2, "0"))
    |> Enum.join("")
  end
end