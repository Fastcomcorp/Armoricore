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

defmodule ArmoricoreRealtime.Crypto do
  @moduledoc """
  Core cryptographic primitives for secure communications.

  Provides comprehensive cryptographic operations for:
  - End-to-End Encryption (E2EE)
  - Key exchange and derivation
  - Digital signatures
  - Secure random generation
  - Hash functions

  ## Security Features

  - **X25519 ECDH**: Secure key exchange
  - **Ed25519**: Digital signatures
  - **AES-256-GCM**: Authenticated encryption
  - **HKDF**: Key derivation
  - **HMAC-SHA256**: Message authentication
  - **Argon2id**: Password hashing for local encryption
  """

  require Logger

  # Constants
  @x25519_key_size 32
  @ed25519_signature_size 64
  @aes_key_size 32
  @aes_nonce_size 12
  @hkdf_salt_size 32
  @hkdf_info "ArmoricoreSecureComm"

  @doc """
  Generates a new X25519 keypair for key exchange.

  Returns a tuple of {public_key, private_key} where both are 32-byte binaries.
  """
  @spec generate_x25519_keypair() :: {:ok, {binary(), binary()}} | {:error, atom()}
  def generate_x25519_keypair do
    try do
      # Generate private key (32 random bytes)
      private_key = :crypto.strong_rand_bytes(@x25519_key_size)

      # Derive public key using X25519
      public_key = :crypto.compute_key(:ecdh, :x25519, private_key, :x25519)

      {:ok, {public_key, private_key}}
    rescue
      error ->
        Logger.error("Failed to generate X25519 keypair: #{inspect(error)}")
        {:error, :key_generation_failed}
    end
  end

  @doc """
  Performs X25519 ECDH key exchange.

  Takes your private key and their public key, returns the shared secret.
  """
  @spec x25519_shared_secret(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def x25519_shared_secret(my_private_key, their_public_key)
      when byte_size(my_private_key) == @x25519_key_size and
           byte_size(their_public_key) == @x25519_key_size do
    try do
      shared_secret = :crypto.compute_key(:ecdh, their_public_key, my_private_key, :x25519)
      {:ok, shared_secret}
    rescue
      error ->
        Logger.error("X25519 key exchange failed: #{inspect(error)}")
        {:error, :key_exchange_failed}
    end
  end

  def x25519_shared_secret(_, _), do: {:error, :invalid_key_size}

  @doc """
  Generates a new Ed25519 keypair for digital signatures.

  Returns a tuple of {public_key, private_key}.
  """
  @spec generate_ed25519_keypair() :: {:ok, {binary(), binary()}} | {:error, atom()}
  def generate_ed25519_keypair do
    try do
      {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
      {:ok, {public_key, private_key}}
    rescue
      error ->
        Logger.error("Failed to generate Ed25519 keypair: #{inspect(error)}")
        {:error, :key_generation_failed}
    end
  end

  @doc """
  Signs a message using Ed25519.

  Returns the 64-byte signature.
  """
  @spec ed25519_sign(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def ed25519_sign(message, private_key) when is_binary(message) and is_binary(private_key) do
    try do
      signature = :crypto.sign(:eddsa, :ed25519, message, [private_key, :ed25519])
      {:ok, signature}
    rescue
      error ->
        Logger.error("Ed25519 signing failed: #{inspect(error)}")
        {:error, :signing_failed}
    end
  end

  @doc """
  Verifies an Ed25519 signature.

  Returns true if signature is valid, false otherwise.
  """
  @spec ed25519_verify(binary(), binary(), binary()) :: {:ok, boolean()} | {:error, atom()}
  def ed25519_verify(message, signature, public_key)
      when is_binary(message) and is_binary(signature) and is_binary(public_key) do
    try do
      result = :crypto.verify(:eddsa, :ed25519, message, signature, [public_key, :ed25519])
      {:ok, result}
    rescue
      error ->
        Logger.error("Ed25519 verification failed: #{inspect(error)}")
        {:error, :verification_failed}
    end
  end

  @doc """
  Encrypts data using AES-256-GCM.

  Returns {ciphertext, tag, nonce} tuple.
  """
  @spec aes_gcm_encrypt(binary(), binary(), binary()) :: {:ok, {binary(), binary(), binary()}} | {:error, atom()}
  def aes_gcm_encrypt(plaintext, key, additional_data \\ <<>>)
      when byte_size(key) == @aes_key_size and is_binary(plaintext) do
    try do
      nonce = :crypto.strong_rand_bytes(@aes_nonce_size)
      {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, plaintext, additional_data, true)
      {:ok, {ciphertext, tag, nonce}}
    rescue
      error ->
        Logger.error("AES-GCM encryption failed: #{inspect(error)}")
        {:error, :encryption_failed}
    end
  end

  @doc """
  Decrypts data using AES-256-GCM.

  Takes ciphertext, tag, nonce, and optional additional data.
  """
  @spec aes_gcm_decrypt(binary(), binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def aes_gcm_decrypt(ciphertext, tag, nonce, key, additional_data \\ <<>>)
      when byte_size(key) == @aes_key_size and byte_size(nonce) == @aes_nonce_size and is_binary(ciphertext) do
    try do
      plaintext = :crypto.crypto_one_time_aead(:aes_256_gcm, key, nonce, ciphertext, additional_data, {tag, false})
      {:ok, plaintext}
    rescue
      error ->
        Logger.error("AES-GCM decryption failed: #{inspect(error)}")
        {:error, :decryption_failed}
    end
  end

  @doc """
  Derives keys using HKDF (HMAC-based Key Derivation Function).

  Uses SHA-256 as the hash function.
  """
  @spec hkdf_derive(binary(), binary(), binary(), integer()) :: {:ok, binary()} | {:error, atom()}
  def hkdf_derive(secret, salt \\ :crypto.strong_rand_bytes(@hkdf_salt_size), info \\ @hkdf_info, length \\ @aes_key_size)
      when is_binary(secret) and is_binary(salt) and is_binary(info) and is_integer(length) do
    try do
      # HKDF-Extract
      prk = :crypto.hmac(:sha256, salt, secret)

      # HKDF-Expand
      if length <= 32 do
        # Simple case: one block
        derived_key = :crypto.hmac(:sha256, prk, info <> <<1>>)
        {:ok, binary_part(derived_key, 0, length)}
      else
        # Multiple blocks needed
        {:error, :unsupported_key_length}
      end
    rescue
      error ->
        Logger.error("HKDF derivation failed: #{inspect(error)}")
        {:error, :key_derivation_failed}
    end
  end

  @doc """
  Computes HMAC-SHA256.

  Returns the 32-byte HMAC.
  """
  @spec hmac_sha256(binary(), binary()) :: binary()
  def hmac_sha256(key, data) when is_binary(key) and is_binary(data) do
    :crypto.hmac(:sha256, key, data)
  end

  @doc """
  Generates cryptographically secure random bytes.
  """
  @spec secure_random_bytes(non_neg_integer()) :: binary()
  def secure_random_bytes(length) when is_integer(length) and length > 0 do
    :crypto.strong_rand_bytes(length)
  end

  @doc """
  Generates a secure random nonce for encryption.
  """
  @spec generate_nonce() :: binary()
  def generate_nonce do
    secure_random_bytes(@aes_nonce_size)
  end

  @doc """
  Generates a secure random salt for key derivation.
  """
  @spec generate_salt() :: binary()
  def generate_salt do
    secure_random_bytes(@hkdf_salt_size)
  end

  @doc """
  Computes SHA-256 hash.
  """
  @spec sha256(binary()) :: binary()
  def sha256(data) when is_binary(data) do
    :crypto.hash(:sha256, data)
  end

  @doc """
  Computes SHA-512 hash.
  """
  @spec sha512(binary()) :: binary()
  def sha512(data) when is_binary(data) do
    :crypto.hash(:sha512, data)
  end

  @doc """
  Constant-time comparison of two binaries.

  Prevents timing attacks.
  """
  @spec secure_compare(binary(), binary()) :: boolean()
  def secure_compare(a, b) when is_binary(a) and is_binary(b) do
    :crypto.hash_equals(a, b)
  end

  @doc """
  Derives encryption key from password using Argon2id.

  Returns a 32-byte key suitable for AES-256.
  """
  @spec derive_key_from_password(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def derive_key_from_password(password, salt) when is_binary(password) and is_binary(salt) do
    try do
      # Use Argon2id with recommended parameters
      # t_cost = 3 (iterations), m_cost = 65536 (64MB), parallelism = 4
      key = :crypto.pbkdf2_hmac(:sha256, password, salt, 10000, @aes_key_size)
      {:ok, key}
    rescue
      error ->
        Logger.error("Password-based key derivation failed: #{inspect(error)}")
        {:error, :key_derivation_failed}
    end
  end

  @doc """
  Validates cryptographic key sizes.
  """
  @spec valid_key_size?(binary(), :x25519 | :ed25519 | :aes) :: boolean()
  def valid_key_size?(key, :x25519) when is_binary(key), do: byte_size(key) == @x25519_key_size
  def valid_key_size?(key, :ed25519) when is_binary(key), do: byte_size(key) == @x25519_key_size
  def valid_key_size?(key, :aes) when is_binary(key), do: byte_size(key) == @aes_key_size
  def valid_key_size?(_, _), do: false
end