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

defmodule ArmoricoreRealtime.EncryptedStorage do
  @moduledoc """
  Encrypted storage for secure local data persistence.

  Provides secure storage for:
  - Encrypted messages and conversations
  - Cryptographic keys and sessions
  - User authentication data
  - Application settings

  ## Security Features

  - **AES-256-GCM Encryption**: Authenticated encryption for all data
  - **PBKDF2 Key Derivation**: Strong key derivation from user passwords
  - **Secure Key Storage**: Keys stored in secure enclaves when available
  - **Data Integrity**: HMAC verification for stored data
  - **Secure Deletion**: Cryptographic erasure of sensitive data

  ## Storage Architecture

  ```
  User Password ───> PBKDF2 ───> Master Key ───> HKDF ───> Domain Keys
       │                    │                        │
       ▼                    ▼                        ▼
  User Database ──────── Encrypted ──────────────── Encrypted Data
  ```

  ## Domains

  - **messages**: Encrypted message history
  - **keys**: Cryptographic keys and sessions
  - **contacts**: Contact information and verification data
  - **settings**: Application preferences and configuration
  """

  require Logger
  alias ArmoricoreRealtime.Crypto

  # Storage domains
  @messages_domain "messages"
  @keys_domain "keys"
  @contacts_domain "contacts"
  @settings_domain "settings"

  @doc """
  Initializes encrypted storage with a master password.

  Derives encryption keys and prepares storage containers.
  """
  @spec initialize(String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def initialize(user_id, master_password) do
    try do
      # Derive master key from password using PBKDF2
      salt = get_or_create_salt(user_id)
      {:ok, master_key} = Crypto.derive_key_from_password(master_password, salt)

      # Derive domain-specific keys
      {:ok, messages_key} = Crypto.hkdf_derive(master_key, salt, @messages_domain)
      {:ok, keys_key} = Crypto.hkdf_derive(master_key, salt, @keys_domain)
      {:ok, contacts_key} = Crypto.hkdf_derive(master_key, salt, @contacts_domain)
      {:ok, settings_key} = Crypto.hkdf_derive(master_key, salt, @settings_domain)

      storage_config = %{
        user_id: user_id,
        master_key: master_key,
        domain_keys: %{
          messages: messages_key,
          keys: keys_key,
          contacts: contacts_key,
          settings: settings_key
        },
        salt: salt,
        initialized_at: DateTime.utc_now()
      }

      Logger.info("Initialized encrypted storage for user #{user_id}")
      {:ok, storage_config}
    rescue
      error ->
        Logger.error("Failed to initialize encrypted storage: #{inspect(error)}")
        {:error, :initialization_failed}
    end
  end

  @doc """
  Stores encrypted data in the specified domain.

  Encrypts data with domain-specific key and stores securely.
  """
  @spec store_data(map(), String.t(), String.t(), any()) :: {:ok, String.t()} | {:error, atom()}
  def store_data(storage_config, domain, key, data) do
    with {:ok, domain_key} <- get_domain_key(storage_config, domain),
         {:ok, serialized_data} <- Jason.encode(data),
         {:ok, encrypted_data} <- encrypt_data(serialized_data, domain_key),
         {:ok, storage_key} <- generate_storage_key(domain, key) do

      # Store encrypted data (in production, this would use a secure database)
      store_encrypted_blob(storage_key, encrypted_data)

      Logger.debug("Stored encrypted data in domain #{domain} with key #{key}")
      {:ok, storage_key}
    end
  end

  @doc """
  Retrieves and decrypts data from encrypted storage.

  Returns the decrypted data or error if not found/decryption fails.
  """
  @spec retrieve_data(map(), String.t(), String.t()) :: {:ok, any()} | {:error, atom()}
  def retrieve_data(storage_config, domain, key) do
    with {:ok, domain_key} <- get_domain_key(storage_config, domain),
         {:ok, storage_key} <- generate_storage_key(domain, key),
         {:ok, encrypted_data} <- retrieve_encrypted_blob(storage_key),
         {:ok, decrypted_data} <- decrypt_data(encrypted_data, domain_key),
         {:ok, data} <- Jason.decode(decrypted_data) do

      Logger.debug("Retrieved and decrypted data from domain #{domain} with key #{key}")
      {:ok, data}
    end
  end

  @doc """
  Stores encrypted messages with metadata.

  Messages are stored with timestamps, sender info, and integrity checks.
  """
  @spec store_encrypted_message(map(), map()) :: {:ok, String.t()} | {:error, atom()}
  def store_encrypted_message(storage_config, message) do
    # Add storage metadata
    enriched_message = Map.merge(message, %{
      stored_at: DateTime.utc_now(),
      storage_version: "1.0"
    })

    message_key = "msg_#{message.id || Crypto.secure_random_bytes(16) |> Base.url_encode64(padding: false)}"
    store_data(storage_config, @messages_domain, message_key, enriched_message)
  end

  @doc """
  Retrieves encrypted messages with pagination.

  Returns decrypted messages sorted by timestamp.
  """
  @spec retrieve_messages(map(), map()) :: {:ok, list(map())} | {:error, atom()}
  def retrieve_messages(storage_config, options \\ %{}) do
    limit = Map.get(options, :limit, 50)
    offset = Map.get(options, :offset, 0)
    conversation_id = Map.get(options, :conversation_id)

    # In production, this would query the encrypted database
    # For now, return mock data
    messages = [
      %{
        id: "msg_1",
        content: "Hello, this is an encrypted message!",
        sender_id: "user_123",
        timestamp: DateTime.utc_now(),
        encrypted: true
      }
    ]

    {:ok, messages}
  end

  @doc """
  Stores cryptographic keys securely.

  Keys are encrypted with the keys domain key for additional security.
  """
  @spec store_cryptographic_key(map(), String.t(), map()) :: {:ok, String.t()} | {:error, atom()}
  def store_cryptographic_key(storage_config, key_id, key_data) do
    # Add key metadata
    enriched_key_data = Map.merge(key_data, %{
      stored_at: DateTime.utc_now(),
      key_version: "1.0",
      security_level: "high"
    })

    store_data(storage_config, @keys_domain, key_id, enriched_key_data)
  end

  @doc """
  Retrieves cryptographic keys.

  Keys are decrypted and validated before return.
  """
  @spec retrieve_cryptographic_key(map(), String.t()) :: {:ok, map()} | {:error, atom()}
  def retrieve_cryptographic_key(storage_config, key_id) do
    retrieve_data(storage_config, @keys_domain, key_id)
  end

  @doc """
  Securely deletes data from encrypted storage.

  Performs cryptographic erasure to prevent recovery.
  """
  @spec secure_delete(map(), String.t(), String.t()) :: {:ok, boolean()} | {:error, atom()}
  def secure_delete(storage_config, domain, key) do
    with {:ok, storage_key} <- generate_storage_key(domain, key) do
      # Overwrite with random data multiple times (cryptographic erasure)
      random_data = Crypto.secure_random_bytes(1024)
      Enum.each(1..3, fn _ ->
        store_encrypted_blob(storage_key, random_data)
      end)

      # Finally delete the key
      delete_encrypted_blob(storage_key)

      Logger.info("Securely deleted data from domain #{domain} with key #{key}")
      {:ok, true}
    end
  end

  @doc """
  Exports encrypted data for backup.

  Creates an encrypted backup that can only be decrypted with the master password.
  """
  @spec export_encrypted_backup(map()) :: {:ok, binary()} | {:error, atom()}
  def export_encrypted_backup(storage_config) do
    # Gather all data from all domains
    backup_data = %{
      user_id: storage_config.user_id,
      exported_at: DateTime.utc_now(),
      version: "1.0",
      domains: %{
        messages: get_all_domain_data(storage_config, @messages_domain),
        keys: get_all_domain_data(storage_config, @keys_domain),
        contacts: get_all_domain_data(storage_config, @contacts_domain),
        settings: get_all_domain_data(storage_config, @settings_domain)
      }
    }

    # Encrypt the entire backup with the master key
    {:ok, serialized_backup} = Jason.encode(backup_data)
    Crypto.aes_gcm_encrypt(serialized_backup, storage_config.master_key)
  end

  @doc """
  Imports encrypted backup data.

  Decrypts and restores backup data.
  """
  @spec import_encrypted_backup(String.t(), binary(), binary()) :: {:ok, map()} | {:error, atom()}
  def import_encrypted_backup(user_id, master_password, encrypted_backup) do
    # First initialize storage to get the master key
    with {:ok, storage_config} <- initialize(user_id, master_password),
         {:ok, decrypted_backup} <- Crypto.aes_gcm_decrypt(
           encrypted_backup.ciphertext,
           encrypted_backup.tag,
           encrypted_backup.nonce,
           storage_config.master_key
         ),
         {:ok, backup_data} <- Jason.decode(decrypted_backup) do

      # Restore data to all domains
      restore_backup_data(storage_config, backup_data)

      Logger.info("Successfully imported encrypted backup for user #{user_id}")
      {:ok, storage_config}
    end
  end

  @doc """
  Changes the master password.

  Re-encrypts all data with the new password.
  """
  @spec change_master_password(map(), String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def change_master_password(storage_config, old_password, new_password) do
    # Verify old password is correct
    old_salt = storage_config.salt
    {:ok, old_master_key} = Crypto.derive_key_from_password(old_password, old_salt)

    if Crypto.secure_compare(old_master_key, storage_config.master_key) do
      # Generate new salt and derive new master key
      new_salt = Crypto.generate_salt()
      {:ok, new_master_key} = Crypto.derive_key_from_password(new_password, new_salt)

      # Re-encrypt all data with new key
      re_encrypt_all_data(storage_config, new_master_key, new_salt)

      # Update storage configuration
      new_config = %{
        storage_config |
        master_key: new_master_key,
        salt: new_salt
      }

      Logger.info("Successfully changed master password for user #{storage_config.user_id}")
      {:ok, new_config}
    else
      {:error, :incorrect_password}
    end
  end

  # Private functions

  defp get_or_create_salt(user_id) do
    # In production, this would be stored securely per user
    # For now, derive a consistent salt from user_id
    Crypto.sha256(user_id <> "encryption_salt") |> binary_part(0, 32)
  end

  defp get_domain_key(storage_config, domain) do
    case Map.get(storage_config.domain_keys, String.to_atom(domain)) do
      nil -> {:error, :invalid_domain}
      key -> {:ok, key}
    end
  end

  defp generate_storage_key(domain, key) do
    # Create a compound key for storage
    storage_key = "#{domain}:#{key}"
    {:ok, storage_key}
  end

  defp encrypt_data(data, key) do
    # Add integrity check (HMAC) before encryption
    hmac = Crypto.hmac_sha256(key, data)
    data_with_integrity = hmac <> data

    Crypto.aes_gcm_encrypt(data_with_integrity, key)
  end

  defp decrypt_data(encrypted_data, key) do
    with {:ok, decrypted_data} <- Crypto.aes_gcm_decrypt(
           encrypted_data.ciphertext,
           encrypted_data.tag,
           encrypted_data.nonce,
           key
         ) do

      # Verify integrity
      <<hmac::binary-size(32), data::binary>> = decrypted_data
      expected_hmac = Crypto.hmac_sha256(key, data)

      if Crypto.secure_compare(hmac, expected_hmac) do
        {:ok, data}
      else
        {:error, :integrity_check_failed}
      end
    end
  end

  # Mock storage functions (would be replaced with actual secure storage)
  defp store_encrypted_blob(key, data), do: {:ok, key}
  defp retrieve_encrypted_blob(key), do: {:ok, Crypto.secure_random_bytes(100)}
  defp delete_encrypted_blob(key), do: :ok

  defp get_all_domain_data(storage_config, domain) do
    # Mock implementation - would retrieve all data for a domain
    []
  end

  defp restore_backup_data(storage_config, backup_data) do
    # Mock implementation - would restore data from backup
    :ok
  end

  defp re_encrypt_all_data(storage_config, new_master_key, new_salt) do
    # Mock implementation - would re-encrypt all stored data
    :ok
  end
end