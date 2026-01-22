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

defmodule ArmoricoreRealtime.SecureBackup do
  @moduledoc """
  Secure backup and recovery system with social trust.

  Implements Signal-style secure backup with:
  - Social recovery using trusted contacts
  - Hardware security key integration
  - Encrypted backup storage
  - Secure key recovery protocols

  ## Architecture

  ```
  Master Key ───┐
                ├──> Backup Shares ───> Trusted Contacts
  User Data ────┼──> Encrypted Backup ──> Cloud Storage
                │
                └──> Recovery Key ────> Hardware Security Key
  ```

  ## Security Features

  - **Social Recovery**: Split-key recovery using trusted contacts
  - **Hardware Security**: FIDO2/WebAuthn integration
  - **Encrypted Backups**: End-to-end encrypted cloud storage
  - **Key Rotation**: Automatic key updates without breaking recovery
  - **Revocation**: Ability to revoke recovery contacts/keys

  ## Recovery Methods

  1. **Social Recovery**: Combine shares from trusted contacts
  2. **Hardware Key**: Use security key for direct recovery
  3. **Backup Code**: One-time recovery code (less secure)
  """

  require Logger
  alias ArmoricoreRealtime.Crypto

  @share_count 5  # Total number of recovery shares
  @threshold 3    # Minimum shares needed for recovery
  @backup_key_length 32

  @doc """
  Sets up secure backup for a user.

  Generates recovery shares and configures backup methods.
  """
  @spec setup_backup(String.t(), list(String.t())) :: {:ok, map()} | {:error, atom()}
  def setup_backup(user_id, trusted_contacts) do
    try do
      # Generate backup master key
      backup_master_key = Crypto.secure_random_bytes(@backup_key_length)

      # Split key using Shamir's Secret Sharing
      {:ok, recovery_shares} = generate_recovery_shares(backup_master_key, @share_count, @threshold)

      # Assign shares to trusted contacts
      contact_shares = assign_shares_to_contacts(recovery_shares, trusted_contacts)

      # Generate hardware recovery key
      {:ok, hardware_key} = generate_hardware_recovery_key(user_id)

      # Generate backup code (last resort)
      backup_code = generate_backup_code()

      backup_config = %{
        user_id: user_id,
        backup_master_key: backup_master_key,
        recovery_shares: contact_shares,
        hardware_key: hardware_key,
        backup_code: backup_code,
        created_at: DateTime.utc_now(),
        last_backup: nil
      }

      # Store backup configuration securely
      store_backup_config(backup_config)

      Logger.info("Set up secure backup for user #{user_id}")
      {:ok, backup_config}
    rescue
      error ->
        Logger.error("Backup setup failed: #{inspect(error)}")
        {:error, :setup_failed}
    end
  end

  @doc """
  Creates an encrypted backup of user data.

  Backs up messages, keys, and settings securely.
  """
  @spec create_backup(String.t(), map()) :: {:ok, String.t()} | {:error, atom()}
  def create_backup(user_id, storage_config) do
    try do
      # Get backup configuration
      {:ok, backup_config} = get_backup_config(user_id)

      # Gather user data to backup
      backup_data = gather_backup_data(user_id)

      # Encrypt backup data with backup master key
      {:ok, encrypted_backup} = Crypto.aes_gcm_encrypt(
        Jason.encode!(backup_data),
        backup_config.backup_master_key
      )

      # Generate backup ID
      backup_id = generate_backup_id(user_id)

      # Store encrypted backup
      store_encrypted_backup(backup_id, encrypted_backup)

      # Update last backup timestamp
      updated_config = %{backup_config | last_backup: DateTime.utc_now()}
      store_backup_config(updated_config)

      Logger.info("Created encrypted backup #{backup_id} for user #{user_id}")
      {:ok, backup_id}
    rescue
      error ->
        Logger.error("Backup creation failed: #{inspect(error)}")
        {:error, :backup_failed}
    end
  end

  @doc """
  Recovers account using social recovery method.

  Combines recovery shares from trusted contacts.
  """
  @spec recover_with_social_shares(String.t(), list(map())) :: {:ok, map()} | {:error, atom()}
  def recover_with_social_shares(user_id, provided_shares) do
    try do
      # Verify provided shares
      case verify_recovery_shares(user_id, provided_shares) do
        {:ok, verified_shares} when length(verified_shares) >= @threshold ->
          # Reconstruct master key
          {:ok, reconstructed_key} = reconstruct_master_key(verified_shares)

          # Verify reconstructed key
          {:ok, backup_config} = get_backup_config(user_id)
          if Crypto.secure_compare(reconstructed_key, backup_config.backup_master_key) do
            # Recovery successful
            recovery_result = %{
              method: :social_recovery,
              user_id: user_id,
              shares_used: length(verified_shares),
              recovered_at: DateTime.utc_now()
            }

            Logger.info("Successful social recovery for user #{user_id}")
            {:ok, recovery_result}
          else
            {:error, :key_verification_failed}
          end

        {:ok, _} ->
          {:error, :insufficient_shares}

        {:error, reason} ->
          {:error, reason}
      end
    rescue
      error ->
        Logger.error("Social recovery failed: #{inspect(error)}")
        {:error, :recovery_failed}
    end
  end

  @doc """
  Recovers account using hardware security key.

  Direct recovery using FIDO2/WebAuthn security key.
  """
  @spec recover_with_hardware_key(String.t(), binary()) :: {:ok, map()} | {:error, atom()}
  def recover_with_hardware_key(user_id, key_signature) do
    try do
      # Get hardware recovery key
      {:ok, backup_config} = get_backup_config(user_id)

      # Verify hardware key signature
      case verify_hardware_signature(key_signature, backup_config.hardware_key) do
        true ->
          recovery_result = %{
            method: :hardware_recovery,
            user_id: user_id,
            hardware_verified: true,
            recovered_at: DateTime.utc_now()
          }

          Logger.info("Successful hardware key recovery for user #{user_id}")
          {:ok, recovery_result}

        false ->
          {:error, :hardware_verification_failed}
      end
    rescue
      error ->
        Logger.error("Hardware recovery failed: #{inspect(error)}")
        {:error, :recovery_failed}
    end
  end

  @doc """
  Recovers account using backup code.

  One-time use emergency recovery method.
  """
  @spec recover_with_backup_code(String.t(), String.t()) :: {:ok, map()} | {:error, atom()}
  def recover_with_backup_code(user_id, provided_code) do
    try do
      {:ok, backup_config} = get_backup_config(user_id)

      # Verify backup code (timing-safe comparison)
      if Crypto.secure_compare(provided_code, backup_config.backup_code) do
        # Mark backup code as used
        updated_config = %{backup_config | backup_code_used: true}
        store_backup_config(updated_config)

        recovery_result = %{
          method: :backup_code_recovery,
          user_id: user_id,
          code_used: true,
          recovered_at: DateTime.utc_now()
        }

        Logger.warning("Backup code used for recovery of user #{user_id}")
        {:ok, recovery_result}
      else
        {:error, :invalid_backup_code}
      end
    rescue
      error ->
        Logger.error("Backup code recovery failed: #{inspect(error)}")
        {:error, :recovery_failed}
    end
  end

  @doc """
  Restores data from encrypted backup.

  Decrypts and restores messages, keys, and settings.
  """
  @spec restore_from_backup(String.t(), String.t(), binary()) :: {:ok, map()} | {:error, atom()}
  def restore_from_backup(user_id, backup_id, master_key) do
    try do
      # Retrieve encrypted backup
      {:ok, encrypted_backup} = get_encrypted_backup(backup_id)

      # Decrypt backup data
      {:ok, decrypted_json} = Crypto.aes_gcm_decrypt(
        encrypted_backup.ciphertext,
        encrypted_backup.tag,
        encrypted_backup.nonce,
        master_key
      )

      # Parse backup data
      backup_data = Jason.decode!(decrypted_json)

      # Restore user data
      restore_result = restore_user_data(user_id, backup_data)

      Logger.info("Restored backup #{backup_id} for user #{user_id}")
      {:ok, restore_result}
    rescue
      error ->
        Logger.error("Backup restoration failed: #{inspect(error)}")
        {:error, :restoration_failed}
    end
  end

  @doc """
  Updates recovery contacts.

  Allows changing trusted contacts for social recovery.
  """
  @spec update_recovery_contacts(String.t(), list(String.t())) :: {:ok, map()} | {:error, atom()}
  def update_recovery_contacts(user_id, new_contacts) do
    try do
      {:ok, backup_config} = get_backup_config(user_id)

      # Generate new recovery shares
      {:ok, new_shares} = generate_recovery_shares(backup_config.backup_master_key, @share_count, @threshold)

      # Assign to new contacts
      new_contact_shares = assign_shares_to_contacts(new_shares, new_contacts)

      # Update configuration
      updated_config = %{
        backup_config |
        recovery_shares: new_contact_shares,
        contacts_updated_at: DateTime.utc_now()
      }

      store_backup_config(updated_config)

      Logger.info("Updated recovery contacts for user #{user_id}")
      {:ok, %{updated_contacts: length(new_contacts)}}
    rescue
      error ->
        Logger.error("Contact update failed: #{inspect(error)}")
        {:error, :update_failed}
    end
  end

  @doc """
  Revokes a recovery method.

  Disables compromised recovery methods.
  """
  @spec revoke_recovery_method(String.t(), atom()) :: {:ok, boolean()} | {:error, atom()}
  def revoke_recovery_method(user_id, method) do
    try do
      {:ok, backup_config} = get_backup_config(user_id)

      updated_config = case method do
        :social_recovery ->
          # Clear all recovery shares
          %{backup_config | recovery_shares: []}

        :hardware_key ->
          # Clear hardware key
          %{backup_config | hardware_key: nil}

        :backup_code ->
          # Mark backup code as revoked
          %{backup_config | backup_code_revoked: true}
      end

      store_backup_config(updated_config)

      Logger.warning("Revoked #{method} for user #{user_id}")
      {:ok, true}
    rescue
      error ->
        Logger.error("Recovery method revocation failed: #{inspect(error)}")
        {:error, :revocation_failed}
    end
  end

  # Private functions

  defp generate_recovery_shares(secret, total_shares, threshold) do
    # Simplified Shamir's Secret Sharing implementation
    # In production, use a proper SSS library

    # For now, create mock shares
    shares = Enum.map(1..total_shares, fn index ->
      %{
        index: index,
        share: Crypto.hkdf_derive(secret, <<index::32>>, "Share", 32),
        created_at: DateTime.utc_now()
      }
    end)

    {:ok, shares}
  end

  defp reconstruct_master_key(shares) do
    # Simplified reconstruction (would use proper SSS math)
    # Combine shares to reconstruct secret
    combined = Enum.reduce(shares, <<>>, fn share, acc ->
      :crypto.exor(acc, share.share)
    end)

    {:ok, combined}
  end

  defp assign_shares_to_contacts(shares, contacts) do
    # Assign shares to contacts
    Enum.zip(contacts, shares)
    |> Enum.map(fn {contact, share} ->
      %{
        contact_id: contact,
        share: share,
        assigned_at: DateTime.utc_now()
      }
    end)
  end

  defp generate_hardware_recovery_key(user_id) do
    # Generate key for hardware security integration
    key_data = %{
      key_id: "hw_#{user_id}_#{DateTime.utc_now() |> DateTime.to_unix()}",
      public_key: Crypto.secure_random_bytes(32),
      key_type: :fido2
    }

    {:ok, key_data}
  end

  defp generate_backup_code do
    # Generate 12-character backup code
    Crypto.secure_random_bytes(6)
    |> Base.url_encode64(padding: false)
    |> String.slice(0, 12)
    |> String.upcase()
  end

  defp generate_backup_id(user_id) do
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    "backup_#{user_id}_#{timestamp}"
  end

  defp gather_backup_data(user_id) do
    # Gather all user data for backup
    %{
      user_id: user_id,
      messages: [],  # Would query message history
      keys: [],      # Would get E2EE keys
      settings: %{}, # Would get user settings
      contacts: [],  # Would get contact list
      backed_up_at: DateTime.utc_now()
    }
  end

  # Mock functions (would be implemented with secure storage)

  defp store_backup_config(config), do: :ok
  defp get_backup_config(user_id), do: {:ok, %{backup_master_key: Crypto.secure_random_bytes(32), hardware_key: %{}, backup_code: "MOCKCODE123"}}
  defp store_encrypted_backup(backup_id, data), do: :ok
  defp get_encrypted_backup(backup_id), do: {:ok, %{ciphertext: <<>>, tag: <<>>, nonce: <<>>}}
  defp verify_recovery_shares(user_id, shares), do: {:ok, shares}
  defp verify_hardware_signature(signature, key), do: true
  defp restore_user_data(user_id, data), do: %{restored_items: 0}
end