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

#!/usr/bin/env elixir
# Migration script to import environment variables into KeyManager
#
# Usage:
#   mix run scripts/migrate_keys_to_key_store.exs
#
# This script reads environment variables and stores them in the KeyManager
# for secure key management.

Mix.install([
  {:jason, "~> 1.2"}
])

defmodule KeyMigration do
  @moduledoc """
  Helper module for migrating environment variables to KeyManager
  """

  def run do
    IO.puts("🔐 Key Migration Script")
    IO.puts("=" <> String.duplicate("=", 50))
    IO.puts("")

    # Start the application to initialize KeyManager
    Application.ensure_all_started(:armoricore_realtime)

    migrated = 0
    skipped = 0
    errors = 0

    # JWT Secret
    {migrated, skipped, errors} =
      migrate_key("JWT_SECRET", "jwt.secret", migrated, skipped, errors)

    # FCM API Key
    {migrated, skipped, errors} =
      migrate_key("FCM_API_KEY", "fcm.api_key", migrated, skipped, errors)

    # APNS Keys
    {migrated, skipped, errors} =
      migrate_key("APNS_KEY_ID", "apns.key_id", migrated, skipped, errors)

    {migrated, skipped, errors} =
      migrate_key("APNS_TEAM_ID", "apns.team_id", migrated, skipped, errors)

    {migrated, skipped, errors} =
      migrate_key("APNS_BUNDLE_ID", "apns.bundle_id", migrated, skipped, errors)

    # SMTP Credentials
    {migrated, skipped, errors} =
      migrate_key("SMTP_USERNAME", "smtp.username", migrated, skipped, errors)

    {migrated, skipped, errors} =
      migrate_key("SMTP_PASSWORD", "smtp.password", migrated, skipped, errors)

    # Object Storage Credentials
    {migrated, skipped, errors} =
      migrate_key("OBJECT_STORAGE_ACCESS_KEY", "object_storage.access_key", migrated, skipped, errors)

    {migrated, skipped, errors} =
      migrate_key("OBJECT_STORAGE_SECRET_KEY", "object_storage.secret_key", migrated, skipped, errors)

    IO.puts("")
    IO.puts("=" <> String.duplicate("=", 50))
    IO.puts("Migration Summary:")
    IO.puts("  ✅ Migrated: #{migrated}")
    IO.puts("  ⏭️  Skipped: #{skipped}")
    IO.puts("  ❌ Errors: #{errors}")
    IO.puts("")
    IO.puts("✅ Migration complete!")
    IO.puts("")
    IO.puts("Next steps:")
    IO.puts("  1. Verify keys are stored: mix run -e 'ArmoricoreRealtime.KeyManager.list_keys() |> IO.inspect()'")
    IO.puts("  2. Test key retrieval: mix run -e 'ArmoricoreRealtime.KeyManager.get_jwt_secret(\"jwt.secret\") |> IO.inspect()'")
    IO.puts("  3. Once verified, you can remove environment variables")
  end

  defp migrate_key(env_var, key_id, migrated, skipped, errors) do
    case System.get_env(env_var) do
      nil ->
        IO.puts("⏭️  #{env_var}: Not set, skipping")
        {migrated, skipped + 1, errors}

      value ->
        # Check if key already exists
        if ArmoricoreRealtime.KeyManager.key_exists?(key_id) do
          IO.puts("⏭️  #{env_var} -> #{key_id}: Already exists, skipping")
          {migrated, skipped + 1, errors}
        else
          case ArmoricoreRealtime.KeyManager.store_api_key(key_id, value) do
            :ok ->
              IO.puts("✅ #{env_var} -> #{key_id}: Migrated successfully")
              {migrated + 1, skipped, errors}

            {:error, reason} ->
              IO.puts("❌ #{env_var} -> #{key_id}: Error - #{inspect(reason)}")
              {migrated, skipped, errors + 1}
          end
        end
    end
  end
end

KeyMigration.run()

