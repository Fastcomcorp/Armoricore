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
# Standalone migration script that doesn't require full Phoenix app
#
# Usage:
#   elixir scripts/migrate_keys_standalone.exs
#
# This script reads environment variables and stores them in the KeyManager
# for secure key management.

# Load the key manager module directly
Code.compile_file("elixir_realtime/lib/armoricore_realtime/key_manager.ex")

defmodule KeyMigration do
  @moduledoc """
  Helper module for migrating environment variables to KeyManager
  """

  def run do
    IO.puts("🔐 Key Migration Script (Standalone)")
    IO.puts("=" <> String.duplicate("=", 50))
    IO.puts("")
    IO.puts("Note: This is a simplified version. For full integration,")
    IO.puts("use the Phoenix app version: mix run scripts/migrate_keys_to_key_store.exs")
    IO.puts("")

    # Check if keys directory exists
    keys_dir = "elixir_realtime/priv/keys"
    unless File.exists?(keys_dir) do
      File.mkdir_p!(keys_dir)
      IO.puts("Created keys directory: #{keys_dir}")
    end

    migrated = 0
    skipped = 0
    errors = 0

    # JWT Secret
    {migrated, skipped, errors} =
      migrate_key_simple("JWT_SECRET", "jwt.secret", migrated, skipped, errors)

    # FCM API Key
    {migrated, skipped, errors} =
      migrate_key_simple("FCM_API_KEY", "fcm.api_key", migrated, skipped, errors)

    # APNS Keys
    {migrated, skipped, errors} =
      migrate_key_simple("APNS_KEY_ID", "apns.key_id", migrated, skipped, errors)

    {migrated, skipped, errors} =
      migrate_key_simple("APNS_TEAM_ID", "apns.team_id", migrated, skipped, errors)

    {migrated, skipped, errors} =
      migrate_key_simple("APNS_BUNDLE_ID", "apns.bundle_id", migrated, skipped, errors)

    # SMTP Credentials
    {migrated, skipped, errors} =
      migrate_key_simple("SMTP_USERNAME", "smtp.username", migrated, skipped, errors)

    {migrated, skipped, errors} =
      migrate_key_simple("SMTP_PASSWORD", "smtp.password", migrated, skipped, errors)

    # Object Storage Credentials
    {migrated, skipped, errors} =
      migrate_key_simple("OBJECT_STORAGE_ACCESS_KEY", "object_storage.access_key", migrated, skipped, errors)

    {migrated, skipped, errors} =
      migrate_key_simple("OBJECT_STORAGE_SECRET_KEY", "object_storage.secret_key", migrated, skipped, errors)

    IO.puts("")
    IO.puts("=" <> String.duplicate("=", 50))
    IO.puts("Migration Summary:")
    IO.puts("  ✅ Would migrate: #{migrated}")
    IO.puts("  ⏭️  Skipped: #{skipped}")
    IO.puts("  ❌ Errors: #{errors}")
    IO.puts("")
    IO.puts("⚠️  Note: This standalone script only checks for environment variables.")
    IO.puts("For actual migration, use the full Phoenix app version.")
    IO.puts("")
  end

  defp migrate_key_simple(env_var, key_id, migrated, skipped, errors) do
    case System.get_env(env_var) do
      nil ->
        IO.puts("⏭️  #{env_var}: Not set, skipping")
        {migrated, skipped + 1, errors}

      _value ->
        IO.puts("✅ #{env_var} -> #{key_id}: Found (would migrate)")
        {migrated + 1, skipped, errors}
    end
  end
end

KeyMigration.run()

