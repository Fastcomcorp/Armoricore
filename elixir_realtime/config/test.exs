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

# Copyright 2025 Francisco F. Pinochet
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

import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :armoricore_realtime, ArmoricoreRealtimeWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "YPa61tsmZBAs1h2WHIBDBVI4/a8tcF9OjKKOR8Tkls956kbI9l0VE1eWp9pn5DCk",
  server: false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Configure JWT secret for testing (required for security fixes)
config :armoricore_realtime, :jwt,
  secret: "test-secret-key-for-jwt-validation-must-be-at-least-32-bytes-long"

# Configure the database for testing
# Use DATABASE_URL environment variable if provided, otherwise use defaults
database_url = System.get_env("DATABASE_URL")

if database_url do
  # Use provided database URL (e.g., from Aiven cloud)
  ssl_enabled = String.contains?(database_url, "sslmode=require") || 
                String.contains?(database_url, "aivencloud.com")
  
  repo_config = [
    url: database_url,
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: 2  # Reduced for Aiven connection limits
  ]
  
  # Add SSL config if needed
  repo_config = if ssl_enabled do
    repo_config ++ [ssl: true, ssl_opts: [verify: :verify_none]]
  else
    repo_config
  end
  
  config :armoricore_realtime, ArmoricoreRealtime.Repo, repo_config
else
  # Default local database for testing
  config :armoricore_realtime, ArmoricoreRealtime.Repo,
    username: "postgres",
    password: "postgres",
    hostname: "localhost",
    database: "armoricore_realtime_test#{System.get_env("MIX_TEST_PARTITION")}",
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: 10
end
