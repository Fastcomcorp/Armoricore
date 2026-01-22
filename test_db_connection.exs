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

# Test database connection script
# Usage: elixir test_db_connection.exs

# Set DATABASE_URL from environment or use default
unless System.get_env("DATABASE_URL") do
  System.put_env("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/armoricore_dev")
end

# Add the app path
System.cwd!()
|> Path.join("elixir_realtime")
|> Code.prepend_path()

# Start the application
Application.start(:crypto)
Application.start(:ssl)
Application.start(:postgrex)
Application.start(:ecto)
Application.start(:ecto_sql)

# Try to connect
try do
  # Parse the URL
  database_url = System.get_env("DATABASE_URL")
  IO.puts("Testing connection to: #{database_url}")

  # Extract connection parameters
  uri = URI.parse(database_url)

  config = [
    hostname: uri.host,
    port: uri.port,
    username: uri.userinfo |> String.split(":") |> List.first(),
    password: uri.userinfo |> String.split(":") |> List.last(),
    database: String.trim_leading(uri.path, "/"),
    ssl: true,
    ssl_opts: [verify: :verify_none]
  ]

  IO.inspect(config, label: "Connection config")

  # Test the connection
  case Postgrex.start_link(config) do
    {:ok, conn} ->
      IO.puts("✅ Successfully connected to database!")

      # Test a simple query
      case Postgrex.query(conn, "SELECT version()", []) do
        {:ok, %Postgrex.Result{rows: [[version]]}} ->
          IO.puts("✅ Database version: #{version}")
        {:error, error} ->
          IO.puts("❌ Query failed: #{inspect(error)}")
      end

      # Test if our tables exist
      case Postgrex.query(conn, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE 'videos'", []) do
        {:ok, %Postgrex.Result{rows: rows}} ->
          IO.puts("✅ Found tables: #{inspect(rows)}")
        {:error, error} ->
          IO.puts("❌ Table check failed: #{inspect(error)}")
      end

      Postgrex.stop(conn)

    {:error, error} ->
      IO.puts("❌ Connection failed: #{inspect(error)}")
  end

rescue
  error ->
    IO.puts("❌ Error: #{inspect(error)}")
end