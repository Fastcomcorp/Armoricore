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

# Test script for room membership functionality
# Run with: elixir test_room_membership.exs

Application.put_env(:armoricore_realtime, :repo_config, [
  url: System.get_env("DATABASE_URL") || "postgres://postgres:postgres@localhost:5432/armoricore_dev",
  ssl: false,  # Disable SSL for testing
  pool_size: 1
])

# Start required applications
{:ok, _} = Application.ensure_all_started(:postgrex)
{:ok, _} = Application.ensure_all_started(:ecto)
{:ok, _} = Application.ensure_all_started(:armoricore_realtime)

IO.puts("Testing Room Membership functionality...")

# Test basic database connection
case ArmoricoreRealtime.Repo.query("SELECT 1 as test") do
  {:ok, _result} ->
    IO.puts("✅ Database connection successful")
  {:error, error} ->
    IO.puts("❌ Database connection failed: #{inspect(error)}")
    exit(1)
end

# Test room membership operations
test_user_id = "550e8400-e29b-41d4-a716-446655440000"
test_room_id = "chat:video:test-room-123"

IO.puts("Testing room membership operations...")

# Test joining a room
case ArmoricoreRealtime.Rooms.join_room(test_user_id, test_room_id, "chat", "member") do
  {:ok, membership} ->
    IO.puts("✅ Successfully joined room: #{membership.room_id}")
  {:error, error} ->
    IO.puts("❌ Failed to join room: #{inspect(error)}")
end

# Test checking membership
case ArmoricoreRealtime.Rooms.has_room_membership?(test_user_id, test_room_id) do
  true ->
    IO.puts("✅ User has room membership")
  false ->
    IO.puts("❌ User does not have room membership")
end

# Test listing user rooms
case ArmoricoreRealtime.Rooms.list_user_rooms(test_user_id) do
  rooms when is_list(rooms) ->
    IO.puts("✅ Found #{length(rooms)} user rooms")
  {:error, error} ->
    IO.puts("❌ Failed to list user rooms: #{inspect(error)}")
end

# Test leaving room
case ArmoricoreRealtime.Rooms.leave_room(test_user_id, test_room_id) do
  {:ok, _} ->
    IO.puts("✅ Successfully left room")
  {:error, error} ->
    IO.puts("❌ Failed to leave room: #{inspect(error)}")
end

IO.puts("Room membership testing complete!")