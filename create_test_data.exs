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

# Script to create test data in database
alias ArmoricoreRealtime.Repo
alias ArmoricoreRealtime.Accounts

Application.put_env(:armoricore_realtime, ArmoricoreRealtime.Repo, [
  url: System.get_env("DATABASE_URL"),
  pool_size: 2
])

case Repo.start_link() do
  {:ok, _pid} ->
    # Create test user
    test_email = "test-" <> Integer.to_string(:erlang.system_time(:second)) <> "@armoricore.test"
    case Accounts.create_user(%{
      email: test_email,
      password: "TestPassword123!",
      username: "testuser"
    }) do
      {:ok, user} ->
        IO.puts("✅ Test user created: #{user.id}")
        IO.puts("   Email: #{user.email}")
        
        # Create test media record
        media_id = Ecto.UUID.generate()
        case Repo.insert(%ArmoricoreRealtime.Media{
          id: media_id,
          user_id: user.id,
          original_filename: "test-video.mp4",
          content_type: "video/mp4",
          file_size: 1000000,
          status: "processing",
          playback_urls: %{},
          thumbnail_urls: [],
          metadata: %{}
        }) do
          {:ok, media} ->
            IO.puts("✅ Test media record created: #{media.id}")
            IO.puts("   Status: #{media.status}")
            IO.puts("")
            IO.puts("📝 Use this media_id to test:")
            IO.puts("   #{media.id}")
          {:error, changeset} ->
            IO.puts("⚠️  Media creation error: #{inspect(changeset.errors)}")
        end
      {:error, changeset} ->
        IO.puts("⚠️  User creation error: #{inspect(changeset.errors)}")
    end
    
    # Show database stats
    IO.puts("")
    IO.puts("📊 Database Statistics:")
    {:ok, user_result} = Repo.query("SELECT COUNT(*) FROM users")
    user_count = List.first(List.first(user_result.rows))
    IO.puts("   Users: #{user_count}")
    
    {:ok, media_result} = Repo.query("SELECT COUNT(*) FROM media")
    media_count = List.first(List.first(media_result.rows))
    IO.puts("   Media: #{media_count}")
    
    GenServer.stop(Repo)
  {:error, error} ->
    IO.puts("Error starting Repo: #{inspect(error)}")
end

