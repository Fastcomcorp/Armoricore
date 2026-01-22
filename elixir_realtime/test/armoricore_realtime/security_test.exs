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

defmodule ArmoricoreRealtime.SecurityTest do
  use ExUnit.Case, async: false  # Cannot be async due to ETS table

  alias ArmoricoreRealtime.Security
  alias ArmoricoreRealtime.Security.RevokedToken
  alias ArmoricoreRealtime.Repo

  setup do
    # Initialize cache for tests
    try do
      :ets.delete(:revoked_tokens_cache)
    rescue
      ArgumentError -> :ok
    end
    Security.init_revoked_tokens_cache()
    
    # Clean up test data
    Repo.delete_all(RevokedToken)
    
    on_exit(fn ->
      :ets.delete(:revoked_tokens_cache)
    end)
    
    :ok
  end

  describe "revoke_token/5" do
    test "revokes a token successfully" do
      jti = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      assert {:ok, %RevokedToken{}} = Security.revoke_token(jti, user_id, "access", expires_at, "test")
    end

    test "prevents revoked token from being used" do
      jti = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      Security.revoke_token(jti, user_id, "access", expires_at, "test")
      assert Security.is_token_revoked?(jti) == true
    end

    test "non-revoked token is not revoked" do
      jti = Ecto.UUID.generate()
      assert Security.is_token_revoked?(jti) == false
    end
  end

  describe "is_token_revoked?/1" do
    test "returns true for revoked token" do
      jti = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      Security.revoke_token(jti, user_id, "access", expires_at, "test")
      assert Security.is_token_revoked?(jti) == true
    end

    test "returns false for non-revoked token" do
      jti = Ecto.UUID.generate()
      assert Security.is_token_revoked?(jti) == false
    end

    test "returns false for expired revoked token" do
      jti = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()
      expires_at = DateTime.utc_now() |> DateTime.add(-3600, :second)  # Expired 1 hour ago

      Security.revoke_token(jti, user_id, "access", expires_at, "test")
      # Cleanup expired tokens
      Security.cleanup_expired_tokens()
      assert Security.is_token_revoked?(jti) == false
    end
  end

  describe "cleanup_expired_tokens/0" do
    test "removes expired tokens" do
      jti1 = Ecto.UUID.generate()
      jti2 = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()

      # Create expired token
      expires_at1 = DateTime.utc_now() |> DateTime.add(-3600, :second)
      Security.revoke_token(jti1, user_id, "access", expires_at1, "test")

      # Create valid token
      expires_at2 = DateTime.utc_now() |> DateTime.add(3600, :second)
      Security.revoke_token(jti2, user_id, "access", expires_at2, "test")

      # Cleanup
      Security.cleanup_expired_tokens()

      # Expired token should be gone
      assert Security.is_token_revoked?(jti1) == false
      # Valid token should still be revoked
      assert Security.is_token_revoked?(jti2) == true
    end
  end

  describe "race condition prevention" do
    test "token is immediately marked as revoked in cache" do
      jti = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      # Revoke token
      {:ok, _} = Security.revoke_token(jti, user_id, "access", expires_at, "test")

      # Immediately check cache (simulating concurrent request)
      # This should return true even if database query hasn't completed
      assert Security.is_token_revoked?(jti) == true
    end

    test "concurrent revocation checks are atomic" do
      jti = Ecto.UUID.generate()
      user_id = Ecto.UUID.generate()
      expires_at = DateTime.utc_now() |> DateTime.add(3600, :second)

      # Simulate concurrent revocation and validation
      tasks = [
        Task.async(fn -> Security.revoke_token(jti, user_id, "access", expires_at, "test") end),
        Task.async(fn -> Security.is_token_revoked?(jti) end),
        Task.async(fn -> Security.is_token_revoked?(jti) end),
        Task.async(fn -> Security.is_token_revoked?(jti) end)
      ]

      results = Enum.map(tasks, &Task.await/1)

      # At least one revocation should succeed
      assert Enum.any?(results, fn
        {:ok, _} -> true
        _ -> false
      end)

      # All checks should eventually return true (token is revoked)
      # Wait a bit for cache to be populated
      Process.sleep(10)
      assert Security.is_token_revoked?(jti) == true
    end
  end
end

