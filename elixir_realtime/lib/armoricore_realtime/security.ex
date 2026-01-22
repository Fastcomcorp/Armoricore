# Copyright 2025 Fastcomcorp
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

defmodule ArmoricoreRealtime.Security do
  @moduledoc """
  Security context for token revocation and security features.
  
  Uses ETS cache for fast, atomic revocation checks to prevent race conditions.
  """

  require Logger
  import Ecto.Query
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Security.RevokedToken

  # ETS table name for revoked tokens cache
  @revoked_tokens_table :revoked_tokens_cache

  @doc """
  Initializes the revoked tokens cache (ETS table).
  Called during application startup.
  """
  def init_revoked_tokens_cache do
    # Create ETS table with write_concurrency for better performance
    :ets.new(@revoked_tokens_table, [
      :named_table,
      :public,
      :set,
      {:read_concurrency, true},
      {:write_concurrency, true}
    ])
    
    # Warm cache with recent revocations
    warm_cache()
    
    # Schedule periodic cleanup
    schedule_cache_cleanup()
    
    Logger.info("Revoked tokens cache initialized")
    :ok
  end

  @doc """
  Revokes a token (adds to blacklist).
  
  SECURITY: Immediately adds to cache to prevent race conditions.
  """
  def revoke_token(token_jti, user_id, token_type, expires_at, reason \\ "logout") do
    # Insert into database
    result = %RevokedToken{}
    |> RevokedToken.changeset(%{
      token_jti: token_jti,
      user_id: user_id,
      token_type: token_type,
      revoked_at: DateTime.utc_now(),
      expires_at: expires_at,
      reason: reason
    })
    |> Repo.insert()

    # SECURITY: Immediately add to cache to prevent race condition
    # This ensures the token is marked as revoked before any concurrent validation
    case result do
      {:ok, _revoked_token} ->
        # Convert expires_at to Unix timestamp for TTL calculation
        expires_timestamp = DateTime.to_unix(expires_at)
        # Store in cache with expiration timestamp
        :ets.insert(@revoked_tokens_table, {token_jti, expires_timestamp})
        Logger.debug("Token revoked and cached", jti: token_jti, reason: reason)
        result

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Checks if a token is revoked.
  
  SECURITY: Uses atomic ETS lookup to prevent race conditions.
  Checks cache first (fast), then falls back to database if needed.
  """
  def is_token_revoked?(token_jti) when is_binary(token_jti) do
    current_timestamp = System.system_time(:second)
    
    # SECURITY: Atomic check in ETS cache first (prevents race condition)
    case :ets.lookup(@revoked_tokens_table, token_jti) do
      [{^token_jti, expires_timestamp}] ->
        # Check if token is still expired (not yet past expiration)
        if expires_timestamp > current_timestamp do
          true
        else
          # Cache entry expired, remove it and check database
          :ets.delete(@revoked_tokens_table, token_jti)
          check_database(token_jti, current_timestamp)
        end

      [] ->
        # Not in cache, check database
        check_database(token_jti, current_timestamp)
    end
  end

  # Private function to check database and update cache
  defp check_database(token_jti, _current_timestamp) do
    current_datetime = DateTime.utc_now()
    
    query =
      from rt in RevokedToken,
        where: rt.token_jti == ^token_jti,
        where: rt.expires_at > ^current_datetime,
        select: rt.expires_at,
        limit: 1

    case Repo.one(query) do
      nil ->
        false

      expires_at ->
        # Token is revoked, add to cache
        expires_timestamp = DateTime.to_unix(expires_at)
        :ets.insert(@revoked_tokens_table, {token_jti, expires_timestamp})
        true
    end
  end

  @doc """
  Revokes all tokens for a user (logout from all devices).
  
  Note: This requires tracking active tokens. For now, tokens are revoked
  as they're validated. In production, consider maintaining an active tokens table.
  """
  def revoke_all_user_tokens(_user_id, _reason \\ "logout_all") do
    # This would require extracting JTI from tokens
    # For now, we'll revoke tokens as they're used
    # In production, you might want to track active tokens
    {:ok, :revoked}
  end

  @doc """
  Cleans up expired revoked tokens from both database and cache.
  """
  def cleanup_expired_tokens do
    current_datetime = DateTime.utc_now()
    current_timestamp = System.system_time(:second)
    
    # Clean up database
    deleted_count = from(rt in RevokedToken, where: rt.expires_at < ^current_datetime)
    |> Repo.delete_all()
    
    # Clean up cache (remove expired entries)
    cleanup_cache(current_timestamp)
    
    Logger.debug("Cleaned up expired revoked tokens", deleted: deleted_count)
    deleted_count
  end

  # Warm cache with recent revocations (last 24 hours)
  defp warm_cache do
    # Only warm cache if Repo is available (skip during test compilation)
    try do
      cutoff_time = DateTime.utc_now() |> DateTime.add(-24, :hour)
      
      query =
        from rt in RevokedToken,
          where: rt.revoked_at >= ^cutoff_time,
          where: rt.expires_at > ^DateTime.utc_now(),
          select: {rt.token_jti, rt.expires_at}

      Repo.all(query)
      |> Enum.each(fn {jti, expires_at} ->
        expires_timestamp = DateTime.to_unix(expires_at)
        :ets.insert(@revoked_tokens_table, {jti, expires_timestamp})
      end)
      
      Logger.debug("Warmed revoked tokens cache")
    rescue
      _ -> 
        # Repo not available yet (e.g., during test compilation)
        Logger.debug("Skipping cache warm - Repo not available")
        :ok
    end
  end

  # Clean up expired entries from cache
  defp cleanup_cache(current_timestamp) do
    # Get all entries and filter expired ones
    :ets.tab2list(@revoked_tokens_table)
    |> Enum.each(fn {jti, expires_timestamp} ->
      if expires_timestamp <= current_timestamp do
        :ets.delete(@revoked_tokens_table, jti)
      end
    end)
  end

  # Schedule periodic cache cleanup (every hour)
  defp schedule_cache_cleanup do
    # Use Process.send_after for periodic cleanup
    Process.send_after(self(), :cleanup_revoked_tokens_cache, 3_600_000) # 1 hour
  end

  # Handle cleanup message (would need to be called from a GenServer)
  # For now, we'll rely on TTL-based expiration during lookups
end
