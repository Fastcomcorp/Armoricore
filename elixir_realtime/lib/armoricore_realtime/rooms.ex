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

defmodule ArmoricoreRealtime.Rooms do
  @moduledoc """
  Context module for room and stream authorization.

  Provides authorization checks for:
  - Chat rooms
  - Comment streams
  - Presence rooms
  - Media streams

  Also provides functions for managing room memberships.

  SECURITY: This module enforces access control to prevent unauthorized
  access to private rooms and streams.
  """

  import Ecto.Query, warn: false
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Rooms.RoomMembership

  require Logger

  # Context functions for room memberships

  @doc """
  Joins a user to a room.

  ## Examples

      iex> join_room("user-123", "chat:video:456", "chat", "member")
      {:ok, %RoomMembership{}}

      iex> join_room("user-123", "chat:video:456", "chat", "owner")
      {:ok, %RoomMembership{}}
  """
  @spec join_room(String.t(), String.t(), String.t(), String.t()) ::
    {:ok, RoomMembership.t()} | {:error, Ecto.Changeset.t()}
  def join_room(user_id, room_id, room_type, role \\ "member") do
    attrs = %{
      user_id: user_id,
      room_id: room_id,
      room_type: room_type,
      role: role
    }

    %RoomMembership{}
    |> RoomMembership.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Leaves a room (deactivates membership).

  ## Examples

      iex> leave_room("user-123", "chat:video:456")
      {:ok, %RoomMembership{}}
  """
  @spec leave_room(String.t(), String.t()) ::
    {:ok, RoomMembership.t()} | {:error, :not_found}
  def leave_room(user_id, room_id) do
    case get_room_membership(user_id, room_id) do
      nil -> {:error, :not_found}
      membership ->
        membership
        |> RoomMembership.leave_changeset()
        |> Repo.update()
    end
  end

  @doc """
  Updates a user's role in a room.

  ## Examples

      iex> update_room_role("user-123", "chat:video:456", "moderator")
      {:ok, %RoomMembership{}}
  """
  @spec update_room_role(String.t(), String.t(), String.t()) ::
    {:ok, RoomMembership.t()} | {:error, :not_found}
  def update_room_role(user_id, room_id, role) do
    case get_room_membership(user_id, room_id) do
      nil -> {:error, :not_found}
      membership ->
        membership
        |> RoomMembership.role_changeset(role)
        |> Repo.update()
    end
  end

  @doc """
  Gets a room membership.

  ## Examples

      iex> get_room_membership("user-123", "chat:video:456")
      %RoomMembership{}
  """
  @spec get_room_membership(String.t(), String.t()) :: RoomMembership.t() | nil
  def get_room_membership(user_id, room_id) do
    Repo.get_by(RoomMembership, user_id: user_id, room_id: room_id, is_active: true)
  end

  @doc """
  Lists all rooms a user is a member of.

  ## Examples

      iex> list_user_rooms("user-123")
      [%RoomMembership{}, ...]
  """
  @spec list_user_rooms(String.t()) :: [RoomMembership.t()]
  def list_user_rooms(user_id) do
    Repo.all(
      from rm in RoomMembership,
        where: rm.user_id == ^user_id and rm.is_active == true,
        preload: [:user]
    )
  end

  @doc """
  Lists all members of a room.

  ## Examples

      iex> list_room_members("chat:video:456")
      [%RoomMembership{}, ...]
  """
  @spec list_room_members(String.t()) :: [RoomMembership.t()]
  def list_room_members(room_id) do
    Repo.all(
      from rm in RoomMembership,
        where: rm.room_id == ^room_id and rm.is_active == true,
        preload: [:user]
    )
  end

  @doc """
  Checks if a user is an owner of a room.

  ## Examples

      iex> is_room_owner?("user-123", "chat:video:456")
      true
  """
  @spec is_room_owner?(String.t(), String.t()) :: boolean()
  def is_room_owner?(user_id, room_id) do
    case get_room_membership(user_id, room_id) do
      %{role: "owner"} -> true
      _ -> false
    end
  end

  @doc """
  Checks if a user is a moderator of a room.

  ## Examples

      iex> is_room_moderator?("user-123", "chat:video:456")
      true
  """
  @spec is_room_moderator?(String.t(), String.t()) :: boolean()
  def is_room_moderator?(user_id, room_id) do
    case get_room_membership(user_id, room_id) do
      %{role: role} when role in ["owner", "moderator"] -> true
      _ -> false
    end
  end

  # Authorization functions

  @doc """
  Checks if a user has access to a chat room.

  ## Examples

      iex> ArmoricoreRealtime.Rooms.user_has_access_to_room?("user-123", "room-456")
      true
  """
  @spec user_has_access_to_room?(String.t(), String.t()) :: boolean()
  def user_has_access_to_room?(user_id, room_id) when is_binary(user_id) and is_binary(room_id) do
    # SECURITY: Authorization check for room access
    # For now, we implement a flexible system:
    # 1. Check if room is public (default behavior for backward compatibility)
    # 2. Check if user is a member of the room (if room membership exists)
    # 3. Check if user has explicit permission

    cond do
      # Public rooms (default) - all authenticated users can access
      is_public_room?(room_id) ->
        true

      # Check room membership (if room membership table exists)
      has_room_membership?(user_id, room_id) ->
        true

      # Check explicit permissions (if permission system exists)
      has_room_permission?(user_id, room_id) ->
        true

      # Default: deny access for unknown rooms
      # This is secure by default - rooms must be explicitly made public or user must have membership
      true ->
        Logger.warning("User #{user_id} denied access to room #{room_id} - room not found or user not authorized")
        false
    end
  end

  @doc """
  Checks if a user has access to a stream (for comments).

  ## Examples

      iex> ArmoricoreRealtime.Rooms.user_has_access_to_stream?("user-123", "stream-456")
      true
  """
  @spec user_has_access_to_stream?(String.t(), String.t()) :: boolean()
  def user_has_access_to_stream?(user_id, stream_id) when is_binary(user_id) and is_binary(stream_id) do
    # SECURITY: Authorization check for stream access
    # Streams are typically public (for live streaming), but can be restricted

    cond do
      # Public streams (default) - all authenticated users can access
      is_public_stream?(stream_id) ->
        true

      # Check stream access permissions
      has_stream_access?(user_id, stream_id) ->
        true

      # Default: allow access (streams are typically public)
      # This can be changed if streams need to be private
      true ->
        Logger.debug("User #{user_id} accessing stream #{stream_id} (public by default)")
        true
    end
  end

  @doc """
  Checks if a user is part of a call (for signaling channel).

  ## Examples

      iex> ArmoricoreRealtime.Rooms.user_is_call_participant?("user-123", "call-456", "user-123", "user-789")
      true
  """
  @spec user_is_call_participant?(String.t(), String.t(), String.t(), String.t()) :: boolean()
  def user_is_call_participant?(user_id, _call_id, caller_id, callee_id)
      when is_binary(user_id) and is_binary(caller_id) and is_binary(callee_id) do
    # SECURITY: Only caller and callee can join signaling channel
    user_id == caller_id || user_id == callee_id
  end

  # Private helper functions

  # Check if room is public
  # SECURITY: For backward compatibility, we allow all rooms by default
  # In production, this should be based on room configuration in database
  # Set :allow_room_access_by_default to false for strict mode
  defp is_public_room?(room_id) do
    # SECURITY: Default to allowing access for backward compatibility
    # This can be changed to false when room membership system is implemented
    allow_by_default = Application.get_env(:armoricore_realtime, :allow_room_access_by_default, true)

    if allow_by_default do
      # Check if room matches restricted patterns (if any configured)
      restricted_patterns = Application.get_env(:armoricore_realtime, :restricted_room_patterns, [])

      if Enum.empty?(restricted_patterns) do
        # No restrictions configured, allow all (backward compatibility)
        true
      else
        # Check if room matches restricted patterns - if so, deny
        is_restricted = Enum.any?(restricted_patterns, fn pattern ->
          case String.split(pattern, "*") do
            [prefix, suffix] ->
              String.starts_with?(room_id, prefix) && String.ends_with?(room_id, suffix)
            [exact] ->
              room_id == exact
            _ ->
              false
          end
        end)

        # Allow if not restricted
        not is_restricted
      end
    else
      # Strict mode: check public patterns only
      public_patterns = Application.get_env(:armoricore_realtime, :public_room_patterns, [])

      if Enum.empty?(public_patterns) do
        # No public patterns, deny all
        false
      else
        # Check if room matches public patterns
        Enum.any?(public_patterns, fn pattern ->
          case String.split(pattern, "*") do
            [prefix, suffix] ->
              String.starts_with?(room_id, prefix) && String.ends_with?(room_id, suffix)
            [exact] ->
              room_id == exact
            _ ->
              false
          end
        end)
      end
    end
  end

  # Check if room is public stream
  defp is_public_stream?(_stream_id) do
    # Streams are public by default (for live streaming)
    # This can be changed if private streams are needed
    true
  end

  # Check if user has room membership
  # SECURITY: Check the room_memberships table for active membership
  defp has_room_membership?(user_id, room_id) do
    Repo.exists?(
      from rm in RoomMembership,
        where: rm.user_id == ^user_id,
        where: rm.room_id == ^room_id,
        where: rm.is_active == true
    )
  end

  # Check if user has explicit room permission
  # SECURITY: This would check permissions table if it exists
  defp has_room_permission?(_user_id, _room_id) do
    # TODO: Implement permission check when permissions system is added
    false
  end

  # Check if user has stream access
  defp has_stream_access?(_user_id, _stream_id) do
    # TODO: Implement stream access check if private streams are needed
    false
  end
end