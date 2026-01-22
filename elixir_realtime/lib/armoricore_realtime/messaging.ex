# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp
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

defmodule ArmoricoreRealtime.Messaging do
  @moduledoc """
  Messaging context.
  Provides functions for direct messages, group chats, and group messages.
  """

  import Ecto.Query, warn: false
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Messaging.{
    DirectMessage,
    GroupChat,
    GroupChatMember,
    GroupMessage,
    MessageReaction,
    MessageReadReceipt
  }

  ## Direct Messages

  @doc """
  Send a direct message.
  """
  def send_direct_message(attrs \\ %{}) do
    %DirectMessage{}
    |> DirectMessage.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get conversation between two users.
  """
  def get_conversation(user1_id, user2_id, opts \\ []) do
    query = from dm in DirectMessage,
      where: (dm.sender_id == ^user1_id and dm.recipient_id == ^user2_id) or
             (dm.sender_id == ^user2_id and dm.recipient_id == ^user1_id),
      order_by: [asc: dm.inserted_at],
      preload: [:sender, :recipient, :media]

    query
    |> apply_dm_filters(opts)
    |> apply_pagination(opts)
    |> Repo.all()
  end

  @doc """
  List conversations for a user (get most recent message from each conversation).
  """
  def list_conversations(user_id, opts \\ []) do
    # Get distinct conversations with most recent message
    query = from dm in DirectMessage,
      where: dm.sender_id == ^user_id or dm.recipient_id == ^user_id,
      distinct: dm.id,
      order_by: [desc: dm.inserted_at],
      preload: [:sender, :recipient, :media]

    query
    |> apply_pagination(opts)
    |> Repo.all()
    |> group_conversations(user_id)
  end

  @doc """
  Mark direct messages as delivered.
  """
  def mark_dm_delivered(recipient_id, sender_id) do
    from(dm in DirectMessage,
      where: dm.recipient_id == ^recipient_id and
             dm.sender_id == ^sender_id and
             dm.status == "sent"
    )
    |> Repo.update_all(set: [status: "delivered"])
  end

  @doc """
  Mark direct message as read.
  """
  def mark_dm_read(message_id, user_id) do
    case Repo.get(DirectMessage, message_id) do
      nil ->
        {:error, :not_found}

      message ->
        if message.recipient_id == user_id do
          message
          |> DirectMessage.changeset(%{
            status: "read",
            read_at: DateTime.utc_now()
          })
          |> Repo.update()
        else
          {:error, :unauthorized}
        end
    end
  end

  @doc """
  Get unread message count for a user.
  """
  def get_unread_dm_count(user_id) do
    from(dm in DirectMessage,
      where: dm.recipient_id == ^user_id and dm.status != "read"
    )
    |> Repo.aggregate(:count)
  end

  ## Group Chats

  @doc """
  Create a group chat.
  """
  def create_group_chat(attrs \\ %{}) do
    result = %GroupChat{}
    |> GroupChat.changeset(attrs)
    |> Repo.insert()

    case result do
      {:ok, group_chat} ->
        # Add creator as admin member
        add_member_to_group_chat(group_chat.id, attrs[:creator_id], "admin")
        # Reload with members
        {:ok, Repo.preload(group_chat, [:members, :creator])}

      error ->
        error
    end
  end

  @doc """
  Get a group chat.
  """
  def get_group_chat!(id) do
    Repo.get!(GroupChat, id)
    |> Repo.preload([:members, :creator, :avatar_media])
  end

  @doc """
  List group chats for a user.
  """
  def list_group_chats(user_id, opts \\ []) do
    query = from gc in GroupChat,
      join: gcm in GroupChatMember,
      on: gc.id == gcm.group_chat_id,
      where: gcm.user_id == ^user_id and is_nil(gcm.left_at),
      preload: [:members, :creator, :avatar_media]

    query
    |> apply_group_chat_filters(opts)
    |> Repo.all()
  end

  @doc """
  Update a group chat.
  """
  def update_group_chat(%GroupChat{} = group_chat, attrs) do
    group_chat
    |> GroupChat.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a group chat.
  """
  def delete_group_chat(%GroupChat{} = group_chat) do
    Repo.delete(group_chat)
  end

  @doc """
  Add member to group chat.
  """
  def add_member_to_group_chat(group_chat_id, user_id, role \\ "member") do
    # Check if already a member
    existing = Repo.get_by(GroupChatMember, group_chat_id: group_chat_id, user_id: user_id)

    case existing do
      nil ->
        # Create new membership
        %GroupChatMember{}
        |> GroupChatMember.changeset(%{
          group_chat_id: group_chat_id,
          user_id: user_id,
          role: role,
          joined_at: DateTime.utc_now()
        })
        |> Repo.insert()
        |> update_group_chat_member_count(group_chat_id)

      %GroupChatMember{left_at: nil} ->
        # Already a member
        {:ok, existing}

      member ->
        # Re-join
        member
        |> GroupChatMember.changeset(%{
          left_at: nil,
          joined_at: DateTime.utc_now()
        })
        |> Repo.update()
        |> update_group_chat_member_count(group_chat_id)
    end
  end

  @doc """
  Remove member from group chat.
  """
  def remove_member_from_group_chat(group_chat_id, user_id) do
    case Repo.get_by(GroupChatMember, group_chat_id: group_chat_id, user_id: user_id) do
      nil ->
        {:error, :not_found}

      member ->
        member
        |> GroupChatMember.changeset(%{left_at: DateTime.utc_now()})
        |> Repo.update()
        |> update_group_chat_member_count(group_chat_id)
    end
  end

  @doc """
  Check if user is member of group chat.
  """
  def is_group_chat_member?(group_chat_id, user_id) do
    Repo.exists?(
      from gcm in GroupChatMember,
      where: gcm.group_chat_id == ^group_chat_id and
             gcm.user_id == ^user_id and
             is_nil(gcm.left_at)
    )
  end

  @doc """
  Get user's role in group chat.
  """
  def get_user_role_in_group_chat(group_chat_id, user_id) do
    case Repo.get_by(GroupChatMember, group_chat_id: group_chat_id, user_id: user_id) do
      nil -> nil
      %GroupChatMember{left_at: left_at} when not is_nil(left_at) -> nil
      %GroupChatMember{role: role} -> role
    end
  end

  defp update_group_chat_member_count({:ok, _member}, group_chat_id) do
    count = from(gcm in GroupChatMember,
      where: gcm.group_chat_id == ^group_chat_id and is_nil(gcm.left_at)
    )
    |> Repo.aggregate(:count)

    case Repo.get(GroupChat, group_chat_id) do
      nil -> :ok
      group_chat ->
        update_group_chat(group_chat, %{member_count: count})
        :ok
    end
  end
  defp update_group_chat_member_count(error, _group_chat_id), do: error

  ## Group Messages

  @doc """
  Send a group message.
  """
  def send_group_message(attrs \\ %{}) do
    %GroupMessage{}
    |> GroupMessage.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  List messages in a group chat.
  """
  def list_group_messages(group_chat_id, opts \\ []) do
    query = from(gm in GroupMessage,
      where: gm.group_chat_id == ^group_chat_id and gm.is_deleted == false,
      order_by: [desc: gm.is_pinned, desc: gm.inserted_at],
      preload: [:sender, :media, :reply_to, :reactions]
    )

    query
    |> apply_group_message_filters(opts)
    |> apply_pagination(opts)
    |> Repo.all()
  end

  @doc """
  Get a single group message.
  """
  def get_group_message!(id) do
    Repo.get!(GroupMessage, id)
    |> Repo.preload([:sender, :group_chat, :media, :reply_to, :reactions])
  end

  @doc """
  Update a group message.
  """
  def update_group_message(%GroupMessage{} = message, attrs) do
    message
    |> GroupMessage.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a group message (soft delete).
  """
  def delete_group_message(%GroupMessage{} = message) do
    message
    |> GroupMessage.changeset(%{is_deleted: true})
    |> Repo.update()
  end

  @doc """
  Pin a group message.
  """
  def pin_group_message(message_id) do
    case Repo.get(GroupMessage, message_id) do
      nil -> {:error, :not_found}
      message ->
        update_group_message(message, %{is_pinned: true})
    end
  end

  @doc """
  Unpin a group message.
  """
  def unpin_group_message(message_id) do
    case Repo.get(GroupMessage, message_id) do
      nil -> {:error, :not_found}
      message ->
        update_group_message(message, %{is_pinned: false})
    end
  end

  @doc """
  Mark group message as read.
  """
  def mark_group_message_read(message_id, user_id) do
    # Check if already read
    existing = Repo.get_by(MessageReadReceipt, message_id: message_id, user_id: user_id)

    case existing do
      nil ->
        %MessageReadReceipt{}
        |> MessageReadReceipt.changeset(%{
          message_id: message_id,
          user_id: user_id,
          read_at: DateTime.utc_now()
        })
        |> Repo.insert()

      _receipt ->
        {:ok, existing}
    end
  end

  @doc """
  Get unread message count for a user in a group chat.
  """
  def get_unread_group_message_count(group_chat_id, user_id) do
    # Count messages sent after user joined
    joined_at = from(gcm in GroupChatMember,
      where: gcm.group_chat_id == ^group_chat_id and gcm.user_id == ^user_id,
      select: gcm.joined_at
    )
    |> Repo.one()

    if joined_at do
      # Count messages not read by user
      total = from(gm in GroupMessage,
        where: gm.group_chat_id == ^group_chat_id and
               gm.inserted_at >= ^joined_at and
               gm.is_deleted == false
      )
      |> Repo.aggregate(:count)

      read = from(mrr in MessageReadReceipt,
        join: gm in GroupMessage,
        on: mrr.message_id == gm.id,
        where: gm.group_chat_id == ^group_chat_id and
               mrr.user_id == ^user_id and
               gm.inserted_at >= ^joined_at
      )
      |> Repo.aggregate(:count)

      total - read
    else
      0
    end
  end

  ## Message Reactions

  @doc """
  Add reaction to a message.
  """
  def add_message_reaction(user_id, message_type, message_id, emoji) do
    # Check if already reacted with same emoji
    existing = Repo.get_by(MessageReaction,
      user_id: user_id,
      message_type: message_type,
      message_id: message_id,
      emoji: emoji
    )

    case existing do
      nil ->
        %MessageReaction{}
        |> MessageReaction.changeset(%{
          user_id: user_id,
          message_type: message_type,
          message_id: message_id,
          emoji: emoji
        })
        |> Repo.insert()

      _reaction ->
        # Already reacted, return existing
        {:ok, existing}
    end
  end

  @doc """
  Remove reaction from a message.
  """
  def remove_message_reaction(user_id, message_type, message_id, emoji) do
    case Repo.get_by(MessageReaction,
      user_id: user_id,
      message_type: message_type,
      message_id: message_id,
      emoji: emoji
    ) do
      nil -> {:error, :not_found}
      reaction -> Repo.delete(reaction)
    end
  end

  @doc """
  Get reactions for a message.
  """
  def get_message_reactions(message_type, message_id) do
    from(mr in MessageReaction,
      where: mr.message_type == ^message_type and mr.message_id == ^message_id,
      preload: [:user]
    )
    |> Repo.all()
  end

  ## Helper functions

  defp group_conversations(messages, user_id) do
    messages
    |> Enum.group_by(fn dm ->
      if dm.sender_id == user_id, do: dm.recipient_id, else: dm.sender_id
    end)
    |> Enum.map(fn {other_user_id, dms} ->
      # Get most recent message
      most_recent = Enum.max_by(dms, &DateTime.to_unix(&1.inserted_at))
      %{
        other_user: if(most_recent.sender_id == user_id, do: most_recent.recipient, else: most_recent.sender),
        last_message: most_recent,
        unread_count: Enum.count(dms, &(&1.recipient_id == user_id && &1.status != "read"))
      }
    end)
  end

  defp apply_dm_filters(query, opts) do
    query
    |> maybe_filter_dm_status(opts[:status])
    |> maybe_filter_dm_type(opts[:message_type])
  end

  defp maybe_filter_dm_status(query, nil), do: query
  defp maybe_filter_dm_status(query, status) do
    from dm in query, where: dm.status == ^status
  end

  defp maybe_filter_dm_type(query, nil), do: query
  defp maybe_filter_dm_type(query, message_type) do
    from dm in query, where: dm.message_type == ^message_type
  end

  defp apply_group_chat_filters(query, opts) do
    query
    |> maybe_filter_group_chat_encrypted(opts[:is_encrypted])
  end

  defp maybe_filter_group_chat_encrypted(query, nil), do: query
  defp maybe_filter_group_chat_encrypted(query, is_encrypted) do
    from gc in query, where: gc.is_encrypted == ^is_encrypted
  end

  defp apply_group_message_filters(query, opts) do
    query
    |> maybe_filter_group_message_type(opts[:message_type])
    |> maybe_filter_group_message_pinned(opts[:pinned_only])
  end

  defp maybe_filter_group_message_type(query, nil), do: query
  defp maybe_filter_group_message_type(query, message_type) do
    from gm in query, where: gm.message_type == ^message_type
  end

  defp maybe_filter_group_message_pinned(query, nil), do: query
  defp maybe_filter_group_message_pinned(query, true) do
    from gm in query, where: gm.is_pinned == true
  end
  defp maybe_filter_group_message_pinned(query, false), do: query

  defp apply_pagination(query, opts) do
    limit = opts[:limit] || 50
    offset = (opts[:page] || 1 - 1) * limit
    from q in query, limit: ^limit, offset: ^offset
  end
end

