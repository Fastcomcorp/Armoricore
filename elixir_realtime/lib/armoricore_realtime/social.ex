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

defmodule ArmoricoreRealtime.Social do
  @moduledoc """
  Social engagement context.
  Provides functions for likes, subscriptions, playlists, watch history, and comments.
  """

  import Ecto.Query, warn: false
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Social.{
    VideoLike,
    Subscription,
    Playlist,
    WatchHistory,
    Comment,
    CommentLike
  }
  alias ArmoricoreRealtime.Content

  ## Video Likes

  @doc """
  Like or dislike a video.
  Returns {:ok, video_like} or {:error, changeset}
  """
  def like_video(user_id, video_id, action) when action in ["like", "dislike"] do
    # Check if user already liked/disliked this video
    existing = Repo.get_by(VideoLike, user_id: user_id, video_id: video_id)

    result = case existing do
      nil ->
        # Create new like/dislike
        %VideoLike{}
        |> VideoLike.changeset(%{user_id: user_id, video_id: video_id, action: action})
        |> Repo.insert()

      existing_like ->
        if existing_like.action == action do
          # User is trying to like/dislike again - remove it (toggle off)
          Repo.delete(existing_like)
          {:ok, :removed}
        else
          # User is changing from like to dislike or vice versa
          existing_like
          |> VideoLike.changeset(%{action: action})
          |> Repo.update()
        end
    end

    # Update video like/dislike counts
    case result do
      {:ok, _} ->
        update_video_like_counts(video_id)
        result
      error ->
        error
    end
  end

  @doc """
  Get user's like/dislike for a video.
  """
  def get_user_video_like(user_id, video_id) do
    Repo.get_by(VideoLike, user_id: user_id, video_id: video_id)
  end

  @doc """
  Check if user has liked a video.
  """
  def user_liked_video?(user_id, video_id) do
    case get_user_video_like(user_id, video_id) do
      %VideoLike{action: "like"} -> true
      _ -> false
    end
  end

  @doc """
  Check if user has disliked a video.
  """
  def user_disliked_video?(user_id, video_id) do
    case get_user_video_like(user_id, video_id) do
      %VideoLike{action: "dislike"} -> true
      _ -> false
    end
  end

  defp update_video_like_counts(video_id) do
    likes_count = Repo.aggregate(
      from(vl in VideoLike, where: vl.video_id == ^video_id and vl.action == "like"),
      :count
    )

    dislikes_count = Repo.aggregate(
      from(vl in VideoLike, where: vl.video_id == ^video_id and vl.action == "dislike"),
      :count
    )

    # Update video counts
    case Content.get_video(video_id) do
      nil -> :ok
      video ->
        Content.update_video(video, %{likes: likes_count, dislikes: dislikes_count})
        :ok
    end
  end

  ## Subscriptions

  @doc """
  Subscribe to a user/channel.
  """
  def subscribe(user_id, subscribed_to_id) do
    if user_id == subscribed_to_id do
      {:error, :cannot_subscribe_to_self}
    else
      case Repo.get_by(Subscription, subscriber_id: user_id, subscribed_to_id: subscribed_to_id) do
        nil ->
          %Subscription{}
          |> Subscription.changeset(%{
            subscriber_id: user_id,
            subscribed_to_id: subscribed_to_id,
            notifications_enabled: true
          })
          |> Repo.insert()

        existing ->
          {:ok, existing}
      end
    end
  end

  @doc """
  Unsubscribe from a user/channel.
  """
  def unsubscribe(user_id, subscribed_to_id) do
    case Repo.get_by(Subscription, subscriber_id: user_id, subscribed_to_id: subscribed_to_id) do
      nil ->
        {:error, :not_found}

      subscription ->
        Repo.delete(subscription)
    end
  end

  @doc """
  Check if user is subscribed to another user.
  """
  def is_subscribed?(user_id, subscribed_to_id) do
    Repo.exists?(from s in Subscription, where: s.subscriber_id == ^user_id and s.subscribed_to_id == ^subscribed_to_id)
  end

  @doc """
  Get user's subscriptions.
  """
  def list_subscriptions(user_id, opts \\ []) do
    query = from s in Subscription,
      where: s.subscriber_id == ^user_id,
      preload: [:subscribed_to]

    query
    |> apply_subscription_filters(opts)
    |> Repo.all()
  end

  @doc """
  Get user's subscribers.
  """
  def list_subscribers(user_id, opts \\ []) do
    query = from s in Subscription,
      where: s.subscribed_to_id == ^user_id,
      preload: [:subscriber]

    query
    |> apply_subscription_filters(opts)
    |> Repo.all()
  end

  @doc """
  Get subscription count for a user.
  """
  def get_subscription_count(user_id) do
    from(s in Subscription, where: s.subscribed_to_id == ^user_id)
    |> Repo.aggregate(:count)
  end

  ## Playlists

  @doc """
  List playlists for a user.
  """
  def list_playlists(user_id, opts \\ []) do
    query = from p in Playlist,
      where: p.user_id == ^user_id or p.visibility == "public"

    query
    |> apply_playlist_filters(opts)
    |> Repo.all()
    |> Repo.preload([:user, :videos])
  end

  @doc """
  Get a single playlist.
  """
  def get_playlist!(id) do
    Repo.get!(Playlist, id) |> Repo.preload([:user, :videos])
  end

  @doc """
  Create a playlist.
  """
  def create_playlist(attrs \\ %{}) do
    %Playlist{}
    |> Playlist.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Update a playlist.
  """
  def update_playlist(%Playlist{} = playlist, attrs) do
    playlist
    |> Playlist.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a playlist.
  """
  def delete_playlist(%Playlist{} = playlist) do
    Repo.delete(playlist)
  end

  @doc """
  Add video to playlist.
  """
  def add_video_to_playlist(playlist_id, video_id) do
    # Check if video already in playlist
    existing = Repo.one(
      from pv in "playlist_videos",
      where: pv.playlist_id == ^playlist_id and pv.video_id == ^video_id,
      select: pv.id
    )

    if existing do
      {:error, :already_in_playlist}
    else
      # Get current max position
      max_position = Repo.one(
        from pv in "playlist_videos",
        where: pv.playlist_id == ^playlist_id,
        select: max(pv.position)
      ) || 0

      # Insert video
      Repo.insert_all("playlist_videos", [[
        id: Ecto.UUID.generate(),
        playlist_id: playlist_id,
        video_id: video_id,
        position: max_position + 1,
        added_at: DateTime.utc_now(),
        inserted_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      ]])

      # Update playlist video count
      update_playlist_video_count(playlist_id)
      {:ok, :added}
    end
  end

  @doc """
  Remove video from playlist.
  """
  def remove_video_from_playlist(playlist_id, video_id) do
    deleted = Repo.delete_all(
      from pv in "playlist_videos",
      where: pv.playlist_id == ^playlist_id and pv.video_id == ^video_id
    )

    if deleted > 0 do
      update_playlist_video_count(playlist_id)
      {:ok, :removed}
    else
      {:error, :not_found}
    end
  end

  defp update_playlist_video_count(playlist_id) do
    count = from(pv in "playlist_videos", where: pv.playlist_id == ^playlist_id)
    |> Repo.aggregate(:count)

    case Repo.get(Playlist, playlist_id) do
      nil -> :ok
      playlist ->
        update_playlist(playlist, %{video_count: count})
        :ok
    end
  end

  ## Watch History

  @doc """
  Update watch history for a video.
  """
  def update_watch_history(user_id, video_id, watch_progress, video_duration) do
    watch_percentage = if video_duration > 0 do
      min(watch_progress / video_duration, 1.0)
    else
      0.0
    end

    completed = watch_percentage >= 0.9  # Consider 90%+ as completed

    case Repo.get_by(WatchHistory, user_id: user_id, video_id: video_id) do
      nil ->
        %WatchHistory{}
        |> WatchHistory.changeset(%{
          user_id: user_id,
          video_id: video_id,
          watch_progress: watch_progress,
          watch_percentage: watch_percentage,
          completed: completed,
          last_watched_at: DateTime.utc_now()
        })
        |> Repo.insert()

      history ->
        history
        |> WatchHistory.changeset(%{
          watch_progress: max(history.watch_progress, watch_progress),
          watch_percentage: max(history.watch_percentage, watch_percentage),
          completed: history.completed || completed,
          last_watched_at: DateTime.utc_now()
        })
        |> Repo.update()
    end
  end

  @doc """
  Get watch history for a user.
  """
  def list_watch_history(user_id, opts \\ []) do
    query = from wh in WatchHistory,
      where: wh.user_id == ^user_id,
      order_by: [desc: wh.last_watched_at]

    query
    |> apply_watch_history_filters(opts)
    |> apply_pagination(opts)
    |> Repo.all()
    |> Repo.preload([:video])
  end

  @doc """
  Get watch history for a specific video.
  """
  def get_watch_history(user_id, video_id) do
    Repo.get_by(WatchHistory, user_id: user_id, video_id: video_id)
    |> Repo.preload([:video])
  end

  @doc """
  Clear watch history for a user.
  """
  def clear_watch_history(user_id) do
    Repo.delete_all(from wh in WatchHistory, where: wh.user_id == ^user_id)
  end

  ## Comments

  @doc """
  Create a comment.
  """
  def create_comment(attrs \\ %{}) do
    %Comment{}
    |> Comment.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get comments for a video.
  """
  def list_comments(video_id, opts \\ []) do
    query = from c in Comment,
      where: c.video_id == ^video_id and c.is_deleted == false,
      order_by: [desc: c.is_pinned, desc: c.inserted_at],
      preload: [:user, :parent, :replies]

    query
    |> apply_comment_filters(opts)
    |> apply_pagination(opts)
    |> Repo.all()
  end

  @doc """
  Get a single comment.
  """
  def get_comment!(id) do
    Repo.get!(Comment, id) |> Repo.preload([:user, :video, :parent, :replies])
  end

  @doc """
  Update a comment.
  """
  def update_comment(%Comment{} = comment, attrs) do
    comment
    |> Comment.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Delete a comment (soft delete).
  """
  def delete_comment(%Comment{} = comment) do
    comment
    |> Comment.changeset(%{is_deleted: true})
    |> Repo.update()
  end

  @doc """
  Like or dislike a comment.
  """
  def like_comment(user_id, comment_id, action) when action in ["like", "dislike"] do
    existing = Repo.get_by(CommentLike, user_id: user_id, comment_id: comment_id)

    result = case existing do
      nil ->
        %CommentLike{}
        |> CommentLike.changeset(%{user_id: user_id, comment_id: comment_id, action: action})
        |> Repo.insert()

      existing_like ->
        if existing_like.action == action do
          Repo.delete(existing_like)
          {:ok, :removed}
        else
          existing_like
          |> CommentLike.changeset(%{action: action})
          |> Repo.update()
        end
    end

    # Update comment like/dislike counts
    case result do
      {:ok, _} ->
        update_comment_like_counts(comment_id)
        result
      error ->
        error
    end
  end

  defp update_comment_like_counts(comment_id) do
    likes_count = Repo.aggregate(
      from(cl in CommentLike, where: cl.comment_id == ^comment_id and cl.action == "like"),
      :count
    )

    dislikes_count = Repo.aggregate(
      from(cl in CommentLike, where: cl.comment_id == ^comment_id and cl.action == "dislike"),
      :count
    )

    case Repo.get(Comment, comment_id) do
      nil -> :ok
      comment ->
        update_comment(comment, %{likes: likes_count, dislikes: dislikes_count})
        :ok
    end
  end

  ## Helper functions

  defp apply_subscription_filters(query, opts) do
    query
    |> maybe_filter_notifications_enabled(opts[:notifications_enabled])
  end

  defp maybe_filter_notifications_enabled(query, nil), do: query
  defp maybe_filter_notifications_enabled(query, enabled) do
    from s in query, where: s.notifications_enabled == ^enabled
  end

  defp apply_playlist_filters(query, opts) do
    query
    |> maybe_filter_playlist_visibility(opts[:visibility])
    |> maybe_filter_playlist_user(opts[:user_id])
  end

  defp maybe_filter_playlist_visibility(query, nil), do: query
  defp maybe_filter_playlist_visibility(query, visibility) do
    from p in query, where: p.visibility == ^visibility
  end

  defp maybe_filter_playlist_user(query, nil), do: query
  defp maybe_filter_playlist_user(query, user_id) do
    from p in query, where: p.user_id == ^user_id
  end

  defp apply_watch_history_filters(query, opts) do
    query
    |> maybe_filter_watch_completed(opts[:completed])
  end

  defp maybe_filter_watch_completed(query, nil), do: query
  defp maybe_filter_watch_completed(query, completed) do
    from wh in query, where: wh.completed == ^completed
  end

  defp apply_comment_filters(query, opts) do
    query
    |> maybe_filter_comment_parent(opts[:parent_id])
    |> maybe_filter_comment_pinned(opts[:pinned_only])
  end

  defp maybe_filter_comment_parent(query, nil), do: query
  defp maybe_filter_comment_parent(query, parent_id) do
    from c in query, where: c.parent_id == ^parent_id
  end

  defp maybe_filter_comment_pinned(query, nil), do: query
  defp maybe_filter_comment_pinned(query, true) do
    from c in query, where: c.is_pinned == true
  end
  defp maybe_filter_comment_pinned(query, false), do: query

  defp apply_pagination(query, opts) do
    limit = opts[:limit] || 20
    offset = (opts[:page] || 1 - 1) * limit
    from q in query, limit: ^limit, offset: ^offset
  end
end

