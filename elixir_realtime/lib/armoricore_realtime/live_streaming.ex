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

defmodule ArmoricoreRealtime.LiveStreaming do
  @moduledoc """
  Live streaming context.
  Provides functions for managing live streams, stream keys, analytics, and recordings.
  """

  import Ecto.Query, warn: false
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.LiveStreaming.{
    LiveStream,
    StreamKey,
    StreamAnalytic,
    StreamRecording,
    StreamQualityProfile
  }

  ## Live Streams

  @doc """
  Create a live stream.
  """
  def create_live_stream(attrs \\ %{}) do
    # Generate stream key if not provided
    attrs = if Map.has_key?(attrs, :stream_key) do
      attrs
    else
      Map.put(attrs, :stream_key, generate_stream_key())
    end

    %LiveStream{}
    |> LiveStream.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Get a live stream.
  """
  def get_live_stream!(id) do
    stream = Repo.get!(LiveStream, id)
    # Preload sequentially to avoid sandbox connection issues
    stream
    |> Repo.preload(:user)
    |> Repo.preload(:category)
    |> Repo.preload(:quality_profiles)
    |> Repo.preload(:recordings)
  end

  @doc """
  Get a live stream by stream key.
  """
  def get_live_stream_by_key(stream_key) do
    Repo.get_by(LiveStream, stream_key: stream_key)
    |> Repo.preload([:user, :category])
  end

  @doc """
  List live streams.
  """
  def list_live_streams(opts \\ []) do
    query = from ls in LiveStream,
      preload: [:user, :category]

    query
    |> apply_stream_filters(opts)
    |> apply_stream_sorting(opts)
    |> apply_pagination(opts)
    |> Repo.all()
  end

  @doc """
  List active (live) streams.
  """
  def list_active_streams(opts \\ []) do
    query = from ls in LiveStream,
      where: ls.status == "live",
      preload: [:user, :category]

    query
    |> apply_stream_sorting(opts)
    |> apply_pagination(opts)
    |> Repo.all()
  end

  @doc """
  Update a live stream.
  """
  def update_live_stream(%LiveStream{} = live_stream, attrs) do
    live_stream
    |> LiveStream.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Start a live stream.
  """
  def start_live_stream(stream_id) do
    case Repo.get(LiveStream, stream_id) do
      nil ->
        {:error, :not_found}

      stream ->
        stream
        |> LiveStream.changeset(%{
          status: "live",
          started_at: DateTime.utc_now()
        })
        |> Repo.update()
    end
  end

  @doc """
  End a live stream.
  """
  def end_live_stream(stream_id) do
    case Repo.get(LiveStream, stream_id) do
      nil ->
        {:error, :not_found}

      stream ->
        ended_at = DateTime.utc_now()
        duration = if stream.started_at do
          DateTime.diff(ended_at, stream.started_at, :second)
        else
          0
        end

        stream
        |> LiveStream.changeset(%{
          status: "ended",
          ended_at: ended_at,
          duration_seconds: duration
        })
        |> Repo.update()
    end
  end

  @doc """
  Update viewer count for a stream.
  """
  def update_viewer_count(stream_id, current_viewers) do
    case Repo.get(LiveStream, stream_id) do
      nil ->
        :ok

      stream ->
        peak_viewers = max(stream.peak_viewers, current_viewers)
        # Only increment total_views for new viewers (not reconnections)
        total_views = if current_viewers > stream.current_viewers do
          stream.total_views + (current_viewers - stream.current_viewers)
        else
          stream.total_views
        end

        stream
        |> LiveStream.changeset(%{
          current_viewers: current_viewers,
          peak_viewers: peak_viewers,
          total_views: total_views
        })
        |> Repo.update()
        :ok
    end
  end

  @doc """
  Track a viewer joining a stream.
  """
  def track_viewer_join(stream_id, user_id, attrs \\ %{}) do
    # Track analytics event
    track_viewer_event(stream_id, "join", Map.merge(attrs, %{user_id: user_id}))

    # Update viewer count
    case Repo.get(LiveStream, stream_id) do
      nil ->
        :ok

      stream ->
        new_viewer_count = stream.current_viewers + 1
        update_viewer_count(stream_id, new_viewer_count)
    end
  end

  @doc """
  Track a viewer leaving a stream.
  """
  def track_viewer_leave(stream_id, user_id, attrs \\ %{}) do
    # Track analytics event
    track_viewer_event(stream_id, "leave", Map.merge(attrs, %{user_id: user_id}))

    # Update viewer count
    case Repo.get(LiveStream, stream_id) do
      nil ->
        :ok

      stream ->
        new_viewer_count = max(0, stream.current_viewers - 1)
        update_viewer_count(stream_id, new_viewer_count)
    end
  end

  @doc """
  Get stream analytics summary.
  """
  def get_stream_analytics(stream_id, opts \\ []) do
    query = from sa in StreamAnalytic,
      where: sa.stream_id == ^stream_id

    query
    |> maybe_filter_analytics_event_type(opts[:event_type])
    |> maybe_filter_analytics_date_range(opts[:start_date], opts[:end_date])
    |> Repo.all()
    |> then(fn events ->
      %{
        total_events: length(events),
        join_events: Enum.count(events, &(&1.event_type == "join")),
        leave_events: Enum.count(events, &(&1.event_type == "leave")),
        quality_changes: Enum.count(events, &(&1.event_type == "quality_change")),
        unique_viewers: events
          |> Enum.filter(&(&1.user_id != nil))
          |> Enum.map(& &1.user_id)
          |> Enum.uniq()
          |> length(),
        events: events
      }
    end)
  end

  @doc """
  Get concurrent viewers for a stream.
  """
  def get_concurrent_viewers(stream_id) do
    case Repo.get(LiveStream, stream_id) do
      nil ->
        {:error, :not_found}

      stream ->
        {:ok, %{
          current: stream.current_viewers,
          peak: stream.peak_viewers,
          total: stream.total_views
        }}
    end
  end

  @doc """
  Track viewer event (join/leave).
  """
  def track_viewer_event(stream_id, event_type, attrs \\ %{}) do
    %StreamAnalytic{}
    |> StreamAnalytic.changeset(Map.merge(attrs, %{
      stream_id: stream_id,
      event_type: event_type,
      timestamp: DateTime.utc_now()
    }))
    |> Repo.insert()
  end

  ## Stream Keys

  @doc """
  Generate a new stream key for a user.
  """
  def generate_stream_key_for_user(user_id, attrs \\ %{}) do
    # Use provided stream_key if available, otherwise generate one
    stream_key = Map.get(attrs, :stream_key) || generate_stream_key()

    %StreamKey{}
    |> StreamKey.changeset(Map.merge(attrs, %{
      user_id: user_id,
      stream_key: stream_key
    }))
    |> Repo.insert()
  end

  @doc """
  Validate a stream key.
  """
  def validate_stream_key(stream_key) do
    case Repo.get_by(StreamKey, stream_key: stream_key, is_active: true) do
      nil ->
        {:error, :invalid_key}

      key ->
        # Check expiration
        if key.expires_at && DateTime.compare(DateTime.utc_now(), key.expires_at) == :gt do
          {:error, :expired_key}
        else
          # Update last_used_at
          case key
               |> StreamKey.changeset(%{last_used_at: DateTime.utc_now()})
               |> Repo.update() do
            {:ok, updated_key} -> {:ok, updated_key}
            {:error, _changeset} -> {:ok, key}  # Return original key if update fails
          end
        end
    end
  end

  @doc """
  List stream keys for a user.
  """
  def list_stream_keys(user_id, opts \\ []) do
    query = from sk in StreamKey,
      where: sk.user_id == ^user_id

    query
    |> apply_stream_key_filters(opts)
    |> Repo.all()
  end

  @doc """
  Revoke a stream key.
  """
  def revoke_stream_key(stream_key_id) do
    case Repo.get(StreamKey, stream_key_id) do
      nil ->
        {:error, :not_found}

      key ->
        key
        |> StreamKey.changeset(%{is_active: false})
        |> Repo.update()
    end
  end

  ## Stream Recordings

  @doc """
  Start recording a stream.
  """
  def start_recording(stream_id, attrs \\ %{}) do
    %StreamRecording{}
    |> StreamRecording.changeset(Map.merge(attrs, %{
      stream_id: stream_id,
      recording_status: "recording",
      started_at: DateTime.utc_now()
    }))
    |> Repo.insert()
  end

  @doc """
  Update recording progress.
  """
  def update_recording(recording_id, attrs) do
    case Repo.get(StreamRecording, recording_id) do
      nil ->
        {:error, :not_found}

      recording ->
        recording
        |> StreamRecording.changeset(attrs)
        |> Repo.update()
    end
  end

  @doc """
  Complete recording and mark for processing.
  """
  def complete_recording(recording_id, media_id \\ nil) do
    case Repo.get(StreamRecording, recording_id) do
      nil ->
        {:error, :not_found}

      recording ->
        recording
        |> StreamRecording.changeset(%{
          recording_status: "processing",
          ended_at: DateTime.utc_now(),
          media_id: media_id
        })
        |> Repo.update()
    end
  end

  ## Stream Quality Profiles

  @doc """
  Create a quality profile for a stream.
  """
  def create_quality_profile(stream_id, attrs) do
    %StreamQualityProfile{}
    |> StreamQualityProfile.changeset(Map.put(attrs, :stream_id, stream_id))
    |> Repo.insert()
  end

  @doc """
  List quality profiles for a stream.
  """
  def list_quality_profiles(stream_id) do
    from(qp in StreamQualityProfile,
      where: qp.stream_id == ^stream_id and qp.is_active == true,
      order_by: [desc: qp.bitrate_kbps]
    )
    |> Repo.all()
  end

  @doc """
  Update quality profile.
  """
  def update_quality_profile(%StreamQualityProfile{} = profile, attrs) do
    profile
    |> StreamQualityProfile.changeset(attrs)
    |> Repo.update()
  end

  ## Helper functions

  defp generate_stream_key do
    # Generate a secure random stream key
    # Format: user-{random}-{timestamp}
    random = :crypto.strong_rand_bytes(16) |> Base.encode64(padding: false) |> String.slice(0, 16)
    timestamp = DateTime.utc_now() |> DateTime.to_unix() |> Integer.to_string()
    "sk-#{random}-#{timestamp}"
  end

  defp apply_stream_filters(query, opts) do
    query
    |> maybe_filter_stream_status(opts[:status])
    |> maybe_filter_stream_user(opts[:user_id])
    |> maybe_filter_stream_category(opts[:category_id])
    |> maybe_filter_stream_scheduled(opts[:scheduled_only])
  end

  defp maybe_filter_stream_status(query, nil), do: query
  defp maybe_filter_stream_status(query, status) do
    from ls in query, where: ls.status == ^status
  end

  defp maybe_filter_stream_user(query, nil), do: query
  defp maybe_filter_stream_user(query, user_id) do
    from ls in query, where: ls.user_id == ^user_id
  end

  defp maybe_filter_stream_category(query, nil), do: query
  defp maybe_filter_stream_category(query, category_id) do
    from ls in query, where: ls.category_id == ^category_id
  end

  defp maybe_filter_stream_scheduled(query, nil), do: query
  defp maybe_filter_stream_scheduled(query, true) do
    from ls in query, where: not is_nil(ls.scheduled_start_at)
  end
  defp maybe_filter_stream_scheduled(query, false), do: query

  defp apply_stream_sorting(query, opts) do
    case opts[:sort] do
      :viewers -> from ls in query, order_by: [desc: ls.current_viewers]
      :peak_viewers -> from ls in query, order_by: [desc: ls.peak_viewers]
      :scheduled -> from ls in query, order_by: [asc: ls.scheduled_start_at]
      :started -> from ls in query, order_by: [desc: ls.started_at]
      _ -> from ls in query, order_by: [desc: ls.inserted_at]
    end
  end

  defp apply_stream_key_filters(query, opts) do
    query
    |> maybe_filter_stream_key_active(opts[:is_active])
  end

  defp maybe_filter_stream_key_active(query, nil), do: query
  defp maybe_filter_stream_key_active(query, is_active) do
    from sk in query, where: sk.is_active == ^is_active
  end

  defp apply_pagination(query, opts) do
    limit = opts[:limit] || 20
    offset = (opts[:page] || 1 - 1) * limit
    from q in query, limit: ^limit, offset: ^offset
  end

  defp maybe_filter_analytics_event_type(query, nil), do: query
  defp maybe_filter_analytics_event_type(query, event_type) do
    from sa in query, where: sa.event_type == ^event_type
  end

  defp maybe_filter_analytics_date_range(query, nil, nil), do: query
  defp maybe_filter_analytics_date_range(query, start_date, nil) do
    from sa in query, where: sa.timestamp >= ^start_date
  end
  defp maybe_filter_analytics_date_range(query, nil, end_date) do
    from sa in query, where: sa.timestamp <= ^end_date
  end
  defp maybe_filter_analytics_date_range(query, start_date, end_date) do
    from sa in query, where: sa.timestamp >= ^start_date and sa.timestamp <= ^end_date
  end
end

