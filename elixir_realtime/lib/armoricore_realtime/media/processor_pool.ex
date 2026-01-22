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

defmodule ArmoricoreRealtime.Media.ProcessorPool do
  @moduledoc """
  Task pool for processing multiple videos simultaneously.
  
  This module provides concurrent processing of media files with configurable
  concurrency limits to prevent system overload.
  
  ## Example
      
      # Process multiple videos concurrently
      videos = [
        %{media_id: "123", file_path: "s3://bucket/video1.mp4", priority: :high},
        %{media_id: "456", file_path: "s3://bucket/video2.mp4", priority: :normal}
      ]
      
      ArmoricoreRealtime.Media.ProcessorPool.process_batch(videos)
  """

  use GenServer
  require Logger

  @default_max_concurrency 4
  @default_timeout 300_000 # 5 minutes

  ## Client API

  @doc """
  Starts the processor pool supervisor.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Process a batch of videos concurrently.
  
  ## Parameters
  - `videos` - List of video maps with `:media_id`, `:file_path`, `:content_type`, and optional `:priority`
  - `opts` - Options:
    - `:max_concurrency` - Maximum number of concurrent processes (default: 4)
    - `:timeout` - Timeout per video in milliseconds (default: 300000)
  
  ## Returns
  - `{:ok, results}` - List of `{:ok, result}` or `{:error, reason}` tuples
  """
  def process_batch(videos, opts \\ []) do
    max_concurrency = Keyword.get(opts, :max_concurrency, @default_max_concurrency)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    Logger.info("Processing batch of #{length(videos)} videos with max_concurrency=#{max_concurrency}")

    videos
    |> Enum.map(fn video ->
      Task.async(fn ->
        process_video(video, timeout)
      end)
    end)
    |> Task.yield_many(timeout + 1000) # Add buffer for yield_many
    |> Enum.map(fn {task, result} ->
      case result do
        {:ok, value} -> value
        {:exit, reason} -> {:error, reason}
        nil -> 
          Task.shutdown(task, :brutal_kill)
          {:error, :timeout}
      end
    end)
  end

  @doc """
  Process a single video by publishing to message bus.
  
  ## Parameters
  - `video` - Map with `:media_id`, `:file_path`, `:content_type`, and optional `:priority`
  - `timeout` - Timeout in milliseconds
  
  ## Returns
  - `{:ok, media_id}` on success
  - `{:error, reason}` on failure
  """
  def process_video(video, _timeout \\ @default_timeout) do
    %{media_id: media_id, file_path: file_path, content_type: content_type} = video
    priority = Map.get(video, :priority, :normal)
    user_id = Map.get(video, :user_id, "00000000-0000-0000-0000-000000000000")

    Logger.info("Processing video: #{media_id} (priority: #{priority})")

    # Publish media.uploaded event to NATS
    case publish_media_uploaded_event(media_id, user_id, file_path, content_type, priority) do
      :ok ->
        Logger.info("Published media.uploaded event for #{media_id}")
        {:ok, media_id}
      
      {:error, reason} = error ->
        Logger.error("Failed to publish event for #{media_id}: #{inspect(reason)}")
        error
    end
  end

  @doc """
  Process videos using async_stream for better backpressure control.
  
  ## Parameters
  - `videos` - List of video maps
  - `opts` - Options:
    - `:max_concurrency` - Maximum concurrent processes (default: 4)
    - `:timeout` - Timeout per video (default: 300000)
    - `:ordered` - Whether to maintain order (default: false)
  
  ## Returns
  - Stream of results
  """
  def process_stream(videos, opts \\ []) do
    max_concurrency = Keyword.get(opts, :max_concurrency, @default_max_concurrency)
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    ordered = Keyword.get(opts, :ordered, false)

    videos
    |> Task.async_stream(
      fn video -> process_video(video, timeout) end,
      max_concurrency: max_concurrency,
      timeout: timeout,
      ordered: ordered,
      on_timeout: :kill_task
    )
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    {:ok, %{
      max_concurrency: @default_max_concurrency,
      active_tasks: 0,
      queue: :queue.new()
    }}
  end

  ## Private Functions

  defp publish_media_uploaded_event(media_id, user_id, file_path, content_type, priority) do
    # Get Gnat connection from MessageBus
    case GenServer.call(ArmoricoreRealtime.MessageBus, :get_gnat) do
      {:ok, gnat} ->
        event = %{
          event_type: "media.uploaded",
          event_id: Ecto.UUID.generate(),
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
          source: "elixir-realtime",
          payload: %{
            media_id: media_id,
            user_id: user_id,
            file_path: file_path,
            content_type: content_type,
            priority: priority,
            metadata: %{}
          }
        }

        subject = "armoricore.media_uploaded"
        
        case Jason.encode(event) do
          {:ok, body} ->
            case Gnat.pub(gnat, subject, body) do
              :ok -> :ok
              {:error, reason} -> {:error, reason}
            end
          
          {:error, reason} ->
            {:error, {:json_encode, reason}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
