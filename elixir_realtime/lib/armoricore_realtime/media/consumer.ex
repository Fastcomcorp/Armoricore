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

defmodule ArmoricoreRealtime.Media.Consumer do
  @moduledoc """
  GenStage consumer for processing videos from the pipeline.
  
  This consumer:
  - Subscribes to the Pipeline producer
  - Processes videos with configurable concurrency
  - Handles errors gracefully
  - Reports processing statistics
  """

  use GenStage
  require Logger

  alias ArmoricoreRealtime.Media.ProcessorPool

  ## Client API

  @doc """
  Start the consumer.
  """
  def start_link(opts \\ []) do
    GenStage.start_link(__MODULE__, opts, name: __MODULE__)
  end

  ## GenStage Callbacks

  @impl true
  def init(opts) do
    max_concurrency = Keyword.get(opts, :max_concurrency, 4)
    timeout = Keyword.get(opts, :timeout, 300_000)

    state = %{
      max_concurrency: max_concurrency,
      timeout: timeout,
      processing: MapSet.new(),
      processed: 0,
      failed: 0,
      subscribed: false
    }

    # Subscribe to pipeline asynchronously
    GenStage.async_subscribe(
      __MODULE__,
      to: ArmoricoreRealtime.Media.Pipeline,
      max_demand: max_concurrency,
      min_demand: div(max_concurrency, 2)
    )

    {:consumer, state}
  end

  @impl true
  def handle_subscribe(:producer, _opts, _from, state) do
    Logger.info("Consumer subscribed to Pipeline")
    {:automatic, %{state | subscribed: true}}
  end

  @impl true
  def handle_events(events, _from, state) do
    Logger.info("Consumer received #{length(events)} events")

    # Process events concurrently
    results = Enum.map(events, fn video ->
      Task.async(fn ->
        process_video(video, state.timeout)
      end)
    end)
    |> Enum.map(fn task ->
      case Task.yield(task, state.timeout + 1000) do
        {:ok, result} -> result
        {:exit, reason} -> {:error, reason}
        nil ->
          Task.shutdown(task, :brutal_kill)
          {:error, :timeout}
      end
    end)

    # Update statistics
    {success, failures} = Enum.split_with(results, fn
      {:ok, _} -> true
      {:error, _} -> false
    end)

    new_state = %{
      state |
      processed: state.processed + length(success),
      failed: state.failed + length(failures)
    }

    # Log results
    if length(failures) > 0 do
      Logger.warning("Failed to process #{length(failures)} videos")
    end

    {:noreply, [], new_state}
  end

  ## Private Functions

  defp process_video(video, timeout) do
    Logger.info("Processing video: #{video.media_id} (priority: #{Map.get(video, :priority, :normal)})")
    
    ProcessorPool.process_video(video, timeout)
  end
end
