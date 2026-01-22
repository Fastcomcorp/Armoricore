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

defmodule ArmoricoreRealtime.Media.Pipeline do
  @moduledoc """
  GenStage pipeline for high-volume media processing with backpressure.
  
  This module implements a producer-consumer pipeline that:
  - Handles backpressure automatically
  - Processes items based on priority
  - Supports high-volume processing
  - Provides flow control
  """

  use GenStage
  require Logger

  alias ArmoricoreRealtime.Media.PriorityQueue

  ## Client API

  @doc """
  Start the pipeline.
  """
  def start_link(opts \\ []) do
    GenStage.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Submit a video for processing.
  """
  def submit(video) do
    GenStage.cast(__MODULE__, {:submit, video})
  end

  @doc """
  Get pipeline statistics.
  """
  def stats do
    GenStage.call(__MODULE__, :stats)
  end

  ## GenStage Callbacks

  @impl true
  def init(_opts) do
    # Producer state
    # PriorityQueue is started by Application supervisor
    producer_state = %{
      demand: 0,
      queue: PriorityQueue
    }

    {:producer, producer_state}
  end

  @impl true
  def handle_demand(demand, state) when demand > 0 do
    # Increase demand
    new_demand = state.demand + demand
    state = %{state | demand: new_demand}
    
    # Try to dispatch events
    dispatch_events(state, [])
  end

  @impl true
  def handle_cast({:submit, video}, state) do
    # Enqueue the video
    PriorityQueue.enqueue(video)
    
    # Try to dispatch if there's demand
    dispatch_events(state, [])
  end

  @impl true
  def handle_call(:stats, _from, state) do
    queue_stats = PriorityQueue.stats()
    
    stats = %{
      demand: state.demand,
      queue: queue_stats
    }
    
    {:reply, stats, state}
  end

  ## Private Functions

  defp dispatch_events(state, events) do
    if state.demand > 0 do
      case PriorityQueue.dequeue() do
        {:ok, video} ->
          # Decrease demand and add event
          new_demand = state.demand - 1
          new_events = [video | events]
          new_state = %{state | demand: new_demand}
          
          # Continue dispatching if there's still demand
          dispatch_events(new_state, new_events)
        
        :empty ->
          # No more items, send what we have
          {:noreply, Enum.reverse(events), state}
      end
    else
      # No demand, send what we have
      {:noreply, Enum.reverse(events), state}
    end
  end
end
