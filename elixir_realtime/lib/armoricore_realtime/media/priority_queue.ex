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

defmodule ArmoricoreRealtime.Media.PriorityQueue do
  @moduledoc """
  Priority queue for media processing tasks.
  
  Supports priority levels: :critical, :high, :normal, :low
  Higher priority items are processed first.
  """

  use GenServer
  require Logger

  @priorities [:critical, :high, :normal, :low]

  ## Client API

  @doc """
  Starts the priority queue.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Enqueue a media processing task.
  
  ## Parameters
  - `video` - Map with `:media_id`, `:file_path`, `:content_type`, and `:priority`
  
  ## Returns
  - `:ok` on success
  - `{:error, reason}` on failure
  """
  def enqueue(video) do
    GenServer.call(__MODULE__, {:enqueue, video})
  end

  @doc """
  Dequeue the next task (highest priority first).
  
  ## Returns
  - `{:ok, video}` if a task is available
  - `:empty` if queue is empty
  """
  def dequeue do
    GenServer.call(__MODULE__, :dequeue)
  end

  @doc """
  Get queue statistics.
  
  ## Returns
  Map with queue size, priority breakdown, etc.
  """
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @doc """
  Clear the queue.
  """
  def clear do
    GenServer.call(__MODULE__, :clear)
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # Create separate queues for each priority
    queues = Enum.into(@priorities, %{}, fn priority -> {priority, :queue.new()} end)
    
    {:ok, %{
      queues: queues,
      total_size: 0
    }}
  end

  @impl true
  def handle_call({:enqueue, video}, _from, state) do
    priority = Map.get(video, :priority, :normal)
    
    # Validate priority
    if priority in @priorities do
      queue = state.queues[priority]
      new_queue = :queue.in(video, queue)
      new_queues = Map.put(state.queues, priority, new_queue)
      
      Logger.debug("Enqueued video #{video.media_id} with priority #{priority}")
      
      {:reply, :ok, %{state | queues: new_queues, total_size: state.total_size + 1}}
    else
      {:reply, {:error, :invalid_priority}, state}
    end
  end

  @impl true
  def handle_call(:dequeue, _from, state) do
    case find_highest_priority_item(state.queues) do
      {video, updated_queues} ->
        {:reply, {:ok, video}, %{state | queues: updated_queues, total_size: state.total_size - 1}}
      
      nil ->
        {:reply, :empty, state}
    end
  end

  @impl true
  def handle_call(:stats, _from, state) do
    stats = %{
      total_size: state.total_size,
      by_priority: Enum.into(@priorities, %{}, fn priority ->
        {priority, :queue.len(state.queues[priority])}
      end)
    }
    
    {:reply, stats, state}
  end

  @impl true
  def handle_call(:clear, _from, _state) do
    queues = Enum.into(@priorities, %{}, fn priority -> {priority, :queue.new()} end)
    {:reply, :ok, %{queues: queues, total_size: 0}}
  end

  ## Private Functions

  defp find_highest_priority_item(queues) do
    # Check priorities in order: critical, high, normal, low
    Enum.reduce_while(@priorities, nil, fn priority, _acc ->
      queue = queues[priority]
      
      case :queue.out(queue) do
        {{:value, video}, new_queue} ->
          updated_queues = Map.put(queues, priority, new_queue)
          {:halt, {video, updated_queues}}
        
        {:empty, _} ->
          {:cont, nil}
      end
    end)
  end
end
