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

defmodule ArmoricoreRealtime.Media.Distributed do
  @moduledoc """
  Distributed processing coordinator for multi-node media processing.
  
  This module:
  - Distributes processing across multiple nodes
  - Load balances based on node capacity
  - Handles node failures gracefully
  - Provides cluster-wide statistics
  """

  use GenServer
  require Logger

  alias ArmoricoreRealtime.Media.ProcessorPool

  ## Client API

  @doc """
  Start the distributed coordinator.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Process videos across the cluster.
  
  ## Parameters
  - `videos` - List of video maps
  - `opts` - Options:
    - `:strategy` - Distribution strategy: `:round_robin`, `:random`, `:least_loaded` (default: `:least_loaded`)
  
  ## Returns
  - List of results from all nodes
  """
  def process_distributed(videos, opts \\ []) do
    strategy = Keyword.get(opts, :strategy, :least_loaded)
    nodes = get_available_nodes()

    if Enum.empty?(nodes) do
      Logger.warning("No nodes available, processing locally")
      ProcessorPool.process_batch(videos, opts)
    else
      Logger.info("Distributing #{length(videos)} videos across #{length(nodes)} nodes using #{strategy} strategy")
      
      distribute_videos(videos, nodes, strategy, opts)
    end
  end

  @doc """
  Get cluster statistics.
  """
  def cluster_stats do
    GenServer.call(__MODULE__, :cluster_stats)
  end

  @doc """
  Get node capacity (estimated).
  """
  def node_capacity(node) do
    GenServer.call(__MODULE__, {:node_capacity, node})
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # Monitor node connections
    :net_kernel.monitor_nodes(true)
    
    # Get initial node list
    nodes = get_available_nodes()
    Logger.info("Distributed coordinator started. Available nodes: #{inspect(nodes)}")

    state = %{
      nodes: MapSet.new(nodes),
      node_capacities: %{},
      node_loads: %{}
    }

    {:ok, state}
  end

  @impl true
  def handle_info({:nodeup, node}, state) do
    Logger.info("Node joined: #{node}")
    new_nodes = MapSet.put(state.nodes, node)
    {:noreply, %{state | nodes: new_nodes}}
  end

  @impl true
  def handle_info({:nodedown, node}, state) do
    Logger.warning("Node left: #{node}")
    new_nodes = MapSet.delete(state.nodes, node)
    new_capacities = Map.delete(state.node_capacities, node)
    new_loads = Map.delete(state.node_loads, node)
    {:noreply, %{state | nodes: new_nodes, node_capacities: new_capacities, node_loads: new_loads}}
  end

  @impl true
  def handle_call(:cluster_stats, _from, state) do
    stats = %{
      total_nodes: MapSet.size(state.nodes),
      nodes: Enum.map(state.nodes, fn node ->
        %{
          node: node,
          capacity: Map.get(state.node_capacities, node, :unknown),
          load: Map.get(state.node_loads, node, 0)
        }
      end)
    }
    
    {:reply, stats, state}
  end

  @impl true
  def handle_call({:node_capacity, node}, _from, state) do
    capacity = Map.get(state.node_capacities, node, :unknown)
    {:reply, capacity, state}
  end

  ## Private Functions

  defp get_available_nodes do
    [Node.self() | Node.list()]
    |> Enum.filter(fn node ->
      # Check if node is alive and has our application
      if node == Node.self() do
        true
      else
        case :rpc.call(node, Code, :ensure_loaded, [ArmoricoreRealtime.Media.ProcessorPool]) do
          {:badrpc, _reason} -> false
          _ -> true
        end
      end
    end)
  end

  defp distribute_videos(videos, nodes, strategy, opts) do
    case strategy do
      :round_robin ->
        distribute_round_robin(videos, nodes, opts)
      
      :random ->
        distribute_random(videos, nodes, opts)
      
      :least_loaded ->
        distribute_least_loaded(videos, nodes, opts)
    end
  end

  defp distribute_round_robin(videos, nodes, opts) do
    node_list = Enum.to_list(nodes)
    
    videos
    |> Enum.with_index()
    |> Enum.map(fn {video, index} ->
      node = Enum.at(node_list, rem(index, length(node_list)))
      process_on_node(video, node, opts)
    end)
    |> Enum.map(&Task.await/1)
  end

  defp distribute_random(videos, nodes, opts) do
    node_list = Enum.to_list(nodes)
    
    videos
    |> Enum.map(fn video ->
      node = Enum.random(node_list)
      process_on_node(video, node, opts)
    end)
    |> Enum.map(&Task.await/1)
  end

  defp distribute_least_loaded(videos, nodes, opts) do
    # Simple implementation: distribute evenly
    # In production, would query actual node loads
    node_list = Enum.to_list(nodes)
    chunks = Enum.chunk_every(videos, div(length(videos), length(node_list)) + 1)
    
    chunks
    |> Enum.with_index()
    |> Enum.flat_map(fn {chunk, index} ->
      node = Enum.at(node_list, rem(index, length(node_list)))
      Enum.map(chunk, fn video ->
        process_on_node(video, node, opts)
      end)
    end)
    |> Enum.map(&Task.await/1)
  end

  defp process_on_node(video, node, opts) do
    if node == Node.self() do
      # Process locally
      Task.async(fn ->
        ProcessorPool.process_video(video, Keyword.get(opts, :timeout, 300_000))
      end)
    else
      # Process on remote node
      Task.async(fn ->
        :rpc.call(node, ProcessorPool, :process_video, [video, Keyword.get(opts, :timeout, 300_000)])
      end)
    end
  end
end
