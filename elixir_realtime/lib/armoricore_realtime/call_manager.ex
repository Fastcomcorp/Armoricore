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

defmodule ArmoricoreRealtime.CallManager do
  @moduledoc """
  Call Manager for tracking active calls and call state.
  
  This module provides functions to manage call state, track active calls,
  and handle call-related operations.
  """

  use GenServer
  require Logger

  # Call record structure
  defstruct [
    call_id: nil,
    caller_id: nil,
    callee_id: nil,
    call_type: nil,
    state: nil,
    initiated_at: nil,
    connected_at: nil,
    ended_at: nil
  ]

  ## Client API

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  @doc """
  Creates a new call.
  """
  def create_call(caller_id, callee_id, call_type) do
    call_id = UUID.uuid4()

    call = %__MODULE__{
      call_id: call_id,
      caller_id: caller_id,
      callee_id: callee_id,
      call_type: call_type,
      state: "initiating",
      initiated_at: DateTime.utc_now()
    }

    GenServer.call(__MODULE__, {:create_call, call})
  end

  @doc """
  Gets call information.
  """
  def get_call(call_id) do
    GenServer.call(__MODULE__, {:get_call, call_id})
  end

  @doc """
  Updates call state.
  """
  def update_call_state(call_id, state, metadata \\ %{}) do
    GenServer.call(__MODULE__, {:update_call_state, call_id, state, metadata})
  end

  @doc """
  Ends a call.
  """
  def end_call(call_id, reason) do
    GenServer.call(__MODULE__, {:end_call, call_id, reason})
  end

  @doc """
  Gets active calls for a user.
  """
  def get_user_calls(user_id) do
    GenServer.call(__MODULE__, {:get_user_calls, user_id})
  end

  @doc """
  Gets all active calls.
  """
  def get_active_calls do
    GenServer.call(__MODULE__, :get_active_calls)
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    {:ok, %{}}
  end

  @impl true
  def handle_call({:create_call, call}, _from, state) do
    new_state = Map.put(state, call.call_id, call)
    Logger.info("Call #{call.call_id} created: #{call.caller_id} -> #{call.callee_id}")
    {:reply, {:ok, call}, new_state}
  end

  @impl true
  def handle_call({:get_call, call_id}, _from, state) do
    call = Map.get(state, call_id)
    {:reply, call, state}
  end

  @impl true
  def handle_call({:update_call_state, call_id, new_state, metadata}, _from, state) do
    case Map.get(state, call_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      call ->
        updated_call = call
                       |> Map.put(:state, new_state)
                       |> Map.merge(metadata)

        new_state = Map.put(state, call_id, updated_call)
        Logger.info("Call #{call_id} state updated to #{new_state}")
        {:reply, {:ok, updated_call}, new_state}
    end
  end

  @impl true
  def handle_call({:end_call, call_id, reason}, _from, state) do
    case Map.get(state, call_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      call ->
        ended_call = %{call | state: "ended", ended_at: DateTime.utc_now()}
        # Remove from active calls
        new_state = Map.delete(state, call_id)
        Logger.info("Call #{call_id} ended: #{reason}")
        {:reply, {:ok, ended_call}, new_state}
    end
  end

  @impl true
  def handle_call({:get_user_calls, user_id}, _from, state) do
    user_calls = state
                 |> Map.values()
                 |> Enum.filter(fn call ->
                   call.caller_id == user_id || call.callee_id == user_id
                 end)
                 |> Enum.filter(fn call -> call.state != "ended" end)

    {:reply, user_calls, state}
  end

  @impl true
  def handle_call(:get_active_calls, _from, state) do
    active_calls = state
                   |> Map.values()
                   |> Enum.filter(fn call -> call.state != "ended" end)

    {:reply, active_calls, state}
  end
end
