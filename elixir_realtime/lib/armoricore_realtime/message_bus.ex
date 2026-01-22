# Copyright 2026 Francisco F. Pinochet, Fastcomcorp
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

defmodule ArmoricoreRealtime.MessageBus do
  @moduledoc """
  NATS-based message bus for Armoricore.

  Provides publish-subscribe messaging capabilities for:
  - Real-time communication between services
  - Event-driven architecture
  - Distributed system coordination
  - ArcRTC signaling coordination

  ## Architecture

  ```
  Publisher → NATS Server ← Subscriber
      ↓              ↑
  Service A      Service B
  ```

  ## Features

  - **JetStream Support**: Persistent streams and message durability
  - **Auto-Reconnection**: Automatic reconnection on network failures
  - **Request-Reply**: Synchronous messaging patterns
  - **Pub-Sub**: Asynchronous event broadcasting
  - **Queue Groups**: Load balancing across multiple subscribers

  ## Configuration

  Configure NATS connection in `config/runtime.exs`:

      config :armoricore_realtime, ArmoricoreRealtime.MessageBus,
        url: System.get_env("NATS_URL") || "nats://localhost:4222",
        token: System.get_env("NATS_TOKEN"),
        connection_name: "armoricore-realtime",
        jetstream_domain: "armoricore"

  ## Usage

      # Publish a message
      MessageBus.publish("user.created", %{user_id: 123, email: "user@example.com"})

      # Subscribe to messages
      MessageBus.subscribe("user.created", fn event_data ->
        # Handle user created event
        IO.inspect(event_data, label: "User created")
      end)

      # Request-Reply pattern
      {:ok, response} = MessageBus.request("user.get", %{user_id: 123})
  """

  use GenServer
  require Logger

  @behaviour :gen_nats

  # Client API

  @doc """
  Start the MessageBus GenServer.

  ## Options
  - `:url` - NATS server URL (default: "nats://localhost:4222")
  - `:token` - Authentication token
  - `:connection_name` - Connection name for monitoring
  - `:jetstream_domain` - JetStream domain name
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Get the Gnat connection process.
  """
  def get_gnat do
    GenServer.call(__MODULE__, :get_gnat)
  end

  @doc """
  Publish a message to a subject.

  ## Parameters
  - `subject` - NATS subject (e.g., "user.created")
  - `payload` - Message payload (map, string, or binary)
  - `opts` - Publishing options

  ## Returns
  - `:ok` on success
  - `{:error, reason}` on failure
  """
  @spec publish(String.t(), any(), keyword()) :: :ok | {:error, term()}
  def publish(subject, payload, opts \\ []) do
    GenServer.call(__MODULE__, {:publish, subject, payload, opts})
  end

  @doc """
  Subscribe to messages on a subject.

  ## Parameters
  - `subject` - NATS subject pattern
  - `callback` - Function to call when messages are received
  - `opts` - Subscription options

  ## Returns
  - `{:ok, subscription_id}` on success
  - `{:error, reason}` on failure

  ## Options
  - `:queue_group` - Queue group for load balancing
  - `:durable` - Durable consumer name for JetStream
  """
  @spec subscribe(String.t(), function(), keyword()) :: {:ok, term()} | {:error, term()}
  def subscribe(subject, callback, opts \\ []) do
    GenServer.call(__MODULE__, {:subscribe, subject, callback, opts})
  end

  @doc """
  Make a request and wait for a reply.

  ## Parameters
  - `subject` - Request subject
  - `payload` - Request payload
  - `timeout` - Timeout in milliseconds (default: 5000)

  ## Returns
  - `{:ok, response}` on success
  - `{:error, reason}` on timeout or failure
  """
  @spec request(String.t(), any(), timeout()) :: {:ok, term()} | {:error, term()}
  def request(subject, payload, timeout \\ 5000) do
    GenServer.call(__MODULE__, {:request, subject, payload, timeout})
  end

  @doc """
  Unsubscribe from messages.

  ## Parameters
  - `subscription_id` - Subscription ID returned by subscribe/3
  """
  @spec unsubscribe(term()) :: :ok | {:error, term()}
  def unsubscribe(subscription_id) do
    GenServer.call(__MODULE__, {:unsubscribe, subscription_id})
  end

  @doc """
  Get connection status.

  ## Returns
  - `:connected` - Connected to NATS server
  - `:disconnected` - Not connected
  - `:connecting` - Attempting to connect
  """
  @spec status() :: :connected | :disconnected | :connecting
  def status do
    GenServer.call(__MODULE__, :status)
  end

  # GenServer Callbacks

  @impl true
  def init(opts) do
    # Get configuration
    nats_url = opts[:url] || Application.get_env(:armoricore_realtime, :nats_url) || "nats://localhost:4222"
    nats_token = opts[:token] || Application.get_env(:armoricore_realtime, :nats_token)
    connection_name = opts[:connection_name] || "armoricore-realtime"
    jetstream_domain = opts[:jetstream_domain] || "armoricore"

    # Initialize state
    state = %{
      url: nats_url,
      token: nats_token,
      connection_name: connection_name,
      jetstream_domain: jetstream_domain,
      gnat: nil,
      subscriptions: %{},
      status: :disconnected,
      reconnect_timer: nil
    }

    # Start connection attempt
    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    Logger.info("Connecting to NATS server at #{state.url}")

    # Attempt connection
    case connect_to_nats(state) do
      {:ok, gnat} ->
        Logger.info("Successfully connected to NATS server")
        {:noreply, %{state | gnat: gnat, status: :connected}}

      {:error, reason} ->
        Logger.error("Failed to connect to NATS server: #{inspect(reason)}")
        # Schedule reconnection
        timer = Process.send_after(self(), :reconnect, 5000)
        {:noreply, %{state | status: :disconnected, reconnect_timer: timer}}
    end
  end

  @impl true
  def handle_call(:get_gnat, _from, state) do
    case state.gnat do
      nil -> {:reply, {:error, :not_connected}, state}
      gnat -> {:reply, {:ok, gnat}, state}
    end
  end

  @impl true
  def handle_call({:publish, subject, payload, _opts}, _from, %{gnat: nil} = state) do
    Logger.warning("Cannot publish message - NATS not connected", subject: subject)
    {:reply, {:error, :not_connected}, state}
  end

  def handle_call({:publish, subject, payload, opts}, _from, state) do
    # Encode payload
    encoded_payload = encode_payload(payload)

    # Publish message using Gnat
    try do
      :ok = Gnat.pub(state.gnat, subject, encoded_payload)
      Logger.debug("Published message to #{subject}")
      {:reply, :ok, state}
    catch
      kind, reason ->
        Logger.error("Failed to publish message to #{subject}: #{inspect({kind, reason})}")
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:subscribe, subject, callback, opts}, _from, %{gnat: nil} = state) do
    Logger.warning("Cannot subscribe - NATS not connected", subject: subject)
    {:reply, {:error, :not_connected}, state}
  end

  def handle_call({:subscribe, subject, callback, opts}, _from, state) do
    # Subscribe using Gnat - messages will be sent to the calling process
    try do
      {:ok, subscription_ref} = Gnat.sub(state.gnat, self(), subject)
      # Store callback for message handling
      subscriptions = Map.put(state.subscriptions, subscription_ref, callback)
      Logger.info("Subscribed to #{subject} with ref #{inspect(subscription_ref)}")
      {:reply, {:ok, subscription_ref}, %{state | subscriptions: subscriptions}}
    catch
      kind, reason ->
        Logger.error("Failed to subscribe to #{subject}: #{inspect({kind, reason})}")
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:request, subject, payload, timeout}, from, %{gnat: nil} = state) do
    Logger.warning("Cannot make request - NATS not connected", subject: subject)
    {:reply, {:error, :not_connected}, state}
  end

  def handle_call({:request, subject, payload, timeout}, from, state) do
    if state.gnat == nil do
      {:reply, {:error, :not_connected}, state}
    else
      # Encode payload
      encoded_payload = encode_payload(payload)

      # Use Gnat.request for request/response
      try do
        case Gnat.request(state.gnat, subject, encoded_payload, [timeout: timeout]) do
          {:ok, %{body: response_body}} ->
            # Decode response
            response = decode_payload(response_body)
            {:reply, {:ok, response}, state}

          {:error, reason} ->
            Logger.error("Request failed for subject #{subject}: #{inspect(reason)}")
            {:reply, {:error, reason}, state}
        end
      catch
        kind, reason ->
          Logger.error("Request exception for subject #{subject}: #{inspect({kind, reason})}")
          {:reply, {:error, reason}, state}
      end
    end
  end

  @impl true
  def handle_call({:unsubscribe, subscription_ref}, _from, state) do
    try do
      :ok = Gnat.unsub(state.gnat, subscription_ref)
      subscriptions = Map.delete(state.subscriptions, subscription_ref)
      Logger.info("Unsubscribed from subscription #{inspect(subscription_ref)}")
      {:reply, :ok, %{state | subscriptions: subscriptions}}
    catch
      kind, reason ->
        Logger.error("Failed to unsubscribe from #{inspect(subscription_ref)}: #{inspect({kind, reason})}")
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call(:status, _from, state) do
    {:reply, state.status, state}
  end


  @impl true
  def handle_info(:reconnect, state) do
    Logger.info("Attempting to reconnect to NATS server...")
    {:noreply, state, {:continue, :connect}}
  end

  @impl true
  def handle_info({:nats_connected, _connection}, state) do
    Logger.info("NATS connection established")
    {:noreply, %{state | status: :connected}}
  end

  @impl true
  def handle_info({:nats_disconnected, _connection}, state) do
    Logger.warning("NATS connection lost, scheduling reconnection")
    timer = Process.send_after(self(), :reconnect, 5000)
    {:noreply, %{state | status: :disconnected, reconnect_timer: timer}}
  end

  @impl true
  def handle_info({:msg, message}, state) do
    # Handle incoming NATS message
    %{topic: topic, body: body, reply_to: reply_to} = message

    # Decode payload
    payload = decode_payload(body)

    # Find callback for this subscription
    subscription_ref = message.gnat_subscription_ref
    case Map.get(state.subscriptions, subscription_ref) do
      nil ->
        Logger.warning("Received message for unknown subscription: #{inspect(subscription_ref)}")
      callback when is_function(callback, 1) ->
        # Call the callback with the payload
        try do
          callback.(payload)
        catch
          kind, reason ->
            Logger.error("Error in message callback for topic #{topic}: #{inspect({kind, reason})}")
        end
      callback ->
        Logger.error("Invalid callback for subscription #{inspect(subscription_ref)}")
    end

    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    # Clean up Gnat connection
    if state.gnat do
      Gnat.stop(state.gnat)
    end

    # Cancel any pending timers
    if state.reconnect_timer do
      Process.cancel_timer(state.reconnect_timer)
    end

    :ok
  end

  # Private Functions

  defp connect_to_nats(state) do
    # Parse NATS URL to extract host and port
    case parse_nats_url(state.url) do
      {:ok, host, port} ->
        # Gnat connection settings
        settings = %{host: host, port: port}

        # Add authentication if token is provided
        settings = if state.token do
          Map.put(settings, :token, state.token)
        else
          settings
        end

        # Add connection name
        settings = Map.put(settings, :connection_name, state.connection_name)

        # Attempt connection using Gnat
        case Gnat.start_link(settings) do
          {:ok, gnat} ->
            Logger.info("Connected to NATS server at #{state.url}")
            {:ok, gnat}
          {:error, reason} ->
            Logger.error("Failed to connect to NATS server: #{inspect(reason)}")
            {:error, reason}
        end

      {:error, reason} ->
        Logger.error("Failed to parse NATS URL #{state.url}: #{inspect(reason)}")
        {:error, reason}
    end
  end

  defp create_subscription_opts(opts) do
    sub_opts = []

    # Add queue group if specified
    sub_opts = if opts[:queue_group] do
      sub_opts ++ [queue_group: String.to_charlist(opts[:queue_group])]
    else
      sub_opts
    end

    # Add durable consumer for JetStream
    sub_opts = if opts[:durable] do
      sub_opts ++ [durable_consumer: String.to_charlist(opts[:durable])]
    else
      sub_opts
    end

    sub_opts
  end

  defp parse_nats_url(url) do
    case URI.parse(url) do
      %URI{scheme: "nats", host: host, port: port} when host != nil and port != nil ->
        {:ok, host, port}
      %URI{scheme: "nats", host: host} when host != nil ->
        # Default NATS port
        {:ok, host, 4222}
      _ ->
        {:error, :invalid_url}
    end
  end

  defp encode_payload(payload) when is_map(payload) do
    Jason.encode!(payload)
  end

  defp encode_payload(payload) when is_binary(payload) do
    payload
  end

  defp encode_payload(payload) do
    inspect(payload)
  end

  defp decode_payload(payload) do
    try do
      Jason.decode!(payload)
    rescue
      _ -> payload
    end
  end

end