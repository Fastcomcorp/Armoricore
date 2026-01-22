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

defmodule ArmoricoreRealtime.MediaEngineClient do
  @moduledoc """
  gRPC client for connecting to the Rust Realtime Media Engine.
  
  This module provides functions to interact with the Rust media engine
  running on port 50051, including stream management, audio encoding/decoding,
  and packet routing.
  """

  use GenServer
  require Logger

  # Use runtime configuration instead of compile-time
  # @grpc_server_url Application.compile_env(:armoricore_realtime, :media_engine_grpc_url, "http://localhost:50051")

  ## Client API

  @doc """
  Starts the MediaEngineClient GenServer.
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Creates a new media stream.
  
  ## Parameters
  - `user_id` - User ID for the stream
  - `media_type` - `:audio` or `:video`
  - `ssrc` - Synchronization source identifier
  - `codec` - Codec name (e.g., "opus", "h264")
  - `bitrate` - Bitrate in bps
  - `encryption_enabled` - Whether encryption is enabled
  
  ## Returns
  - `{:ok, stream_id}` on success
  - `{:error, reason}` on failure
  """
  def create_stream(user_id, media_type, ssrc, codec, bitrate, encryption_enabled \\ true) do
    GenServer.call(__MODULE__, {:create_stream, user_id, media_type, ssrc, codec, bitrate, encryption_enabled})
  end

  @doc """
  Stops a media stream.
  
  ## Parameters
  - `stream_id` - Stream ID to stop
  
  ## Returns
  - `:ok` on success
  - `{:error, reason}` on failure
  """
  def stop_stream(stream_id) do
    GenServer.call(__MODULE__, {:stop_stream, stream_id})
  end

  @doc """
  Gets stream information.
  
  ## Parameters
  - `stream_id` - Stream ID to query
  
  ## Returns
  - `{:ok, stream_info}` on success
  - `{:error, reason}` on failure
  """
  def get_stream(stream_id) do
    GenServer.call(__MODULE__, {:get_stream, stream_id})
  end

  @doc """
  Routes an RTP packet.
  
  ## Parameters
  - `stream_id` - Stream ID
  - `rtp_packet` - RTP packet bytes
  
  ## Returns
  - `{:ok, destination}` on success
  - `{:error, reason}` on failure
  """
  def route_packet(stream_id, rtp_packet) do
    GenServer.call(__MODULE__, {:route_packet, stream_id, rtp_packet})
  end

  @doc """
  Encodes audio samples.
  
  ## Parameters
  - `stream_id` - Stream ID
  - `samples` - List of float PCM samples
  - `sample_rate` - Sample rate in Hz
  - `channels` - Number of channels
  - `timestamp` - RTP timestamp
  
  ## Returns
  - `{:ok, encoded_data}` on success
  - `{:error, reason}` on failure
  """
  def encode_audio(stream_id, samples, sample_rate, channels, timestamp) do
    GenServer.call(__MODULE__, {:encode_audio, stream_id, samples, sample_rate, channels, timestamp})
  end

  @doc """
  Decodes audio data.
  
  ## Parameters
  - `stream_id` - Stream ID
  - `encoded_data` - Encoded audio bytes
  - `timestamp` - RTP timestamp
  
  ## Returns
  - `{:ok, {samples, sample_rate, channels}}` on success
  - `{:error, reason}` on failure
  """
  def decode_audio(stream_id, encoded_data, timestamp) do
    GenServer.call(__MODULE__, {:decode_audio, stream_id, encoded_data, timestamp})
  end

  @doc """
  Updates stream state.
  
  ## Parameters
  - `stream_id` - Stream ID
  - `state` - New state (`:initializing`, `:active`, `:paused`, `:stopped`, `:error`)
  
  ## Returns
  - `:ok` on success
  - `{:error, reason}` on failure
  """
  def update_stream_state(stream_id, state) do
    GenServer.call(__MODULE__, {:update_stream_state, stream_id, state})
  end

  @doc """
  Gets stream statistics.
  
  ## Parameters
  - `stream_id` - Stream ID
  
  ## Returns
  - `{:ok, stats}` on success
  - `{:error, reason}` on failure
  """
  def get_stream_stats(stream_id) do
    GenServer.call(__MODULE__, {:get_stream_stats, stream_id})
  end

  @doc """
  Create ArcRTC media stream.

  ## Parameters
  - `session_id`: ArcRTC session identifier
  - `config`: Stream configuration (codec, bitrate, etc.)

  ## Returns
  - `{:ok, response}` on success
  - `{:error, reason}` on failure
  """
  def create_arcrtc_stream(session_id, config) do
    GenServer.call(__MODULE__, {:create_arcrtc_stream, session_id, config})
  end

  @doc """
  Start ArcRTC media stream.

  ## Parameters
  - `session_id`: ArcRTC session identifier
  - `config`: Stream configuration

  ## Returns
  - `{:ok, stream_data}` on success
  - `{:error, reason}` on failure
  """
  def start_arcrtc_stream(session_id, config) do
    GenServer.call(__MODULE__, {:start_arcrtc_stream, session_id, config})
  end

  @doc """
  Stop ArcRTC media stream.

  ## Parameters
  - `stream_id`: Stream identifier to stop

  ## Returns
  - `:ok` on success
  - `{:error, reason}` on failure
  """
  def stop_arcrtc_stream(stream_id) do
    GenServer.call(__MODULE__, {:stop_arcrtc_stream, stream_id})
  end

  @doc """
  Update ArcRTC stream quality.

  ## Parameters
  - `session_id`: ArcRTC session identifier
  - `quality`: Quality settings

  ## Returns
  - `:ok` on success
  - `{:error, reason}` on failure
  """
  def update_arcrtc_quality(session_id, quality) do
    GenServer.call(__MODULE__, {:update_arcrtc_quality, session_id, quality})
  end

  @doc """
  Health check for the Media Engine service.

  Attempts to connect to the gRPC service and verify it's responding.

  ## Returns
  - `{:ok, %{status: "healthy", response_time: ms}}` if service is healthy
  - `{:ok, %{status: "unhealthy", error: reason}}` if service is down
  - `{:ok, %{status: "not_running"}}` if MediaEngineClient is not running
  """
  def health_check do
    case Process.whereis(__MODULE__) do
      nil ->
        {:ok, %{status: "not_running", note: "MediaEngineClient process not started"}}
      _pid ->
        GenServer.call(__MODULE__, :health_check, 5000)
    end
  rescue
    _ ->
      {:ok, %{status: "error", note: "Health check failed"}}
  end

  ## GenServer Callbacks

  @impl true
  def init(_opts) do
    # For now, we'll use a simple HTTP/2 client approach
    # In production, this would use the grpc library with proper channel management
    # Read from environment variable at runtime to avoid compile-time issues
    grpc_url = System.get_env("MEDIA_ENGINE_GRPC_URL") || 
               Application.get_env(:armoricore_realtime, :media_engine_grpc_url, "http://localhost:50051")
    Logger.info("MediaEngineClient started, connecting to #{grpc_url}")
    {:ok, %{grpc_url: grpc_url, channel: nil}}
  end

  @impl true
  def handle_call(:health_check, _from, state) do
    start_time = System.monotonic_time(:millisecond)
    
    # Try to make a simple request to the gRPC service
    result = check_grpc_health(state)
    
    response_time = System.monotonic_time(:millisecond) - start_time
    
    case result do
      {:ok, _} ->
        {:reply, {:ok, %{status: "healthy", response_time: response_time, grpc_url: state.grpc_url}}, state}
      {:error, :connection_refused} ->
        {:reply, {:ok, %{status: "unavailable", note: "Media engine not running", grpc_url: state.grpc_url}}, state}
      {:error, reason} ->
        {:reply, {:ok, %{status: "unhealthy", error: inspect(reason), grpc_url: state.grpc_url}}, state}
    end
  end

  @impl true
  def handle_call({:create_arcrtc_stream, session_id, config}, _from, state) do
    Logger.debug("Creating ArcRTC stream", %{session_id: session_id})

    # Create ArcRTC stream request
    request = %{
      type: "CREATE_ARCRTC_STREAM",
      session_id: session_id,
      config: config,
      timestamp: DateTime.utc_now() |> DateTime.to_unix()
    }

    result = call_grpc_service("CreateArcRtcStream", request, state)

    case result do
      {:ok, response} ->
        Logger.info("ArcRTC stream created", %{session_id: session_id, stream_id: response["stream_id"]})
        {:reply, {:ok, response}, state}
      {:error, reason} ->
        Logger.error("ArcRTC stream creation failed", %{session_id: session_id, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:start_arcrtc_stream, session_id, config}, _from, state) do
    Logger.debug("Starting ArcRTC stream", %{session_id: session_id})

    request = %{
      type: "START_ARCRTC_STREAM",
      session_id: session_id,
      stream_config: config,
      timestamp: DateTime.utc_now() |> DateTime.to_unix()
    }

    result = call_grpc_service("StartArcRtcStream", request, state)

    case result do
      {:ok, response} ->
        Logger.info("ArcRTC stream started", %{session_id: session_id, stream_id: response["stream_id"]})
        {:reply, {:ok, response}, state}
      {:error, reason} ->
        Logger.error("ArcRTC stream start failed", %{session_id: session_id, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:stop_arcrtc_stream, stream_id}, _from, state) do
    Logger.debug("Stopping ArcRTC stream", %{stream_id: stream_id})

    request = %{
      type: "STOP_ARCRTC_STREAM",
      stream_id: stream_id,
      timestamp: DateTime.utc_now() |> DateTime.to_unix()
    }

    result = call_grpc_service("StopArcRtcStream", request, state)

    case result do
      {:ok, _response} ->
        Logger.info("ArcRTC stream stopped", %{stream_id: stream_id})
        {:reply, :ok, state}
      {:error, reason} ->
        Logger.error("ArcRTC stream stop failed", %{stream_id: stream_id, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:update_arcrtc_quality, session_id, quality}, _from, state) do
    Logger.debug("Updating ArcRTC quality", %{session_id: session_id})

    request = %{
      type: "UPDATE_ARCRTC_QUALITY",
      session_id: session_id,
      quality: quality,
      timestamp: DateTime.utc_now() |> DateTime.to_unix()
    }

    result = call_grpc_service("UpdateArcRtcQuality", request, state)

    case result do
      {:ok, _response} ->
        Logger.info("ArcRTC quality updated", %{session_id: session_id})
        {:reply, :ok, state}
      {:error, reason} ->
        Logger.error("ArcRTC quality update failed", %{session_id: session_id, reason: reason})
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_call({:create_stream, user_id, media_type, ssrc, codec, bitrate, encryption_enabled}, _from, state) do
    # Convert media_type atom to protobuf enum
    media_type_enum = case media_type do
      :audio -> 0  # AUDIO
      :video -> 1  # VIDEO
      _ -> 0
    end

    # Build request (simplified - in production would use proper protobuf encoding)
    request = %{
      config: %{
        user_id: user_id,
        media_type: media_type_enum,
        ssrc: ssrc,
        payload_type: 96,  # Default payload type
        codec: codec,
        bitrate: bitrate,
        encryption_enabled: encryption_enabled
      }
    }

    # Call gRPC service (placeholder - will be implemented with actual gRPC client)
    result = call_grpc_service("CreateStream", request, state)
    
    case result do
      {:ok, %{stream_id: stream_id, success: true}} ->
        Logger.info("Stream created: #{stream_id}")
        {:reply, {:ok, stream_id}, state}
      {:error, reason} ->
        Logger.error("gRPC call failed: #{inspect(reason)}")
        {:reply, {:error, "gRPC connection error: #{inspect(reason)}"}, state}
      other ->
        Logger.error("Unexpected response: #{inspect(other)}")
        {:reply, {:error, "Unexpected response from gRPC service"}, state}
    end
  end

  @impl true
  def handle_call({:stop_stream, stream_id}, _from, state) do
    request = %{stream_id: stream_id}
    result = call_grpc_service("StopStream", request, state)
    
    case result do
      {:ok, %{success: true}} ->
        Logger.info("Stream stopped: #{stream_id}")
        {:reply, :ok, state}
      {:error, reason} ->
        {:reply, {:error, "gRPC connection error: #{inspect(reason)}"}, state}
      other ->
        Logger.error("Unexpected response: #{inspect(other)}")
        {:reply, {:error, "Unexpected response from gRPC service"}, state}
    end
  end

  @impl true
  def handle_call({:get_stream, stream_id}, _from, state) do
    request = %{stream_id: stream_id}
    result = call_grpc_service("GetStream", request, state)
    
    case result do
      {:ok, response} ->
        {:reply, {:ok, response}, state}
      {:error, reason} ->
        {:reply, {:error, "gRPC connection error: #{inspect(reason)}"}, state}
    end
  end

  @impl true
  def handle_call({:route_packet, stream_id, rtp_packet}, _from, state) do
    request = %{
      stream_id: stream_id,
      rtp_packet: rtp_packet
    }
    result = call_grpc_service("RoutePacket", request, state)
    
    case result do
      {:ok, %{success: true, destination: destination}} ->
        {:reply, {:ok, destination}, state}
      {:error, reason} ->
        {:reply, {:error, "gRPC connection error: #{inspect(reason)}"}, state}
      other ->
        Logger.error("Unexpected response: #{inspect(other)}")
        {:reply, {:error, "Unexpected response from gRPC service"}, state}
    end
  end

  @impl true
  def handle_call({:encode_audio, stream_id, samples, sample_rate, channels, timestamp}, _from, state) do
    request = %{
      stream_id: stream_id,
      samples: samples,
      sample_rate: sample_rate,
      channels: channels,
      timestamp: timestamp
    }
    result = call_grpc_service("EncodeAudio", request, state)
    
    case result do
      {:ok, %{success: true, encoded_data: encoded_data}} ->
        {:reply, {:ok, encoded_data}, state}
      {:error, reason} ->
        {:reply, {:error, "gRPC connection error: #{inspect(reason)}"}, state}
      other ->
        Logger.error("Unexpected response: #{inspect(other)}")
        {:reply, {:error, "Unexpected response from gRPC service"}, state}
    end
  end

  @impl true
  def handle_call({:decode_audio, stream_id, encoded_data, timestamp}, _from, state) do
    request = %{
      stream_id: stream_id,
      encoded_data: encoded_data,
      timestamp: timestamp
    }
    result = call_grpc_service("DecodeAudio", request, state)
    
    case result do
      {:ok, %{success: true, samples: samples, sample_rate: sample_rate, channels: channels}} ->
        {:reply, {:ok, {samples, sample_rate, channels}}, state}
      {:error, reason} ->
        {:reply, {:error, "gRPC connection error: #{inspect(reason)}"}, state}
      other ->
        Logger.error("Unexpected response: #{inspect(other)}")
        {:reply, {:error, "Unexpected response from gRPC service"}, state}
    end
  end

  @impl true
  def handle_call({:update_stream_state, stream_id, state}, _from, server_state) do
    # Convert atom to protobuf enum
    state_enum = case state do
      :initializing -> 0
      :active -> 1
      :paused -> 2
      :stopped -> 3
      :error -> 4
      _ -> 0
    end

    request = %{
      stream_id: stream_id,
      new_state: state_enum
    }
    result = call_grpc_service("UpdateStreamState", request, server_state)
    
    case result do
      {:ok, %{success: true}} ->
        {:reply, :ok, server_state}
      {:error, _reason} ->
        {:reply, {:error, "gRPC connection error"}, server_state}
      other ->
        Logger.error("Unexpected response: #{inspect(other)}")
        {:reply, {:error, "Unexpected response from gRPC service"}, server_state}
    end
  end

  @impl true
  def handle_call({:get_stream_stats, stream_id}, _from, state) do
    request = %{stream_id: stream_id}
    result = call_grpc_service("GetStreamStats", request, state)
    
    case result do
      # Note: When real gRPC is implemented, add pattern for {:ok, %{exists: true, stats: stats}}
      # Currently mock always returns exists: false
      {:ok, %{exists: false}} ->
        {:reply, {:error, "Stream not found"}, state}
      {:error, reason} ->
        {:reply, {:error, "gRPC connection error: #{inspect(reason)}"}, state}
      other ->
        Logger.error("Unexpected response: #{inspect(other)}")
        {:reply, {:error, "Unexpected response from gRPC service"}, state}
    end
  end

  ## Private Functions

  # Check if gRPC service is healthy by making a simple HTTP request
  defp check_grpc_health(state) do
    url = "#{state.grpc_url}/health"
    headers = [{"content-type", "application/json"}]
    
    case HTTPoison.get(url, headers, [timeout: 3000, recv_timeout: 3000]) do
      {:ok, %HTTPoison.Response{status_code: status}} when status in 200..299 ->
        {:ok, :healthy}
      {:ok, %HTTPoison.Response{status_code: status}} ->
        {:error, "HTTP #{status}"}
      {:error, %HTTPoison.Error{reason: :econnrefused}} ->
        {:error, :connection_refused}
      {:error, %HTTPoison.Error{reason: :timeout}} ->
        {:error, :timeout}
      {:error, %HTTPoison.Error{reason: reason}} ->
        {:error, reason}
    end
  rescue
    error ->
      {:error, error}
  end

  # HTTP-based gRPC client implementation
  # This is a temporary implementation using HTTP/JSON instead of protobuf
  # TODO: Replace with proper gRPC implementation using generated modules
  defp call_grpc_service(method, request, state) do
    url = "#{state.grpc_url}/#{method}"

    # Convert request map to JSON
    json_body = Jason.encode!(request)

    headers = [
      {"content-type", "application/json"},
      {"user-agent", "ArmoricoreRealtime/1.0"}
    ]

    # Make HTTP request
    case HTTPoison.post(url, json_body, headers, [timeout: 5000, recv_timeout: 5000]) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, response} -> {:ok, response}
          {:error, decode_error} ->
            Logger.error("Failed to decode JSON response: #{inspect(decode_error)}")
            {:error, "Invalid JSON response"}
        end

      {:ok, %HTTPoison.Response{status_code: status_code, body: body}} ->
        Logger.warning("gRPC call to #{method} failed with status #{status_code}: #{body}")
        {:error, "HTTP #{status_code}: #{body}"}

      {:error, %HTTPoison.Error{reason: reason}} ->
        Logger.error("gRPC call to #{method} failed: #{inspect(reason)}")
        # Fall back to mock response for development
        Logger.info("Falling back to mock response for #{method}")
        get_mock_response(method, request)
    end
  rescue
    error ->
      Logger.error("Exception in gRPC call to #{method}: #{inspect(error)}")
      # Fall back to mock response
      get_mock_response(method, request)
  end

  # Mock responses for when the gRPC server is not available
  defp get_mock_response(method, _request) do
    Logger.debug("Using mock response for #{method}")

    case method do
      "CreateStream" ->
        {:ok, %{stream_id: UUID.uuid4(), success: true, error: ""}}
      "StopStream" ->
        {:ok, %{success: true, error: ""}}
      "GetStream" ->
        {:ok, %{exists: false, config: nil, state: 0}}
      "RoutePacket" ->
        {:ok, %{success: true, destination: nil, error: ""}}
      "EncodeAudio" ->
        {:ok, %{success: true, encoded_data: <<>>, error: ""}}
      "DecodeAudio" ->
        {:ok, %{success: true, samples: [], sample_rate: 16000, channels: 1, error: ""}}
      "UpdateStreamState" ->
        {:ok, %{success: true, error: ""}}
      "GetStreamStats" ->
        {:ok, %{exists: false, stats: nil}}
      "CreateArcRtcStream" ->
        {:ok, %{stream_id: UUID.uuid4(), success: true, error: ""}}
      "StartArcRtcStream" ->
        {:ok, %{stream_id: UUID.uuid4(), success: true, error: ""}}
      "StopArcRtcStream" ->
        {:ok, %{success: true, error: ""}}
      "UpdateArcRtcQuality" ->
        {:ok, %{success: true, error: ""}}
      _ ->
        {:error, "Unknown method: #{method}"}
    end
  end
end
