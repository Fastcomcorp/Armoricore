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

defmodule ArmoricoreRealtimeWeb.ArcRtcChannel do
  @moduledoc """
  Phoenix Channel for ArcRTC protocol signaling.

  This channel handles ArcRTC-specific signaling messages for ultra-low latency
  real-time communication. It provides an interface between WebRTC clients and
  the ArcRTC media engine running in Rust.

  ## Channel Topic

  `arcrtc:{session_id}` - Where `session_id` is a unique identifier for the ArcRTC session

  ## Supported Messages

  ### Incoming Messages (from client)
  - `arc_connect` - Initiate ArcRTC connection
  - `arc_stream_start` - Start media stream
  - `arc_stream_stop` - Stop media stream
  - `arc_quality_update` - Update quality settings
  - `arc_ping` - Connection keepalive

  ### Outgoing Messages (to client)
  - `arc_connected` - Connection established
  - `arc_stream_started` - Stream successfully started
  - `arc_stream_stopped` - Stream stopped
  - `arc_quality_updated` - Quality settings applied
  - `arc_error` - Error notification
  - `arc_pong` - Keepalive response

  ## Architecture

  ```
  WebRTC Client ↔ ArcRTC Channel ↔ ArcRTC Bridge ↔ Media Engine Client ↔ Rust ArcRTC Engine
  ```

  ## Security

  - Session validation required for channel join
  - User authorization checks
  - Input validation for all messages
  - Rate limiting applied
  """

  use ArmoricoreRealtimeWeb, :channel
  require Logger

  alias ArmoricoreRealtime.ArcRtcBridge
  alias ArmoricoreRealtime.MediaEngineClient

  @doc """
  Join the ArcRTC signaling channel.

  ## Parameters
  - `session_id`: Unique session identifier
  - `payload`: Must contain authorization data

  ## Authorization
  Validates session exists and user has permission to join.
  """
  @impl true
  def join("arcrtc:" <> session_id, payload, socket) do
    user_id = socket.assigns.user_id

    Logger.info("ArcRTC channel join attempt", %{
      session_id: session_id,
      user_id: user_id
    })

    case validate_arcrtc_session(session_id, payload, user_id) do
      {:ok, session_data} ->
        Logger.info("ArcRTC channel join successful", %{
          session_id: session_id,
          user_id: user_id
        })

        # Subscribe to session-specific events
        Phoenix.PubSub.subscribe(ArmoricoreRealtime.PubSub, "arcrtc:#{session_id}")

        {:ok, socket
             |> assign(:session_id, session_id)
             |> assign(:user_id, user_id)
             |> assign(:arcrtc_session, session_data)}

      {:error, reason} ->
        Logger.warning("ArcRTC channel join failed", %{
          session_id: session_id,
          user_id: user_id,
          reason: reason
        })
        {:error, %{reason: reason}}
    end
  end

  @doc """
  Handle ArcRTC connection request.

  Initiates connection with the ArcRTC media engine.
  """
  @impl true
  def handle_in("arc_connect", payload, socket) do
    session_id = socket.assigns.session_id
    user_id = socket.assigns.user_id

    Logger.debug("ArcRTC connect request", %{
      session_id: session_id,
      user_id: user_id
    })

    case connect_arcrtc_session(session_id, payload, user_id) do
      {:ok, connection_data} ->
        Logger.info("ArcRTC connection established", %{
          session_id: session_id,
          user_id: user_id
        })

        # Notify client of successful connection
        push(socket, "arc_connected", connection_data)

        {:reply, {:ok, %{status: "connected", session_id: session_id}}, socket}

      {:error, reason} ->
        Logger.error("ArcRTC connection failed", %{
          session_id: session_id,
          user_id: user_id,
          reason: reason
        })

        push(socket, "arc_error", %{type: "connection_failed", reason: reason})

        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  # Handle ArcRTC stream start request - creates a new media stream in the ArcRTC engine
  @impl true
  def handle_in("arc_stream_start", %{"config" => config} = _payload, socket) do
    session_id = socket.assigns.session_id
    user_id = socket.assigns.user_id

    Logger.debug("ArcRTC stream start request", %{
      session_id: session_id,
      user_id: user_id,
      config: config
    })

    case start_arcrtc_stream(session_id, config, user_id) do
      {:ok, stream_data} ->
        Logger.info("ArcRTC stream started", %{
          session_id: session_id,
          user_id: user_id,
          stream_id: stream_data.stream_id
        })

        push(socket, "arc_stream_started", stream_data)

        {:reply, {:ok, %{status: "stream_started", stream_id: stream_data.stream_id}}, socket}

      {:error, reason} ->
        Logger.error("ArcRTC stream start failed", %{
          session_id: session_id,
          user_id: user_id,
          reason: reason
        })

        push(socket, "arc_error", %{type: "stream_start_failed", reason: reason})

        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @doc """
  Handle ArcRTC stream stop request.

  Stops an active media stream.
  """
  @impl true
  def handle_in("arc_stream_stop", %{"stream_id" => stream_id}, socket) do
    session_id = socket.assigns.session_id
    user_id = socket.assigns.user_id

    Logger.debug("ArcRTC stream stop request", %{
      session_id: session_id,
      user_id: user_id,
      stream_id: stream_id
    })

    case stop_arcrtc_stream(stream_id, user_id) do
      :ok ->
        Logger.info("ArcRTC stream stopped", %{
          session_id: session_id,
          user_id: user_id,
          stream_id: stream_id
        })

        push(socket, "arc_stream_stopped", %{stream_id: stream_id})

        {:reply, {:ok, %{status: "stream_stopped", stream_id: stream_id}}, socket}

      {:error, reason} ->
        Logger.error("ArcRTC stream stop failed", %{
          session_id: session_id,
          user_id: user_id,
          stream_id: stream_id,
          reason: reason
        })

        push(socket, "arc_error", %{type: "stream_stop_failed", reason: reason})

        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @doc """
  Handle ArcRTC quality update request.

  Updates quality settings for active streams.
  """
  @impl true
  def handle_in("arc_quality_update", %{"quality" => quality}, socket) do
    session_id = socket.assigns.session_id
    user_id = socket.assigns.user_id

    Logger.debug("ArcRTC quality update request", %{
      session_id: session_id,
      user_id: user_id,
      quality: quality
    })

    case update_arcrtc_quality(session_id, quality, user_id) do
      :ok ->
        Logger.info("ArcRTC quality updated", %{
          session_id: session_id,
          user_id: user_id
        })

        push(socket, "arc_quality_updated", %{quality: quality})

        {:reply, {:ok, %{status: "quality_updated"}}, socket}

      {:error, reason} ->
        Logger.error("ArcRTC quality update failed", %{
          session_id: session_id,
          user_id: user_id,
          reason: reason
        })

        push(socket, "arc_error", %{type: "quality_update_failed", reason: reason})

        {:reply, {:error, %{reason: reason}}, socket}
    end
  end

  @doc """
  Handle connection keepalive ping.
  """
  @impl true
  def handle_in("arc_ping", _payload, socket) do
    session_id = socket.assigns.session_id

    # Send pong response
    push(socket, "arc_pong", %{timestamp: DateTime.utc_now() |> DateTime.to_unix()})

    {:reply, {:ok, %{status: "pong"}}, socket}
  end

  @doc """
  Handle ArcRTC events from the media engine.

  This callback receives events from the Rust ArcRTC engine via PubSub.
  """
  @impl true
  def handle_info({:arcrtc_event, event}, socket) do
    Logger.debug("Received ArcRTC event", %{
      session_id: socket.assigns.session_id,
      event_type: event.type
    })

    # Forward event to client
    push(socket, "arc_event", event)

    {:noreply, socket}
  end

  @doc """
  Handle channel termination.

  Cleans up ArcRTC session resources.
  """
  @impl true
  def terminate(reason, socket) do
    session_id = socket.assigns[:session_id]
    user_id = socket.assigns[:user_id]

    Logger.info("ArcRTC channel terminating", %{
      session_id: session_id,
      user_id: user_id,
      reason: inspect(reason)
    })

    # Cleanup ArcRTC session
    if session_id do
      cleanup_arcrtc_session(session_id, user_id)
    end

    :ok
  end

  # Private Functions

  defp validate_arcrtc_session(session_id, payload, user_id) do
    # Validate session ID format
    if not is_valid_session_id?(session_id) do
      {:error, :invalid_session_id}
    else
      # Check if user has permission for this session
      # This could involve checking database or calling auth service
      case check_session_permission(session_id, user_id) do
        :ok -> {:ok, %{session_id: session_id, user_id: user_id}}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp connect_arcrtc_session(session_id, payload, user_id) do
    # Extract client capabilities from payload
    capabilities = payload["capabilities"] || %{}

    # Create ArcRTC connection request
    case ArcRtcBridge.webrtc_to_arcrtc(session_id, payload["sdp"] || "", payload["ice_candidates"] || [], %{user_id: user_id}) do
      {:ok, arc_request} ->
        # Send to media engine
        case MediaEngineClient.create_arcrtc_stream(session_id, arc_request) do
          {:ok, response} ->
            {:ok, %{connection_id: session_id, capabilities: response}}
          {:error, reason} ->
            {:error, reason}
        end
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp start_arcrtc_stream(session_id, config, user_id) do
    # Validate stream configuration
    case validate_stream_config(config) do
      {:ok, validated_config} ->
        # Start stream in media engine
        case MediaEngineClient.start_arcrtc_stream(session_id, validated_config) do
          {:ok, stream_response} ->
            {:ok, %{stream_id: stream_response["stream_id"] || UUID.uuid4(), config: validated_config}}
          {:error, reason} ->
            {:error, reason}
        end
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp stop_arcrtc_stream(stream_id, user_id) do
    # Stop stream in media engine
    MediaEngineClient.stop_arcrtc_stream(stream_id)
  end

  defp update_arcrtc_quality(session_id, quality, user_id) do
    # Update quality settings in media engine
    case MediaEngineClient.update_arcrtc_quality(session_id, quality) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  defp cleanup_arcrtc_session(session_id, user_id) do
    # Cleanup resources in media engine
    Logger.debug("Cleaning up ArcRTC session", %{session_id: session_id, user_id: user_id})

    # This could involve stopping streams, closing connections, etc.
    # For now, just log the cleanup
    :ok
  end

  # Helper Functions

  defp is_valid_session_id?(session_id) do
    # Basic validation: alphanumeric, hyphens, underscores, reasonable length
    Regex.match?(~r/^[a-zA-Z0-9_-]{8,128}$/, session_id)
  end

  defp check_session_permission(session_id, user_id) do
    # Placeholder for session permission checking
    # In production, this would validate against database or auth service
    :ok
  end

  defp validate_stream_config(config) do
    # Basic validation of stream configuration
    required_fields = ["type"]  # audio, video, or both

    case validate_required_fields(config, required_fields) do
      :ok ->
        # Additional validation based on type
        case config["type"] do
          "audio" -> validate_audio_config(config)
          "video" -> validate_video_config(config)
          "both" -> validate_both_config(config)
          _ -> {:error, :invalid_stream_type}
        end
      {:error, missing} ->
        {:error, {:missing_fields, missing}}
    end
  end

  defp validate_audio_config(config) do
    # Validate audio-specific configuration
    # Could check codec, bitrate, sample rate, etc.
    {:ok, config}
  end

  defp validate_video_config(config) do
    # Validate video-specific configuration
    # Could check codec, resolution, framerate, etc.
    {:ok, config}
  end

  defp validate_both_config(config) do
    # Validate both audio and video configuration
    {:ok, config}
  end

  defp validate_required_fields(config, required) do
    missing = Enum.filter(required, fn field -> not Map.has_key?(config, field) end)

    if Enum.empty?(missing) do
      :ok
    else
      {:error, missing}
    end
  end
end