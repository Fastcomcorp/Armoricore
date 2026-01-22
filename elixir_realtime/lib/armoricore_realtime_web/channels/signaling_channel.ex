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

defmodule ArmoricoreRealtimeWeb.SignalingChannel do
  @moduledoc """
  Signaling Channel for WebRTC voice/video calls.

  This channel implements the WebRTC signaling protocol for peer-to-peer voice and video calls.
  It handles the complete call lifecycle from initiation to termination, including SDP negotiation
  and ICE candidate exchange.

  ## Channel Topic
  `signaling:call:{call_id}` - Where `call_id` is a unique identifier for the call

  ## Join Parameters
  ```elixir
  %{
    "caller_id" => "user-uuid",  # Required: User initiating the call
    "callee_id" => "user-uuid"   # Required: User being called
  }
  ```

  ## Events Handled
  - `call_initiate` - Start a new call
  - `call_offer` - Send SDP offer
  - `call_answer` - Send SDP answer
  - `ice_candidate` - Exchange ICE candidates
  - `call_end` - Terminate call
  - `call_reject` - Reject incoming call
  - `ping` - Connection keepalive

  ## Events Broadcast
  - `call_initiated` - Call has been initiated
  - `call_offer` - SDP offer received
  - `call_answer` - SDP answer received
  - `ice_candidate` - ICE candidate received
  - `call_connected` - Call successfully connected
  - `call_ended` - Call terminated
  - `call_rejected` - Call rejected by callee

  ## Security Features
  - Call ID format validation
  - SDP injection prevention
  - ICE candidate sanitization
  - Authorization via room membership
  - Input length limits and type validation

  ## Error Handling
  All invalid inputs are logged and rejected with appropriate error messages.
  The channel automatically handles disconnection cleanup.

  ## Integration
  Works with `ArmoricoreRealtime.Rooms` for authorization and
  `ArmoricoreRealtimeWeb.ChannelHelpers` for event publishing.
  """

  use ArmoricoreRealtimeWeb, :channel
  require Logger

  # Call states - align with client expectations
  @call_state_initiating "initiating"
  @call_state_ringing "ringing"
  @call_state_connected "connected"
  @call_state_ended "ended"

  @impl true
  @doc """
  Join the signaling channel for a specific call.

  ## Parameters
  - `call_id`: Unique call identifier (validated for format and length)
  - `payload`: Must contain `caller_id` and `callee_id`
  - `socket`: Phoenix socket with authenticated user

  ## Authorization
  User must be either the caller or callee of the call, verified through
  `ArmoricoreRealtime.Rooms.user_is_call_participant?/4`

  ## Returns
  - `{:ok, socket}` with call state initialized
  - `{:error, %{reason: string}}` for validation or authorization failures
  """
  def join("signaling:call:" <> call_id, payload, socket) do
    user_id = socket.assigns.user_id

    # SECURITY: Validate call_id format to prevent injection attacks
    case validate_call_id(call_id) do
      {:ok, validated_call_id} ->
        # SECURITY: Validate required payload fields
        caller_id = Map.get(payload, "caller_id")
        callee_id = Map.get(payload, "callee_id")

        cond do
          # Validate caller_id presence and type
          is_nil(caller_id) or not is_binary(caller_id) ->
            Logger.warning("Invalid caller_id in signaling join from user #{user_id}")
            {:error, %{reason: "Invalid caller identifier"}}

          # Validate callee_id presence and type
          is_nil(callee_id) or not is_binary(callee_id) ->
            Logger.warning("Invalid callee_id in signaling join from user #{user_id}")
            {:error, %{reason: "Invalid callee identifier"}}

          # SECURITY: Verify user is authorized to participate in this call
          # This checks room membership and call participant validation
          ArmoricoreRealtime.Rooms.user_is_call_participant?(user_id, validated_call_id, caller_id, callee_id) ->
            Logger.info("User #{user_id} joining signaling channel for call #{validated_call_id}")

            # Subscribe to call-specific PubSub topic for real-time messaging
            Phoenix.PubSub.subscribe(ArmoricoreRealtime.PubSub, "signaling:call:#{validated_call_id}")

            # Initialize socket with call context
            {:ok, socket
                 |> assign(:call_id, validated_call_id)
                 |> assign(:user_id, user_id)
                 |> assign(:caller_id, caller_id)
                 |> assign(:callee_id, callee_id)
                 |> assign(:call_state, @call_state_initiating)}

          # Authorization failed
          true ->
            Logger.warning("User #{user_id} attempted to join call #{validated_call_id} they're not part of")
            {:error, %{reason: "unauthorized"}}
        end

      # Call ID validation failed
      {:error, reason} ->
        Logger.warning("Invalid call_id from user #{user_id}: #{inspect(reason)}")
        {:error, %{reason: "Invalid call identifier"}}
    end
  end
  
  # SECURITY: Validate call ID format
  defp validate_call_id(call_id) when is_binary(call_id) do
    cond do
      byte_size(call_id) == 0 ->
        {:error, :empty_call_id}
      
      byte_size(call_id) > 128 ->
        {:error, :call_id_too_long}
      
      # Allow UUID format or alphanumeric with dashes/underscores
      String.match?(call_id, ~r/^[a-zA-Z0-9_-]+$/) ->
        {:ok, call_id}
      
      true ->
        {:error, :invalid_call_id_format}
    end
  end
  
  defp validate_call_id(_) do
    {:error, :invalid_call_id_type}
  end

  @doc """
  Initiates a call.
  
  Payload:
  {
    "callee_id": "user-uuid",
    "call_type": "voice" | "video"
  }
  """
  @impl true
  def handle_in("call_initiate", payload, socket) do
    caller_id = socket.assigns.user_id
    call_id = socket.assigns.call_id
    
    # SECURITY: Validate payload structure
    case validate_call_initiate_payload(payload) do
      {:ok, %{callee_id: callee_id, call_type: call_type}} ->
        Logger.info("Call #{call_id} initiated by #{caller_id} to #{callee_id} (#{call_type})")

        # Create call metadata
        call_metadata = %{
          call_id: call_id,
          caller_id: caller_id,
          callee_id: callee_id,
          call_type: call_type,
          state: @call_state_ringing,
          initiated_at: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        # Broadcast call initiation to both participants
        broadcast(socket, "call_initiated", call_metadata)

        # Publish to message bus for analytics/moderation
        ArmoricoreRealtimeWeb.ChannelHelpers.publish_call_event(call_metadata)

        {:reply, {:ok, call_metadata}, assign(socket, :call_state, @call_state_ringing)}
      
      {:error, reason} ->
        Logger.warning("Invalid call_initiate payload from user #{caller_id}: #{inspect(reason)}")
        {:reply, {:error, %{reason: "Invalid call initiation parameters"}}, socket}
    end
  end

  # Sends SDP offer.
  # Payload: {"sdp": "v=0\\no=-...", "type": "offer"}
  @impl true
  def handle_in("call_offer", payload, socket) do
    user_id = socket.assigns.user_id
    call_id = socket.assigns.call_id

    # SECURITY: Validate SDP payload
    case validate_sdp_payload(payload, "offer") do
      {:ok, sdp} ->
        Logger.debug("SDP offer received from #{user_id} for call #{call_id}")

        # Create offer message
        offer = %{
          call_id: call_id,
          from: user_id,
          sdp: sdp,
          type: "offer",
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        # Broadcast offer to other participant (not sender)
        broadcast_from(socket, "call_offer", offer)

        {:reply, {:ok, %{status: "offer_sent"}}, socket}
      
      {:error, reason} ->
        Logger.warning("Invalid SDP offer from user #{user_id}: #{inspect(reason)}")
        {:reply, {:error, %{reason: "Invalid SDP offer format"}}, socket}
    end
  end

  # Sends SDP answer.
  # Payload: {"sdp": "v=0\\no=-...", "type": "answer"}
  @impl true
  def handle_in("call_answer", payload, socket) do
    user_id = socket.assigns.user_id
    call_id = socket.assigns.call_id

    # SECURITY: Validate SDP payload
    case validate_sdp_payload(payload, "answer") do
      {:ok, sdp} ->
        Logger.debug("SDP answer received from #{user_id} for call #{call_id}")

        # Create answer message
        answer = %{
          call_id: call_id,
          from: user_id,
          sdp: sdp,
          type: "answer",
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        # Update call state to connected
        call_metadata = %{
          call_id: call_id,
          state: @call_state_connected,
          connected_at: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        # Broadcast answer to other participant (not sender)
        broadcast_from(socket, "call_answer", answer)

        # Broadcast call connected state
        broadcast(socket, "call_connected", call_metadata)

        {:reply, {:ok, %{status: "answer_sent"}}, assign(socket, :call_state, @call_state_connected)}
      
      {:error, reason} ->
        Logger.warning("Invalid SDP answer from user #{user_id}: #{inspect(reason)}")
        {:reply, {:error, %{reason: "Invalid SDP answer format"}}, socket}
    end
  end

  # Exchanges ICE candidate.
  # Payload: {"candidate": "candidate:...", "sdp_mid": "0", "sdp_m_line_index": 0}
  @impl true
  def handle_in("ice_candidate", payload, socket) do
    user_id = socket.assigns.user_id
    call_id = socket.assigns.call_id
    
    # SECURITY: Validate ICE candidate payload
    case validate_ice_candidate_payload(payload) do
      {:ok, validated_payload} ->
        candidate = Map.get(validated_payload, "candidate")
        sdp_mid = Map.get(validated_payload, "sdp_mid")
        sdp_m_line_index = Map.get(validated_payload, "sdp_m_line_index")

        Logger.debug("ICE candidate received from #{user_id} for call #{call_id}")

        # Create ICE candidate message
        ice_candidate = %{
          call_id: call_id,
          from: user_id,
          candidate: candidate,
          sdp_mid: sdp_mid,
          sdp_m_line_index: sdp_m_line_index,
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
        }

        # Broadcast ICE candidate to other participant (not sender)
        broadcast_from(socket, "ice_candidate", ice_candidate)

        {:reply, {:ok, %{status: "ice_candidate_sent"}}, socket}
      
      {:error, reason} ->
        Logger.warning("Invalid ICE candidate from user #{user_id}: #{inspect(reason)}")
        {:reply, {:error, %{reason: "Invalid ICE candidate format"}}, socket}
    end
  end

  # Ends the call.
  # Payload: {"reason": "user_hangup" | "rejected" | "timeout" | "error"}
  @impl true
  def handle_in("call_end", %{"reason" => reason} = _payload, socket) do
    user_id = socket.assigns.user_id
    call_id = socket.assigns.call_id

    Logger.info("Call #{call_id} ended by #{user_id}, reason: #{reason}")

    # Create end call message
    end_call = %{
      call_id: call_id,
      ended_by: user_id,
      reason: reason,
      ended_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    # Broadcast call end to all participants
    broadcast(socket, "call_ended", end_call)

    # Publish to message bus
    ArmoricoreRealtimeWeb.ChannelHelpers.publish_call_event(end_call)

    {:reply, {:ok, %{status: "call_ended"}}, assign(socket, :call_state, @call_state_ended)}
  end

  # Rejects an incoming call.
  @impl true
  def handle_in("call_reject", _payload, socket) do
    user_id = socket.assigns.user_id
    call_id = socket.assigns.call_id

    Logger.info("Call #{call_id} rejected by #{user_id}")

    # Create reject message
    reject_call = %{
      call_id: call_id,
      rejected_by: user_id,
      reason: "rejected",
      rejected_at: DateTime.utc_now() |> DateTime.to_iso8601()
    }

    # Broadcast call rejection
    broadcast(socket, "call_rejected", reject_call)

    # Publish to message bus
    ArmoricoreRealtimeWeb.ChannelHelpers.publish_call_event(reject_call)

    {:reply, {:ok, %{status: "call_rejected"}}, assign(socket, :call_state, @call_state_ended)}
  end

  # Handles ping for connection keepalive.
  @impl true
  def handle_in("ping", _payload, socket) do
    {:reply, {:ok, %{ping: "pong"}}, socket}
  end

  @impl true
  def terminate(_reason, socket) do
    # If call is still active, end it
    call_state = socket.assigns[:call_state]
    if call_state && call_state != @call_state_ended do
      user_id = socket.assigns[:user_id]
      call_id = socket.assigns[:call_id]

      Logger.info("User #{user_id} disconnected from call #{call_id}, ending call")

      # Broadcast call end due to disconnect
      end_call = %{
        call_id: call_id,
        ended_by: user_id,
        reason: "disconnected",
        ended_at: DateTime.utc_now() |> DateTime.to_iso8601()
      }

      Phoenix.PubSub.broadcast(
        ArmoricoreRealtime.PubSub,
        "signaling:call:#{call_id}",
        %Phoenix.Socket.Broadcast{
          topic: "signaling:call:#{call_id}",
          event: "call_ended",
          payload: end_call
        }
      )
    end

    :ok
  end
  
  # SECURITY: Validate call initiation payload
  defp validate_call_initiate_payload(payload) when is_map(payload) do
    callee_id = Map.get(payload, "callee_id")
    call_type = Map.get(payload, "call_type")
    
    cond do
      is_nil(callee_id) or not is_binary(callee_id) ->
        {:error, :invalid_callee_id}
      
      byte_size(callee_id) == 0 or byte_size(callee_id) > 128 ->
        {:error, :invalid_callee_id_length}
      
      is_nil(call_type) or not is_binary(call_type) ->
        {:error, :invalid_call_type}
      
      call_type not in ["voice", "video"] ->
        {:error, :invalid_call_type_value}
      
      true ->
        {:ok, %{callee_id: callee_id, call_type: call_type}}
    end
  end
  
  defp validate_call_initiate_payload(_) do
    {:error, :invalid_payload_type}
  end
  
  # SECURITY: Validate SDP payload (prevent injection and DoS)
  defp validate_sdp_payload(payload, expected_type) when is_map(payload) do
    sdp = Map.get(payload, "sdp")
    type = Map.get(payload, "type")
    
    cond do
      is_nil(sdp) or not is_binary(sdp) ->
        {:error, :missing_sdp}
      
      byte_size(sdp) == 0 ->
        {:error, :empty_sdp}
      
      # Prevent DoS: limit SDP size (typical SDP is < 4KB, allow up to 64KB)
      byte_size(sdp) > 65_536 ->
        {:error, :sdp_too_large}
      
      is_nil(type) or type != expected_type ->
        {:error, :invalid_sdp_type}
      
      # Basic SDP format validation (should start with "v=0")
      not String.starts_with?(sdp, "v=") ->
        {:error, :invalid_sdp_format}
      
      true ->
        {:ok, sdp}
    end
  end
  
  defp validate_sdp_payload(_, _) do
    {:error, :invalid_payload_type}
  end
  
  # SECURITY: Validate ICE candidate payload
  defp validate_ice_candidate_payload(payload) when is_map(payload) do
    candidate = Map.get(payload, "candidate")
    sdp_mid = Map.get(payload, "sdp_mid")
    sdp_m_line_index = Map.get(payload, "sdp_m_line_index")
    
    cond do
      is_nil(candidate) or not is_binary(candidate) ->
        {:error, :missing_candidate}
      
      byte_size(candidate) == 0 ->
        {:error, :empty_candidate}
      
      # Prevent DoS: limit candidate size
      byte_size(candidate) > 1_024 ->
        {:error, :candidate_too_large}
      
      # Validate sdp_mid if provided
      not is_nil(sdp_mid) and (not is_binary(sdp_mid) or byte_size(sdp_mid) > 64) ->
        {:error, :invalid_sdp_mid}
      
      # Validate sdp_m_line_index if provided
      not is_nil(sdp_m_line_index) and (not is_integer(sdp_m_line_index) or sdp_m_line_index < 0 or sdp_m_line_index > 65535) ->
        {:error, :invalid_sdp_m_line_index}
      
      # Basic candidate format validation (should start with "candidate:")
      not String.starts_with?(candidate, "candidate:") ->
        {:error, :invalid_candidate_format}
      
      true ->
        validated = %{
          "candidate" => candidate,
          "sdp_mid" => sdp_mid,
          "sdp_m_line_index" => sdp_m_line_index
        }
        {:ok, validated}
    end
  end
  
  defp validate_ice_candidate_payload(_) do
    {:error, :invalid_payload_type}
  end
end
