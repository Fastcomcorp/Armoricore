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

defmodule ArmoricoreRealtime.ArcRtcBridge do
  @moduledoc """
  Protocol bridge between WebRTC and ArcRTC signaling protocols.

  This module provides bidirectional translation between:
  - WebRTC SDP/ICE signaling and ArcRTC ArcSignaling messages
  - WebRTC media streams and ArcRTC ArcRTP packets
  - WebRTC peer connections and ArcRTC sessions

  ## Architecture

  ```
  WebRTC Client ── WebRTC Signaling ── ArcRTC Bridge ── ArcRTC Signaling ── ArcRTC Client
  (Browser)         (SDP/ICE)           (Translation)      (ArcSignaling)      (Native App)
  ```

  ## Key Features

  - **Protocol Translation**: Converts WebRTC SDP offers/answers to ArcRTC messages
  - **Codec Mapping**: Translates codec specifications between protocols
  - **Capability Negotiation**: Handles capability discovery and negotiation
  - **Error Handling**: Graceful degradation and error translation
  - **Performance**: Optimized for low-latency translation
  """

  require Logger
  alias ArmoricoreRealtime.MediaEngineClient
  alias ArmoricoreRealtime.ArcRtcSecurity
  alias ArmoricoreRealtime.E2EE

  @doc """
  Translates WebRTC SDP offer to ArcRTC ConnectRequest.

  ## Parameters
  - `session_id`: Unique session identifier
  - `sdp_offer`: WebRTC SDP offer string
  - `ice_candidates`: Optional list of ICE candidates
  - `metadata`: Optional metadata (user_id, room_id, etc.)
  - `security_config`: Optional security configuration for E2EE

  ## Returns
  - `{:ok, arc_connect_request}` - Successful translation
  - `{:error, reason}` - Translation failed
  """
  @spec webrtc_to_arcrtc(String.t(), String.t(), [map()], map()) ::
    {:ok, map()} | {:error, atom()}
  @spec secure_webrtc_to_arcrtc(String.t(), String.t(), [map()], map(), list(map())) ::
    {:ok, {map(), map()}} | {:error, atom()}
  def webrtc_to_arcrtc(session_id, sdp_offer, ice_candidates \\ [], metadata \\ %{}) do
    Logger.debug("Translating WebRTC SDP to ArcRTC ConnectRequest", %{
      session_id: session_id,
      sdp_length: String.length(sdp_offer)
    })

    # Validate input parameters
    with {:ok, _} <- validate_input_params(session_id, sdp_offer),
         {:ok, parsed_sdp} <- parse_webrtc_sdp(sdp_offer),
         {:ok, capabilities} <- extract_capabilities(parsed_sdp),
         {:ok, arc_request} <- create_arc_connect_request(session_id, capabilities, metadata) do

      Logger.info("WebRTC → ArcRTC translation successful", %{
        session_id: session_id,
        audio_codecs: length(capabilities.audio_codecs),
        video_codecs: length(capabilities.video_codecs)
      })

      {:ok, arc_request}
    else
      {:error, reason} ->
        Logger.error("WebRTC → ArcRTC translation failed", %{
          session_id: session_id,
          reason: reason
        })
        {:error, reason}
    end
  rescue
    error ->
      Logger.error("Exception in WebRTC → ArcRTC translation", %{
        session_id: session_id,
        error: inspect(error)
      })
      {:error, :translation_exception}
  end

  @doc """
  Creates a secure ArcRTC session with E2EE capabilities.

  ## Parameters
  - `session_id`: Unique session identifier
  - `sdp_offer`: WebRTC SDP offer string
  - `ice_candidates`: Optional list of ICE candidates
  - `metadata`: Session metadata
  - `participant_keys`: List of participant identity keys for E2EE

  ## Returns
  - `{:ok, {arc_connect_request, secure_session}}` - Successful secure session creation
  - `{:error, reason}` - Session creation failed
  """
  def secure_webrtc_to_arcrtc(session_id, sdp_offer, ice_candidates \\ [], metadata \\ %{}, participant_keys \\ []) do
    Logger.debug("Creating secure ArcRTC session", %{
      session_id: session_id,
      participant_count: length(participant_keys)
    })

    with {:ok, _} <- validate_input_params(session_id, sdp_offer),
         {:ok, parsed_sdp} <- parse_webrtc_sdp(sdp_offer),
         {:ok, capabilities} <- extract_capabilities(parsed_sdp),
         {:ok, secure_session} <- ArcRtcSecurity.create_secure_session(session_id, participant_keys),
         {:ok, arc_request} <- create_secure_arc_connect_request(session_id, capabilities, metadata, secure_session) do

      Logger.info("Secure ArcRTC session created successfully", %{
        session_id: session_id,
        audio_codecs: length(capabilities.audio_codecs),
        video_codecs: length(capabilities.video_codecs)
      })

      {:ok, {arc_request, secure_session}}
    else
      {:error, reason} ->
        Logger.error("Secure ArcRTC session creation failed", %{
          session_id: session_id,
          reason: reason
        })
        {:error, reason}
    end
  rescue
    error ->
      Logger.error("Exception in secure ArcRTC session creation", %{
        session_id: session_id,
        error: inspect(error)
      })
      {:error, :secure_session_exception}
  end

  defp validate_input_params(session_id, sdp_offer) do
    cond do
      is_nil(session_id) or not is_binary(session_id) or String.length(session_id) == 0 ->
        {:error, :invalid_session_id}
      is_nil(sdp_offer) or not is_binary(sdp_offer) or String.length(sdp_offer) == 0 ->
        {:error, :invalid_sdp}
      true ->
        {:ok, :valid}
    end
  end

  @doc """
  Translates ArcRTC ConnectAck to WebRTC-compatible SDP answer.

  ## Parameters
  - `arc_ack`: ArcRTC ConnectAck message
  - `original_offer`: Original WebRTC SDP offer (for reference)

  ## Returns
  - `{:ok, %{sdp: sdp_answer, ice_candidates: candidates}}` - Successful translation
  - `{:error, reason}` - Translation failed
  """
  @spec arcrtc_to_webrtc(map(), String.t()) ::
    {:ok, %{sdp: String.t(), ice_candidates: [map()]}} | {:error, atom()}
  def arcrtc_to_webrtc(arc_ack, original_offer) do
    Logger.debug("Translating ArcRTC ConnectAck to WebRTC SDP", %{
      session_id: get_session_id(arc_ack)
    })

    # Validate input
    with {:ok, _} <- validate_arcrtc_input(arc_ack),
         {:ok, _} <- validate_original_offer(original_offer) do
      # Extract negotiated capabilities from ArcRTC response
      capabilities = get_capabilities(arc_ack)

      # Create WebRTC SDP answer
      with {:ok, sdp_answer} <- create_webrtc_sdp_answer(capabilities, original_offer),
           {:ok, ice_candidates} <- extract_ice_candidates(arc_ack) do

        result = %{
          sdp: sdp_answer,
          ice_candidates: ice_candidates,
          session_id: get_session_id(arc_ack)
        }

        Logger.info("ArcRTC → WebRTC translation successful", %{
          session_id: result.session_id
        })

        {:ok, result}
      else
        {:error, reason} ->
          Logger.error("ArcRTC → WebRTC translation failed", %{
            reason: reason
          })
          {:error, reason}
      end
    end
  rescue
    error ->
      Logger.error("Exception in ArcRTC → WebRTC translation", %{
        error: inspect(error)
      })
      {:error, :translation_exception}
  end

  defp validate_arcrtc_input(arc_ack) do
    cond do
      is_nil(arc_ack) ->
        {:error, :invalid_arcrtc_response}
      not is_map(arc_ack) ->
        {:error, :invalid_arcrtc_response_type}
      map_size(arc_ack) == 0 ->
        {:error, :empty_arcrtc_response}
      true ->
        {:ok, :valid}
    end
  end

  defp validate_original_offer(original_offer) do
    cond do
      is_nil(original_offer) ->
        {:error, :missing_original_offer}
      not is_binary(original_offer) ->
        {:error, :invalid_original_offer_type}
      String.length(original_offer) == 0 ->
        {:error, :empty_original_offer}
      true ->
        {:ok, :valid}
    end
  end

  defp get_session_id(arc_ack) do
    arc_ack["session_id"] || arc_ack[:session_id]
  end

  defp get_capabilities(arc_ack) do
    arc_ack["capabilities"] || arc_ack[:capabilities] || %{}
  end

  @doc """
  Routes media packets between WebRTC and ArcRTC streams.

  ## Parameters
  - `packet`: Media packet data
  - `from_protocol`: `:webrtc` or `:arcrtc`
  - `to_protocol`: `:webrtc` or `:arcrtc`
  - `stream_id`: Stream identifier

  ## Returns
  - `:ok` - Packet routed successfully
  - `{:error, reason}` - Routing failed
  """
  @spec route_media_packet(binary(), :webrtc | :arcrtc, :webrtc | :arcrtc, String.t()) ::
    :ok | {:error, atom()}
  def route_media_packet(packet, from_protocol, to_protocol, stream_id) do
    Logger.debug("Routing media packet", %{
      from_protocol: from_protocol,
      to_protocol: to_protocol,
      stream_id: stream_id,
      packet_size: byte_size(packet)
    })

    # For now, direct routing - in future may need format conversion
    case {from_protocol, to_protocol} do
      {:webrtc, :arcrtc} ->
        # Convert WebRTC RTP to ArcRTP if needed
        route_webrtc_to_arcrtc(packet, stream_id)
        :ok

      {:arcrtc, :webrtc} ->
        # Convert ArcRTP to WebRTC RTP if needed
        route_arcrtc_to_webrtc(packet, stream_id)
        :ok

      {same, same} ->
        # Same protocol, direct routing
        MediaEngineClient.route_packet(stream_id, packet)
        :ok
    end
  rescue
    error ->
      Logger.error("Failed to route media packet", %{
        error: inspect(error),
        from_protocol: from_protocol,
        to_protocol: to_protocol,
        stream_id: stream_id
      })
      {:error, :routing_failed}
  end

  @doc """
  Validates ArcRTC session compatibility.

  ## Parameters
  - `session_id`: Session identifier
  - `webrtc_capabilities`: WebRTC client capabilities
  - `arcrtc_capabilities`: ArcRTC client capabilities

  ## Returns
  - `{:ok, negotiated_caps}` - Compatible, returns negotiated capabilities
  - `{:error, :incompatible}` - Protocols not compatible
  """
  @spec validate_session_compatibility(String.t(), map(), map()) ::
    {:ok, map()} | {:error, :incompatible}
  def validate_session_compatibility(session_id, webrtc_caps, arcrtc_caps) do
    Logger.debug("Validating session compatibility", %{session_id: session_id})

    # Check codec compatibility
    webrtc_audio = webrtc_caps["audio_codecs"] || []
    webrtc_video = webrtc_caps["video_codecs"] || []
    arcrtc_audio = arcrtc_caps["audio_codecs"] || []
    arcrtc_video = arcrtc_caps["video_codecs"] || []

    # Find common codecs
    common_audio = webrtc_audio -- (webrtc_audio -- arcrtc_audio)
    common_video = webrtc_video -- (webrtc_video -- arcrtc_video)

    if length(common_audio) > 0 or length(common_video) > 0 do
      negotiated = %{
        audio_codecs: common_audio,
        video_codecs: common_video,
        max_bitrate: min(webrtc_caps["max_bitrate"] || 2000000,
                        arcrtc_caps["max_bitrate"] || 2000000)
      }

      Logger.info("Session compatibility validated", %{
        session_id: session_id,
        common_audio: length(common_audio),
        common_video: length(common_video)
      })

      {:ok, negotiated}
    else
      Logger.warning("Session incompatible - no common codecs", %{
        session_id: session_id
      })
      {:error, :incompatible}
    end
  end

  # Private Functions

  defp parse_webrtc_sdp(sdp_text) do
    try do
      # Basic validation
      if is_nil(sdp_text) or not is_binary(sdp_text) do
        {:error, :invalid_sdp_type}
      else
        # Parse SDP lines
        lines = String.split(sdp_text, ["\r\n", "\n"], trim: true)

        # Must have at least a version line
        if Enum.empty?(lines) or not Enum.any?(lines, &String.starts_with?(&1, "v=")) do
          {:error, :invalid_sdp_format}
        else
          # Extract media descriptions
          media_descriptions = Enum.filter(lines, &String.starts_with?(&1, "m="))

          # Extract codecs from rtpmap attributes
          rtpmap_lines = Enum.filter(lines, &String.starts_with?(&1, "a=rtpmap:"))

          # Basic SDP structure
          parsed = %{
            media_descriptions: media_descriptions,
            rtpmap_lines: rtpmap_lines,
            raw_sdp: sdp_text
          }

          {:ok, parsed}
        end
      end
    rescue
      _ -> {:error, :invalid_sdp_format}
    end
  end

  defp extract_capabilities(parsed_sdp) do
    try do
      # Extract audio codecs
      audio_codecs = extract_codecs_for_media(parsed_sdp, "audio")

      # Extract video codecs
      video_codecs = extract_codecs_for_media(parsed_sdp, "video")

      # Extract other capabilities
      capabilities = %{
        audio_codecs: audio_codecs,
        video_codecs: video_codecs,
        resolutions: ["720p", "1080p"],  # Default supported resolutions
        max_bitrate: 2000000,  # 2 Mbps default
        encryption_supported: true
      }

      {:ok, capabilities}
    rescue
      _ -> {:error, :capability_extraction_failed}
    end
  end

  defp extract_codecs_for_media(parsed_sdp, media_type) do
    # Find media descriptions for this type
    media_lines = Enum.filter(parsed_sdp.media_descriptions,
                             &String.contains?(&1, "#{media_type} "))

    codecs = for media_line <- media_lines do
      # Extract codec numbers from m= line (e.g., "m=audio 5000 RTP/AVP 96")
      case Regex.run(~r/m=#{media_type} \d+ RTP\/AVP (.+)/, media_line) do
        [_, codec_nums] ->
          codec_nums
          |> String.split()
          |> Enum.map(&codec_number_to_name(&1))
          |> Enum.reject(&is_nil/1)
        _ -> []
      end
    end

    # Also check rtpmap lines for codec information
    rtpmap_codecs = extract_codecs_from_rtpmap(parsed_sdp.rtpmap_lines, media_type)

    # Combine and deduplicate
    (List.flatten(codecs) ++ rtpmap_codecs) |> Enum.uniq()
  end

  defp extract_codecs_from_rtpmap(rtpmap_lines, media_type) do
    # Extract codecs from rtpmap lines like "a=rtpmap:96 opus/48000/2"
    for line <- rtpmap_lines do
      case Regex.run(~r/a=rtpmap:\d+ (\w+)/, line) do
        [_, codec_name] ->
          # Map common codec names
          case String.downcase(codec_name) do
            "opus" -> "opus"
            "h264" -> "H264"
            "vp8" -> "VP8"
            "vp9" -> "VP9"
            "pcmu" -> "PCMU"
            "pcma" -> "PCMA"
            "g722" -> "G722"
            _ -> nil
          end
        _ -> nil
      end
    end
    |> Enum.reject(&is_nil/1)
  end

  defp codec_number_to_name(number) do
    # RTP payload type to codec name mapping
    case number do
      "0" -> "PCMU"
      "8" -> "PCMA"
      "9" -> "G722"
      "96" -> "opus"
      "97" -> "H264"
      "98" -> "VP8"
      "99" -> "VP9"
      "100" -> "H265"
      _ -> nil
    end
  end

  defp create_arc_connect_request(session_id, capabilities, metadata) do
    try do
      # Create ArcRTC ConnectRequest
      request = %{
        type: "CONNECT",
        version: "1.0",
        session_id: session_id,
        peer_id: metadata[:peer_id] || "webrtc-client",
        capabilities: %{
          audio_codecs: capabilities.audio_codecs,
          video_codecs: capabilities.video_codecs,
          resolutions: capabilities.resolutions,
          max_bitrate: capabilities.max_bitrate,
          encryption_supported: capabilities.encryption_supported
        },
        timestamp: DateTime.utc_now() |> DateTime.to_unix()
      }

      {:ok, request}
    rescue
      _ -> {:error, :arc_request_creation_failed}
    end
  end

  defp create_secure_arc_connect_request(session_id, capabilities, metadata, secure_session) do
    try do
      # Create secure ArcRTC ConnectRequest with E2EE support
      request = %{
        type: "SECURE_CONNECT",
        version: "2.0",
        session_id: session_id,
        peer_id: metadata[:peer_id] || "secure-webrtc-client",
        capabilities: %{
          audio_codecs: capabilities.audio_codecs,
          video_codecs: capabilities.video_codecs,
          resolutions: capabilities.resolutions,
          max_bitrate: capabilities.max_bitrate,
          encryption_supported: true,
          e2ee_enabled: true,
          pfs_enabled: true
        },
        security: %{
          protocol_version: "ArcRTC-Secure-1.0",
          key_exchange: "X25519",
          cipher_suite: "AES-256-GCM",
          device_fingerprint: secure_session.device_fingerprints,
          session_keys: secure_session.session_keys.master_key,  # Would be encrypted in production
          ratchet_state: secure_session.ratchet_state
        },
        timestamp: DateTime.utc_now() |> DateTime.to_unix()
      }

      {:ok, request}
    rescue
      _ -> {:error, :secure_arc_request_creation_failed}
    end
  end

  defp create_webrtc_sdp_answer(capabilities, original_offer) do
    try do
      # Create basic SDP answer structure
      # This is a simplified implementation - production would need full SDP parsing
      selected_audio = List.first(capabilities["audio_codecs"] || ["opus"])
      selected_video = List.first(capabilities["video_codecs"] || ["VP9"])

      sdp_answer = """
      v=0
      o=- #{:rand.uniform(999999999)} 2 IN IP4 127.0.0.1
      s=-
      t=0 0
      a=group:BUNDLE audio video
      a=msid-semantic: WMS stream
      m=audio 9 UDP/TLS/RTP/SAVPF 96
      c=IN IP4 0.0.0.0
      a=rtcp:9 IN IP4 0.0.0.0
      a=ice-ufrag:#{:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)}
      a=ice-pwd:#{:crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)}
      a=ice-options:trickle
      a=fingerprint:sha-256 #{:crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)}
      a=setup:active
      a=mid:audio
      a=recvonly
      a=rtcp-mux
      a=rtpmap:96 #{String.downcase(selected_audio)}/48000/2
      a=fmtp:96 useinbandfec=1
      m=video 9 UDP/TLS/RTP/SAVPF 97
      c=IN IP4 0.0.0.0
      a=rtcp:9 IN IP4 0.0.0.0
      a=ice-ufrag:#{:crypto.strong_rand_bytes(4) |> Base.encode16(case: :lower)}
      a=ice-pwd:#{:crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)}
      a=ice-options:trickle
      a=fingerprint:sha-256 #{:crypto.strong_rand_bytes(32) |> Base.encode16(case: :lower)}
      a=setup:active
      a=mid:video
      a=recvonly
      a=rtcp-mux
      a=rtpmap:97 #{String.upcase(selected_video)}/90000
      """

      # Clean up the SDP string
      sdp_answer = String.trim(sdp_answer)

      {:ok, sdp_answer}
    rescue
      error ->
        Logger.error("Failed to create WebRTC SDP answer", %{error: inspect(error)})
        {:error, :sdp_creation_failed}
    end
  end

  defp extract_ice_candidates(arc_ack) do
    # Extract ICE candidates from ArcRTC response
    # This is placeholder - actual implementation would parse ArcRTC format
    candidates = arc_ack["ice_candidates"] || []

    # Convert to WebRTC format if needed
    webrtc_candidates = Enum.map(candidates, fn candidate ->
      %{
        candidate: candidate["candidate"] || "",
        sdpMid: candidate["sdp_mid"] || "0",
        sdpMLineIndex: candidate["sdp_m_line_index"] || 0
      }
    end)

    {:ok, webrtc_candidates}
  end

  defp route_webrtc_to_arcrtc(packet, stream_id) do
    # Placeholder for WebRTC RTP to ArcRTP conversion
    # In production, this would convert packet formats
    MediaEngineClient.route_packet(stream_id, packet)
  end

  defp route_arcrtc_to_webrtc(packet, stream_id) do
    # Placeholder for ArcRTP to WebRTC RTP conversion
    # In production, this would convert packet formats
    MediaEngineClient.route_packet(stream_id, packet)
  end
end