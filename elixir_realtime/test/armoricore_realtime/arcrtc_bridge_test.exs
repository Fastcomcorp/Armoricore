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

defmodule ArmoricoreRealtime.ArcRtcBridgeTest do
  @moduledoc """
  Unit tests for ArcRTC Bridge protocol translation.

  Tests the bidirectional translation between WebRTC and ArcRTC protocols.
  """

  use ExUnit.Case, async: true

  alias ArmoricoreRealtime.ArcRtcBridge

  describe "webrtc_to_arcrtc/4" do
    test "translates valid WebRTC SDP to ArcRTC ConnectRequest" do
      session_id = "test-session-123"
      sdp_offer = """
      v=0
      o=- 123456789 0 IN IP4 127.0.0.1
      s=-
      t=0 0
      m=audio 5000 RTP/AVP 96
      a=rtpmap:96 opus/48000/2
      m=video 5002 RTP/AVP 97
      a=rtpmap:97 H264/90000
      """

      ice_candidates = [
        %{"candidate" => "candidate:1 1 UDP 2013266431 192.168.1.1 5000 typ host"}
      ]

      metadata = %{peer_id: "webrtc-client-456"}

      result = ArcRtcBridge.webrtc_to_arcrtc(session_id, sdp_offer, ice_candidates, metadata)

      assert {:ok, arc_request} = result
      assert arc_request.type == "CONNECT"
      assert arc_request.version == "1.0"
      assert arc_request.session_id == session_id
      assert arc_request.peer_id == "webrtc-client-456"
      assert is_map(arc_request.capabilities)
      assert is_integer(arc_request.timestamp)
    end

    test "extracts audio and video codecs from SDP" do
      session_id = "test-session-456"
      sdp_offer = """
      v=0
      o=- 123456789 0 IN IP4 127.0.0.1
      s=-
      t=0 0
      m=audio 5000 RTP/AVP 96 8
      a=rtpmap:96 opus/48000/2
      a=rtpmap:8 PCMA/8000
      m=video 5002 RTP/AVP 97 98
      a=rtpmap:97 H264/90000
      a=rtpmap:98 VP9/90000
      """

      result = ArcRtcBridge.webrtc_to_arcrtc(session_id, sdp_offer)

      assert {:ok, arc_request} = result
      capabilities = arc_request.capabilities

      # Check audio codecs
      assert "opus" in capabilities.audio_codecs
      assert "PCMA" in capabilities.audio_codecs

      # Check video codecs
      assert "H264" in capabilities.video_codecs
      assert "VP9" in capabilities.video_codecs
    end

    test "handles invalid SDP gracefully" do
      session_id = "test-session-invalid"
      invalid_sdp = "invalid sdp content"

      result = ArcRtcBridge.webrtc_to_arcrtc(session_id, invalid_sdp)

      assert {:error, :invalid_sdp_format} = result
    end

    test "includes encryption support by default" do
      session_id = "test-session-secure"
      sdp_offer = """
      v=0
      o=- 123456789 0 IN IP4 127.0.0.1
      s=-
      t=0 0
      m=audio 5000 RTP/AVP 96
      a=rtpmap:96 opus/48000/2
      """

      result = ArcRtcBridge.webrtc_to_arcrtc(session_id, sdp_offer)

      assert {:ok, arc_request} = result
      assert arc_request.capabilities.encryption_supported == true
    end
  end

  describe "arcrtc_to_webrtc/2" do
    test "translates ArcRTC ConnectAck to WebRTC SDP answer" do
      arc_ack = %{
        "session_id" => "test-session-789",
        "capabilities" => %{
          "audio_codecs" => ["opus"],
          "video_codecs" => ["H264"]
        }
      }

      original_offer = """
      v=0
      o=- 123456789 0 IN IP4 127.0.0.1
      s=-
      t=0 0
      m=audio 5000 RTP/AVP 96
      m=video 5002 RTP/AVP 97
      """

      result = ArcRtcBridge.arcrtc_to_webrtc(arc_ack, original_offer)

      assert {:ok, webrtc_response} = result
      assert is_binary(webrtc_response.sdp)
      assert String.contains?(webrtc_response.sdp, "v=0")
      assert String.contains?(webrtc_response.sdp, "m=audio")
      assert String.contains?(webrtc_response.sdp, "m=video")
      assert webrtc_response.session_id == "test-session-789"
      assert is_list(webrtc_response.ice_candidates)
    end

    test "handles missing capabilities gracefully" do
      arc_ack = %{
        "session_id" => "test-session-missing",
        "capabilities" => %{}
      }

      original_offer = "v=0\r\no=- 123456789 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0"

      result = ArcRtcBridge.arcrtc_to_webrtc(arc_ack, original_offer)

      assert {:ok, webrtc_response} = result
      assert is_binary(webrtc_response.sdp)
    end
  end

  describe "route_media_packet/4" do
    test "routes WebRTC to ArcRTC packets" do
      packet = <<1, 2, 3, 4, 5>>
      stream_id = "test-stream-123"

      # This should not error (routes to media engine)
      result = ArcRtcBridge.route_media_packet(packet, :webrtc, :arcrtc, stream_id)

      assert result == :ok
    end

    test "routes ArcRTC to WebRTC packets" do
      packet = <<5, 4, 3, 2, 1>>
      stream_id = "test-stream-456"

      # This should not error (routes to media engine)
      result = ArcRtcBridge.route_media_packet(packet, :arcrtc, :webrtc, stream_id)

      assert result == :ok
    end

    test "handles same protocol routing" do
      packet = <<9, 8, 7, 6, 5>>
      stream_id = "test-stream-789"

      result = ArcRtcBridge.route_media_packet(packet, :webrtc, :webrtc, stream_id)

      assert result == :ok
    end
  end

  describe "validate_session_compatibility/3" do
    test "validates compatible sessions" do
      session_id = "test-session-compat"
      webrtc_caps = %{
        "audio_codecs" => ["opus", "PCMA"],
        "video_codecs" => ["H264", "VP9"],
        "max_bitrate" => 2000000
      }
      arcrtc_caps = %{
        "audio_codecs" => ["opus", "AAC"],
        "video_codecs" => ["H264", "AV1"],
        "max_bitrate" => 2500000
      }

      result = ArcRtcBridge.validate_session_compatibility(session_id, webrtc_caps, arcrtc_caps)

      assert {:ok, negotiated} = result
      assert "opus" in negotiated.audio_codecs
      assert "H264" in negotiated.video_codecs
      assert negotiated.max_bitrate == 2000000  # Min of both
    end

    test "rejects incompatible sessions" do
      session_id = "test-session-incompat"
      webrtc_caps = %{
        "audio_codecs" => ["PCMU"],
        "video_codecs" => ["H263"],
        "max_bitrate" => 1000000
      }
      arcrtc_caps = %{
        "audio_codecs" => ["AAC"],
        "video_codecs" => ["AV1"],
        "max_bitrate" => 2000000
      }

      result = ArcRtcBridge.validate_session_compatibility(session_id, webrtc_caps, arcrtc_caps)

      assert {:error, :incompatible} = result
    end

    test "handles empty capabilities" do
      session_id = "test-session-empty"
      webrtc_caps = %{}
      arcrtc_caps = %{}

      result = ArcRtcBridge.validate_session_compatibility(session_id, webrtc_caps, arcrtc_caps)

      assert {:error, :incompatible} = result
    end
  end

  describe "SDP parsing utilities" do
    test "parses basic SDP structure" do
      sdp = """
      v=0
      o=- 123456789 0 IN IP4 127.0.0.1
      s=Test Session
      t=0 0
      m=audio 5000 RTP/AVP 96
      a=rtpmap:96 opus/48000/2
      m=video 5002 RTP/AVP 97
      a=rtpmap:97 H264/90000
      """

      # Test internal parsing (this is a simplified test)
      # The actual parsing is tested through webrtc_to_arcrtc
      result = ArcRtcBridge.webrtc_to_arcrtc("test", sdp)

      assert {:ok, _arc_request} = result
    end

    test "handles codec mapping correctly" do
      # Test that RTP payload types map to codec names
      # This is tested indirectly through the main functions

      sdp = """
      v=0
      o=- 123456789 0 IN IP4 127.0.0.1
      s=-
      t=0 0
      m=audio 5000 RTP/AVP 0 8 96
      a=rtpmap:0 PCMU/8000
      a=rtpmap:8 PCMA/8000
      a=rtpmap:96 opus/48000/2
      """

      result = ArcRtcBridge.webrtc_to_arcrtc("test-codecs", sdp)

      assert {:ok, arc_request} = result
      capabilities = arc_request.capabilities

      assert "PCMU" in capabilities.audio_codecs
      assert "PCMA" in capabilities.audio_codecs
      assert "opus" in capabilities.audio_codecs
    end
  end

  describe "error handling" do
    test "handles malformed SDP gracefully" do
      result = ArcRtcBridge.webrtc_to_arcrtc("test", nil)
      assert {:error, _reason} = result

      result = ArcRtcBridge.webrtc_to_arcrtc("test", "")
      assert {:error, _reason} = result
    end

    test "handles invalid ArcRTC responses" do
      result = ArcRtcBridge.arcrtc_to_webrtc(nil, "sdp")
      assert {:error, _reason} = result

      result = ArcRtcBridge.arcrtc_to_webrtc(%{}, nil)
      assert {:error, _reason} = result
    end

    test "handles nil parameters gracefully" do
      result = ArcRtcBridge.route_media_packet(nil, :webrtc, :arcrtc, "stream")
      assert result == :ok  # Should not crash
    end
  end
end