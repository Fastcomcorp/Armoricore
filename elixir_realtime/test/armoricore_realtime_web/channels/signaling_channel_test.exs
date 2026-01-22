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

defmodule ArmoricoreRealtimeWeb.SignalingChannelTest do
  @moduledoc """
  Unit tests for SignalingChannel validation functions.
  These tests don't require database access.
  """

  use ExUnit.Case, async: true

  alias ArmoricoreRealtimeWeb.SignalingChannel

  describe "validate_call_id/1" do
    test "accepts valid call IDs" do
      assert {:ok, "valid-call-123"} = SignalingChannel.validate_call_id("valid-call-123")
      assert {:ok, "call_456"} = SignalingChannel.validate_call_id("call_456")
      assert {:ok, "call-with-dash"} = SignalingChannel.validate_call_id("call-with-dash")
    end

    test "rejects empty call IDs" do
      assert {:error, :empty_call_id} = SignalingChannel.validate_call_id("")
    end

    test "rejects call IDs that are too long" do
      long_id = String.duplicate("a", 129)
      assert {:error, :call_id_too_long} = SignalingChannel.validate_call_id(long_id)
    end

    test "rejects call IDs with invalid characters" do
      assert {:error, :invalid_call_id_format} = SignalingChannel.validate_call_id("call@invalid")
      assert {:error, :invalid_call_id_format} = SignalingChannel.validate_call_id("call invalid")
      assert {:error, :invalid_call_id_format} = SignalingChannel.validate_call_id("call#invalid")
    end

    test "rejects non-binary inputs" do
      assert {:error, :invalid_call_id_type} = SignalingChannel.validate_call_id(nil)
      assert {:error, :invalid_call_id_type} = SignalingChannel.validate_call_id(123)
      assert {:error, :invalid_call_id_type} = SignalingChannel.validate_call_id([])
    end
  end

  describe "validate_call_initiate_payload/1" do
    test "accepts valid call initiate payload" do
      payload = %{"callee_id" => "user-123", "call_type" => "voice"}
      assert {:ok, %{callee_id: "user-123", call_type: "voice"}} = SignalingChannel.validate_call_initiate_payload(payload)

      payload = %{"callee_id" => "user-456", "call_type" => "video"}
      assert {:ok, %{callee_id: "user-456", call_type: "video"}} = SignalingChannel.validate_call_initiate_payload(payload)
    end

    test "rejects missing callee_id" do
      payload = %{"call_type" => "voice"}
      assert {:error, :invalid_callee_id} = SignalingChannel.validate_call_initiate_payload(payload)
    end

    test "rejects non-binary callee_id" do
      payload = %{"callee_id" => 123, "call_type" => "voice"}
      assert {:error, :invalid_callee_id} = SignalingChannel.validate_call_initiate_payload(payload)
    end

    test "rejects empty callee_id" do
      payload = %{"callee_id" => "", "call_type" => "voice"}
      assert {:error, :invalid_callee_id} = SignalingChannel.validate_call_initiate_payload(payload)
    end

    test "rejects callee_id that is too long" do
      long_id = String.duplicate("a", 129)
      payload = %{"callee_id" => long_id, "call_type" => "voice"}
      assert {:error, :invalid_callee_id_length} = SignalingChannel.validate_call_initiate_payload(payload)
    end

    test "rejects missing call_type" do
      payload = %{"callee_id" => "user-123"}
      assert {:error, :invalid_call_type} = SignalingChannel.validate_call_initiate_payload(payload)
    end

    test "rejects non-binary call_type" do
      payload = %{"callee_id" => "user-123", "call_type" => :voice}
      assert {:error, :invalid_call_type} = SignalingChannel.validate_call_initiate_payload(payload)
    end

    test "rejects invalid call_type values" do
      payload = %{"callee_id" => "user-123", "call_type" => "invalid"}
      assert {:error, :invalid_call_type_value} = SignalingChannel.validate_call_initiate_payload(payload)
    end

    test "rejects non-map payloads" do
      assert {:error, :invalid_payload_type} = SignalingChannel.validate_call_initiate_payload("invalid")
      assert {:error, :invalid_payload_type} = SignalingChannel.validate_call_initiate_payload(nil)
    end
  end

  describe "validate_sdp_payload/2" do
    test "accepts valid SDP offer payload" do
      sdp = "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
      payload = %{"sdp" => sdp, "type" => "offer"}
      assert {:ok, ^sdp} = SignalingChannel.validate_sdp_payload(payload, "offer")
    end

    test "accepts valid SDP answer payload" do
      sdp = "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
      payload = %{"sdp" => sdp, "type" => "answer"}
      assert {:ok, ^sdp} = SignalingChannel.validate_sdp_payload(payload, "answer")
    end

    test "rejects missing SDP" do
      payload = %{"type" => "offer"}
      assert {:error, :missing_sdp} = SignalingChannel.validate_sdp_payload(payload, "offer")
    end

    test "rejects non-binary SDP" do
      payload = %{"sdp" => 123, "type" => "offer"}
      assert {:error, :missing_sdp} = SignalingChannel.validate_sdp_payload(payload, "offer")
    end

    test "rejects empty SDP" do
      payload = %{"sdp" => "", "type" => "offer"}
      assert {:error, :empty_sdp} = SignalingChannel.validate_sdp_payload(payload, "offer")
    end

    test "rejects SDP that is too large" do
      large_sdp = String.duplicate("a", 65_537)
      payload = %{"sdp" => large_sdp, "type" => "offer"}
      assert {:error, :sdp_too_large} = SignalingChannel.validate_sdp_payload(payload, "offer")
    end

    test "rejects invalid SDP type" do
      sdp = "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
      payload = %{"sdp" => sdp, "type" => "invalid"}
      assert {:error, :invalid_sdp_type} = SignalingChannel.validate_sdp_payload(payload, "offer")
    end

    test "rejects missing SDP type" do
      sdp = "v=0\r\no=- 123 456 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
      payload = %{"sdp" => sdp}
      assert {:error, :invalid_sdp_type} = SignalingChannel.validate_sdp_payload(payload, "offer")
    end

    test "rejects SDP that doesn't start with v=" do
      sdp = "invalid sdp content"
      payload = %{"sdp" => sdp, "type" => "offer"}
      assert {:error, :invalid_sdp_format} = SignalingChannel.validate_sdp_payload(payload, "offer")
    end

    test "rejects non-map payloads" do
      assert {:error, :invalid_payload_type} = SignalingChannel.validate_sdp_payload("invalid", "offer")
      assert {:error, :invalid_payload_type} = SignalingChannel.validate_sdp_payload(nil, "offer")
    end
  end

  describe "validate_ice_candidate_payload/1" do
    test "accepts valid ICE candidate payload" do
      candidate = "candidate:1 1 UDP 2013266431 192.168.1.1 5000 typ host"
      payload = %{
        "candidate" => candidate,
        "sdp_mid" => "0",
        "sdp_m_line_index" => 0
      }
      expected = %{
        "candidate" => candidate,
        "sdp_mid" => "0",
        "sdp_m_line_index" => 0
      }
      assert {:ok, ^expected} = SignalingChannel.validate_ice_candidate_payload(payload)
    end

    test "accepts ICE candidate payload with nil optional fields" do
      candidate = "candidate:1 1 UDP 2013266431 192.168.1.1 5000 typ host"
      payload = %{"candidate" => candidate}
      expected = %{
        "candidate" => candidate,
        "sdp_mid" => nil,
        "sdp_m_line_index" => nil
      }
      assert {:ok, ^expected} = SignalingChannel.validate_ice_candidate_payload(payload)
    end

    test "rejects missing candidate" do
      payload = %{"sdp_mid" => "0"}
      assert {:error, :missing_candidate} = SignalingChannel.validate_ice_candidate_payload(payload)
    end

    test "rejects non-binary candidate" do
      payload = %{"candidate" => 123}
      assert {:error, :missing_candidate} = SignalingChannel.validate_ice_candidate_payload(payload)
    end

    test "rejects empty candidate" do
      payload = %{"candidate" => ""}
      assert {:error, :empty_candidate} = SignalingChannel.validate_ice_candidate_payload(payload)
    end

    test "rejects candidate that is too large" do
      large_candidate = String.duplicate("a", 1025)
      payload = %{"candidate" => large_candidate}
      assert {:error, :candidate_too_large} = SignalingChannel.validate_ice_candidate_payload(payload)
    end

    test "rejects invalid sdp_mid" do
      candidate = "candidate:1 1 UDP 2013266431 192.168.1.1 5000 typ host"
      payload = %{
        "candidate" => candidate,
        "sdp_mid" => String.duplicate("a", 65)  # Too long
      }
      assert {:error, :invalid_sdp_mid} = SignalingChannel.validate_ice_candidate_payload(payload)
    end

    test "rejects invalid sdp_m_line_index" do
      candidate = "candidate:1 1 UDP 2013266431 192.168.1.1 5000 typ host"
      payload = %{
        "candidate" => candidate,
        "sdp_m_line_index" => -1  # Negative
      }
      assert {:error, :invalid_sdp_m_line_index} = SignalingChannel.validate_ice_candidate_payload(payload)

      payload = %{
        "candidate" => candidate,
        "sdp_m_line_index" => 65_536  # Too large
      }
      assert {:error, :invalid_sdp_m_line_index} = SignalingChannel.validate_ice_candidate_payload(payload)

      payload = %{
        "candidate" => candidate,
        "sdp_m_line_index" => "invalid"  # Not integer
      }
      assert {:error, :invalid_sdp_m_line_index} = SignalingChannel.validate_ice_candidate_payload(payload)
    end

    test "rejects candidate that doesn't start with 'candidate:'" do
      candidate = "invalid candidate format"
      payload = %{"candidate" => candidate}
      assert {:error, :invalid_candidate_format} = SignalingChannel.validate_ice_candidate_payload(payload)
    end

    test "rejects non-map payloads" do
      assert {:error, :invalid_payload_type} = SignalingChannel.validate_ice_candidate_payload("invalid")
      assert {:error, :invalid_payload_type} = SignalingChannel.validate_ice_candidate_payload(nil)
    end
  end
end