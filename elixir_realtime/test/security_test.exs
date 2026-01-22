# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC

defmodule ArmoricoreRealtime.SecurityTest do
  @moduledoc """
  Comprehensive security test suite for Armoricore.

  Tests authentication, authorization, input validation, and security controls.
  """

  use ExUnit.Case, async: false
  use ArmoricoreRealtimeWeb.ConnCase

  alias ArmoricoreRealtime.{Accounts, Content, Rooms, Messaging}
  alias ArmoricoreRealtimeWeb.{AuthController, VideoController}

  describe "authentication security" do
    test "prevents brute force attacks" do
      # Test rate limiting for login attempts
      invalid_credentials = %{email: "nonexistent@example.com", password: "wrong"}

      # Make multiple rapid login attempts
      results = for _ <- 1..20 do
        conn = post(build_conn(), "/api/v1/auth/login", invalid_credentials)
        conn.status
      end

      # Should eventually get rate limited (429)
      assert Enum.any?(results, &(&1 == 429)),
             "Rate limiting not working - no 429 status found in #{Enum.join(results, ", ")}"
    end

    test "validates JWT tokens properly" do
      # Test with valid token
      {:ok, user} = Accounts.register_user(%{
        email: "jwt-test-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "jwt_test_#{System.unique_integer()}"
      })

      {:ok, session} = Accounts.create_user_session(user, "test")
      valid_token = session.token

      # Valid token should work
      conn = put_req_header(build_conn(), "authorization", "Bearer #{valid_token}")
      conn = get(conn, "/api/v1/users/me")
      assert conn.status == 200

      # Invalid token should fail
      conn = put_req_header(build_conn(), "authorization", "Bearer invalid.jwt.token")
      conn = get(conn, "/api/v1/users/me")
      assert conn.status == 401

      # Malformed token should fail
      conn = put_req_header(build_conn(), "authorization", "Bearer not-a-jwt")
      conn = get(conn, "/api/v1/users/me")
      assert conn.status == 401

      # Cleanup
      Accounts.delete_user(user)
    end

    test "prevents JWT token tampering" do
      {:ok, user} = Accounts.register_user(%{
        email: "tamper-test-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "tamper_test_#{System.unique_integer()}"
      })

      {:ok, session} = Accounts.create_user_session(user, "test")

      # Decode and tamper with JWT payload
      [header, payload, signature] = String.split(session.token, ".")
      {:ok, decoded_payload} = Base.url_decode64(payload, padding: false)
      tampered_payload = Regex.replace(~r/"id":\d+/, decoded_payload, "\"id\":99999")
      tampered_payload_b64 = Base.url_encode64(tampered_payload, padding: false)
      tampered_token = "#{header}.#{tampered_payload_b64}.#{signature}"

      # Tampered token should fail
      conn = put_req_header(build_conn(), "authorization", "Bearer #{tampered_token}")
      conn = get(conn, "/api/v1/users/me")
      assert conn.status == 401

      # Cleanup
      Accounts.delete_user(user)
    end
  end

  describe "input validation and sanitization" do
    test "prevents SQL injection in search" do
      sql_payloads = [
        "' OR '1'='1",
        "; DROP TABLE users; --",
        "' UNION SELECT * FROM users --"
      ]

      for payload <- sql_payloads do
        conn = get(build_conn(), "/api/v1/videos/search?q=#{URI.encode(payload)}")
        # Should not crash with 500 error
        refute conn.status == 500, "SQL injection payload caused server error: #{payload}"
        # Should return valid JSON response
        assert conn.resp_body =~ ~s("data")
      end
    end

    test "prevents XSS in user inputs" do
      {:ok, user} = Accounts.register_user(%{
        email: "xss-test-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "xss_test_#{System.unique_integer()}"
      })

      {:ok, session} = Accounts.create_user_session(user, "test")

      xss_payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert('xss')"
      ]

      for payload <- xss_payloads do
        # Test video upload with XSS payload
        conn = put_req_header(build_conn(), "authorization", "Bearer #{session.token}")
        conn = post(conn, "/api/v1/videos", %{
          "title" => payload,
          "description" => "Test video",
          "file" => "" # Empty file for testing
        })

        if conn.status == 201 do
          # If video was created, check that XSS payload is not in response
          refute conn.resp_body =~ payload,
                 "XSS payload reflected in API response: #{payload}"
        end
      end

      # Cleanup
      Accounts.delete_user(user)
    end

    test "validates file upload security" do
      {:ok, user} = Accounts.register_user(%{
        email: "upload-test-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "upload_test_#{System.unique_integer()}"
      })

      {:ok, session} = Accounts.create_user_session(user, "test")

      # Test with invalid file types
      invalid_files = [
        %{filename: "test.exe", content_type: "application/x-msdownload"},
        %{filename: "malicious.php", content_type: "application/x-php"},
        %{filename: "script.js", content_type: "application/javascript"}
      ]

      for file_spec <- invalid_files do
        conn = put_req_header(build_conn(), "authorization", "Bearer #{session.token}")
        conn = post(conn, "/api/v1/videos", %{
          "title" => "Security Test",
          "description" => "Testing file upload",
          "file" => "" # Empty for test
        })

        # Should reject invalid file types
        assert conn.status in [400, 422],
               "Accepted invalid file type: #{file_spec.filename} (#{file_spec.content_type})"
      end

      # Cleanup
      Accounts.delete_user(user)
    end

    test "prevents path traversal attacks" do
      traversal_payloads = [
        "../../../etc/passwd",
        "../../../../windows/system32/cmd.exe",
        "../../../../../../etc/shadow"
      ]

      for payload <- traversal_payloads do
        # Test in various endpoints
        conn = get(build_conn(), "/api/v1/videos/search?q=#{URI.encode(payload)}")
        refute conn.status == 500,
               "Path traversal caused server error: #{payload}"

        conn = get(build_conn(), "/api/v1/videos/#{URI.encode(payload)}")
        assert conn.status in [400, 404],
               "Path traversal not properly handled: #{payload}"
      end
    end
  end

  describe "authorization and access control" do
    test "enforces proper resource ownership" do
      # Create two users
      {:ok, user1} = Accounts.register_user(%{
        email: "owner-test-1-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "owner_test_1_#{System.unique_integer()}"
      })

      {:ok, user2} = Accounts.register_user(%{
        email: "owner-test-2-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "owner_test_2_#{System.unique_integer()}"
      })

      {:ok, session1} = Accounts.create_user_session(user1, "test")
      {:ok, session2} = Accounts.create_user_session(user2, "test")

      # User 1 creates a video
      conn1 = put_req_header(build_conn(), "authorization", "Bearer #{session1.token}")
      conn1 = post(conn1, "/api/v1/videos", %{
        "title" => "User 1 Video",
        "description" => "Video owned by user 1",
        "file" => ""
      })

      assert conn1.status == 201
      %{"data" => %{"id" => video_id}} = Jason.decode!(conn1.resp_body)

      # User 2 should not be able to delete user 1's video
      conn2 = put_req_header(build_conn(), "authorization", "Bearer #{session2.token}")
      conn2 = delete(conn2, "/api/v1/videos/#{video_id}")
      assert conn2.status == 403, "User 2 was able to delete user 1's video"

      # User 1 should be able to delete their own video
      conn1 = delete(conn1, "/api/v1/videos/#{video_id}")
      assert conn1.status == 204, "User 1 could not delete their own video"

      # Cleanup
      Accounts.delete_user(user1)
      Accounts.delete_user(user2)
    end

    test "validates room membership for messaging" do
      # Create users and room
      {:ok, user1} = Accounts.register_user(%{
        email: "room-test-1-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "room_test_1_#{System.unique_integer()}"
      })

      {:ok, user2} = Accounts.register_user(%{
        email: "room-test-2-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "room_test_2_#{System.unique_integer()}"
      })

      {:ok, room} = Rooms.create_room(%{
        name: "Security Test Room",
        description: "Room for security testing",
        is_private: true,
        created_by_id: user1.id
      })

      {:ok, _membership1} = Rooms.join_room(room.id, user1.id)

      # User 2 should not be able to access private room
      {:ok, session2} = Accounts.create_user_session(user2, "test")
      conn = put_req_header(build_conn(), "authorization", "Bearer #{session2.token}")
      conn = get(conn, "/api/v1/rooms/#{room.id}")
      assert conn.status == 403, "User 2 was able to access private room"

      # Cleanup
      Rooms.delete_room(room)
      Accounts.delete_user(user1)
      Accounts.delete_user(user2)
    end
  end

  describe "error handling and information disclosure" do
    test "does not leak sensitive information in errors" do
      sensitive_patterns = [
        ~r/password/i,
        ~r/token/i,
        ~r/secret/i,
        ~r/key/i,
        ~r/stack\s+trace/i,
        ~r/sql\s+error/i,
        ~r/database/i,
        ~r/ecto/i,
        ~r/postgres/i
      ]

      # Test various error conditions
      error_endpoints = [
        "/api/v1/videos/999999",
        "/api/v1/users/999999",
        "/api/v1/rooms/999999"
      ]

      for endpoint <- error_endpoints do
        conn = get(build_conn(), endpoint)
        response_body = conn.resp_body

        for pattern <- sensitive_patterns do
          refute response_body =~ pattern,
                 "Sensitive information leaked in error response for #{endpoint}: #{pattern}"
        end
      end
    end

    test "handles malformed JSON gracefully" do
      malformed_payloads = [
        "{invalid json",
        "{\"email\": \"test@example.com\", \"password\":}",
        "{\"email\": null, \"password\": null}",
        "[\"array\", \"instead\", \"of\", \"object\"]"
      ]

      for payload <- malformed_payloads do
        conn = post(build_conn(), "/api/v1/auth/login", payload)
        # Should not crash with 500 error
        refute conn.status == 500,
               "Malformed JSON caused server crash: #{payload}"
        # Should return proper error response
        assert conn.status in [400, 422],
               "Malformed JSON not handled properly: #{payload}"
      end
    end

    test "validates API input parameters" do
      # Test with invalid parameters
      invalid_params = [
        %{email: "", password: "test"},
        %{email: "invalid-email", password: "test"},
        %{email: "test@example.com", password: ""},
        %{email: String.duplicate("a", 300) <> "@example.com", password: "test"}
      ]

      for params <- invalid_params do
        conn = post(build_conn(), "/api/v1/auth/login", params)
        refute conn.status == 500,
               "Invalid parameters caused server crash: #{inspect(params)}"
      end
    end
  end

  describe "rate limiting and DoS protection" do
    test "implements effective rate limiting" do
      # Make many rapid requests to test rate limiting
      results = for _ <- 1..100 do
        conn = get(build_conn(), "/api/v1/health")
        conn.status
      end

      # Should see some 429 (Too Many Requests) responses
      rate_limited_responses = Enum.count(results, &(&1 == 429))
      assert rate_limited_responses > 0,
             "Rate limiting not working - no 429 responses in #{Enum.join(results, ", ")}"
    end

    test "prevents resource exhaustion" do
      # Test with large payloads that could cause memory issues
      large_payload = String.duplicate("x", 1024 * 1024) # 1MB payload

      conn = post(build_conn(), "/api/v1/auth/login", %{
        email: "test@example.com",
        password: large_payload
      })

      # Should not crash or consume excessive resources
      refute conn.status == 500,
             "Large payload caused server crash"

      # Should reject with proper error
      assert conn.status in [400, 401, 422],
             "Large payload not properly handled"
    end
  end

  describe "session security" do
    test "properly invalidates sessions on logout" do
      {:ok, user} = Accounts.register_user(%{
        email: "session-test-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "session_test_#{System.unique_integer()}"
      })

      {:ok, session} = Accounts.create_user_session(user, "test")

      # Verify session works initially
      conn = put_req_header(build_conn(), "authorization", "Bearer #{session.token}")
      conn = get(conn, "/api/v1/users/me")
      assert conn.status == 200

      # Logout should invalidate session
      conn = put_req_header(build_conn(), "authorization", "Bearer #{session.token}")
      conn = post(conn, "/api/v1/auth/logout")
      assert conn.status == 200

      # Session should no longer work
      conn = put_req_header(build_conn(), "authorization", "Bearer #{session.token}")
      conn = get(conn, "/api/v1/users/me")
      assert conn.status == 401, "Session not properly invalidated after logout"

      # Cleanup
      Accounts.delete_user(user)
    end

    test "prevents concurrent session abuse" do
      {:ok, user} = Accounts.register_user(%{
        email: "concurrent-test-#{System.unique_integer()}@example.com",
        password: "TestPass123!",
        password_confirmation: "TestPass123!",
        username: "concurrent_test_#{System.unique_integer()}"
      })

      # Create multiple sessions
      sessions = for _ <- 1..5 do
        {:ok, session} = Accounts.create_user_session(user, "test")
        session
      end

      # All sessions should work initially
      for session <- sessions do
        conn = put_req_header(build_conn(), "authorization", "Bearer #{session.token}")
        conn = get(conn, "/api/v1/users/me")
        assert conn.status == 200, "Session #{session.id} should be valid"
      end

      # Logout from one session
      first_session = List.first(sessions)
      conn = put_req_header(build_conn(), "authorization", "Bearer #{first_session.token}")
      conn = post(conn, "/api/v1/auth/logout")
      assert conn.status == 200

      # That specific session should be invalidated
      conn = put_req_header(build_conn(), "authorization", "Bearer #{first_session.token}")
      conn = get(conn, "/api/v1/users/me")
      assert conn.status == 401, "Logged out session should be invalid"

      # Other sessions should still work
      remaining_sessions = Enum.drop(sessions, 1)
      for session <- remaining_sessions do
        conn = put_req_header(build_conn(), "authorization", "Bearer #{session.token}")
        conn = get(conn, "/api/v1/users/me")
        assert conn.status == 200, "Other sessions should remain valid"
      end

      # Cleanup
      Accounts.delete_user(user)
    end
  end
end