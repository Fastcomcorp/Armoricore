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

defmodule ArmoricoreRealtimeWeb.UserSocketTest do
  use ExUnit.Case, async: true
  use Phoenix.ChannelTest

  @endpoint ArmoricoreRealtimeWeb.Endpoint

  alias ArmoricoreRealtimeWeb.UserSocket
  alias ArmoricoreRealtime.JWT

  @secret "test-secret-key"
  @valid_user_id "123e4567-e89b-12d3-a456-426614174000"

  setup do
    Application.put_env(:armoricore_realtime, :jwt, secret: @secret)
    
    on_exit(fn ->
      Application.delete_env(:armoricore_realtime, :jwt)
    end)

    :ok
  end

  describe "connect/3" do
    test "accepts connection with valid JWT token" do
      signer = Joken.Signer.create("HS256", @secret)
      
      claims = %{
        "user_id" => @valid_user_id,
        "exp" => System.system_time(:second) + 3600
      }
      
      {:ok, token, _} = Joken.encode_and_sign(claims, signer)
      
      assert {:ok, socket} = connect(UserSocket, %{"token" => token})
      assert socket.assigns.user_id == @valid_user_id
    end

    test "rejects connection with invalid token" do
      assert {:error, %{reason: _}} = connect(UserSocket, %{"token" => "invalid.token"})
    end

    test "rejects connection with expired token" do
      signer = Joken.Signer.create("HS256", @secret)
      
      claims = %{
        "user_id" => @valid_user_id,
        "exp" => System.system_time(:second) - 3600
      }
      
      {:ok, token, _} = Joken.encode_and_sign(claims, signer)
      
      assert {:error, %{reason: :token_expired}} = connect(UserSocket, %{"token" => token})
    end

    test "rejects connection without token" do
      assert {:error, %{reason: "missing_token"}} = connect(UserSocket, %{})
    end

    test "rejects connection with token missing user_id" do
      signer = Joken.Signer.create("HS256", @secret)
      
      claims = %{
        "exp" => System.system_time(:second) + 3600
      }
      
      {:ok, token, _} = Joken.encode_and_sign(claims, signer)
      
      assert {:error, %{reason: "invalid_token"}} = connect(UserSocket, %{"token" => token})
    end
  end

  describe "id/1" do
    test "generates socket ID from user_id" do
      signer = Joken.Signer.create("HS256", @secret)
      
      claims = %{
        "user_id" => @valid_user_id,
        "exp" => System.system_time(:second) + 3600
      }
      
      {:ok, token, _} = Joken.encode_and_sign(claims, signer)
      
      {:ok, socket} = connect(UserSocket, %{"token" => token})
      
      assert UserSocket.id(socket) == "user_socket:#{@valid_user_id}"
    end
  end
end

