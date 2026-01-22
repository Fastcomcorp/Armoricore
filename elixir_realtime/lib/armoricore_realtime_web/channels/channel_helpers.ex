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

defmodule ArmoricoreRealtimeWeb.ChannelHelpers do
  @moduledoc """
  Helper functions for channels to interact with message bus.
  """

  require Logger

  # UUID module available for generating event IDs if needed

  @doc """
  Publishes a chat message event to the message bus.
  """
  def publish_chat_message(message) do
    event = %{
      event_type: "chat.message",
      event_id: message["id"] || UUID.uuid4(),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      source: "elixir-realtime",
      payload: message
    }

    publish_event("armoricore.chat_message", event)
  end

  @doc """
  Publishes a call event to the message bus.
  """
  def publish_call_event(call_event) do
    event_type = case call_event do
      %{state: "ringing"} -> "call.initiated"
      %{state: "connected"} -> "call.connected"
      %{reason: _} -> "call.ended"
      _ -> "call.event"
    end

    event = %{
      event_type: event_type,
      event_id: Map.get(call_event, :call_id) || UUID.uuid4(),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      source: "elixir-realtime",
      payload: call_event
    }

    publish_event("armoricore.#{event_type}", event)
  end

  @doc """
  Publishes a comment event to the message bus.
  """
  def publish_comment_event(comment) do
    event = %{
      event_type: "comment.created",
      event_id: comment["id"] || UUID.uuid4(),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      source: "elixir-realtime",
      payload: comment
    }

    publish_event("armoricore.comment_created", event)
  end

  # Private helper to publish events to NATS
  defp publish_event(topic, event) do
    case get_gnat_connection() do
      {:ok, gnat} ->
        case Jason.encode(event) do
          {:ok, json_body} ->
            case Gnat.pub(gnat, topic, json_body) do
              :ok ->
                Logger.info("Published event to #{topic}: #{inspect(event["event_id"])}")
                :ok

              {:error, reason} ->
                Logger.error("Failed to publish event to #{topic}: #{inspect(reason)}")
                {:error, reason}
            end

          {:error, reason} ->
            Logger.error("Failed to encode event: #{inspect(reason)}")
            {:error, :encode_error}
        end

      {:error, reason} ->
        Logger.warning("Gnat connection not available: #{inspect(reason)}")
        {:error, :no_connection}
    end
  end

  # Get Gnat connection from MessageBus GenServer
  defp get_gnat_connection do
    case GenServer.call(ArmoricoreRealtime.MessageBus, :get_gnat) do
      {:ok, gnat} -> {:ok, gnat}
      {:error, reason} -> {:error, reason}
    end
  end
end
