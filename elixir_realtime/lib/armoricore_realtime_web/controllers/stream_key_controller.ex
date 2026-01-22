# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp
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

defmodule ArmoricoreRealtimeWeb.StreamKeyController do
  @moduledoc """
  Controller for stream key operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.LiveStreaming

  @doc """
  List stream keys for current user (protected endpoint).
  GET /api/v1/stream-keys
  """
  def index(conn, params) do
    user_id = conn.assigns.current_user_id
    opts = parse_list_params(params)
    keys = LiveStreaming.list_stream_keys(user_id, opts)
    json(conn, %{
      data: Enum.map(keys, &serialize_stream_key/1),
      count: length(keys)
    })
  end

  @doc """
  Generate a new stream key (protected endpoint).
  POST /api/v1/stream-keys
  """
  def create(conn, %{"stream_key" => key_params}) do
    user_id = conn.assigns.current_user_id

    case LiveStreaming.generate_stream_key_for_user(user_id, key_params) do
      {:ok, key} ->
        conn
        |> put_status(:created)
        |> json(%{data: serialize_stream_key(key)})

      {:error, %Ecto.Changeset{} = changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Validation failed", errors: format_errors(changeset)})
    end
  end

  @doc """
  Revoke a stream key (protected endpoint - owner only).
  DELETE /api/v1/stream-keys/:id
  """
  def delete(conn, %{"id" => id}) do
    user_id = conn.assigns.current_user_id

    case LiveStreaming.revoke_stream_key(id) do
      {:ok, key} ->
        # SECURITY: Only key owner can revoke
        if key.user_id == user_id do
          conn
          |> put_status(:no_content)
          |> json(%{})
        else
          conn
          |> put_status(:forbidden)
          |> json(%{error: "You don't have permission to revoke this key"})
        end

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Stream key not found"})
    end
  end

  @doc """
  Validate a stream key (internal endpoint - used by RTMP server).
  POST /api/v1/stream-keys/validate
  """
  def validate(conn, %{"stream_key" => stream_key}) do
    case LiveStreaming.validate_stream_key(stream_key) do
      {:ok, key} ->
        json(conn, %{
          valid: true,
          user_id: key.user_id,
          key_id: key.id
        })

      {:error, :invalid_key} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{valid: false, error: "Invalid stream key"})

      {:error, :expired_key} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{valid: false, error: "Stream key has expired"})
    end
  end

  # Helper functions

  defp parse_list_params(params) do
    [
      is_active: parse_boolean(params["is_active"])
    ]
    |> Enum.filter(fn {_key, value} -> not is_nil(value) end)
  end

  defp parse_boolean(nil), do: nil
  defp parse_boolean("true"), do: true
  defp parse_boolean("false"), do: false
  defp parse_boolean(bool) when is_boolean(bool), do: bool
  defp parse_boolean(_), do: nil

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp serialize_stream_key(key) do
    %{
      id: key.id,
      name: key.name,
      stream_key: key.stream_key,
      is_active: key.is_active,
      last_used_at: key.last_used_at,
      expires_at: key.expires_at,
      created_at: key.inserted_at
    }
  end
end

