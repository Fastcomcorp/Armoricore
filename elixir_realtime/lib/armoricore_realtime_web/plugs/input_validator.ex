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

defmodule ArmoricoreRealtimeWeb.Plugs.InputValidator do
  @moduledoc """
  Input validation and sanitization plug.
  
  Validates and sanitizes user inputs to prevent injection attacks.
  """
  
  import Plug.Conn
  require Logger

  @behaviour Plug

  # Maximum field lengths
  @max_string_length 10_000
  @max_email_length 255
  @max_username_length 50

  def init(opts), do: opts

  def call(conn, _opts) do
    conn
    |> validate_params(conn.params)
  end

  defp validate_params(conn, params) when is_map(params) do
    case validate_map(params, []) do
      {:ok, sanitized_params} ->
        %{conn | params: sanitized_params}
      
      {:error, errors} ->
        Logger.warning("Input validation failed: #{inspect(errors)}")
        conn
        |> put_status(400)
        |> put_resp_content_type("application/json")
        |> send_resp(400, Jason.encode!(%{error: "Invalid input", details: errors}))
        |> halt()
    end
  end

  defp validate_params(conn, _), do: conn

  defp validate_map(params, errors) when is_map(params) do
    {sanitized, new_errors} = 
      Enum.reduce(params, {%{}, errors}, fn {key, value}, {acc, errs} ->
        case validate_value(key, value) do
          {:ok, sanitized_value} ->
            {Map.put(acc, key, sanitized_value), errs}
          
          {:error, field_errors} ->
            {acc, errs ++ field_errors}
        end
      end)
    
    if new_errors == [] do
      {:ok, sanitized}
    else
      {:error, new_errors}
    end
  end

  defp validate_map(value, _errors), do: {:ok, value}

  defp validate_value(key, value) when is_binary(value) do
    cond do
      # Email validation
      String.contains?(to_string(key), "email") ->
        validate_email(value)
      
      # Username validation
      String.contains?(to_string(key), "username") ->
        validate_username(value)
      
      # Password validation
      String.contains?(to_string(key), "password") ->
        validate_password(value)
      
      # General string validation
      true ->
        validate_string(key, value)
    end
  end

  defp validate_value(_key, value) when is_map(value) do
    validate_map(value, [])
  end

  defp validate_value(_key, value) when is_list(value) do
    # Validate list items
    validated = Enum.map(value, fn item ->
      case validate_value("list_item", item) do
        {:ok, sanitized} -> sanitized
        {:error, _} -> item # Keep original if validation fails (non-critical)
      end
    end)
    {:ok, validated}
  end

  defp validate_value(_key, value) do
    {:ok, value}
  end

  # SECURITY: Improved email validation with RFC 5322 compliance
  defp validate_email(email) do
    cond do
      byte_size(email) > @max_email_length ->
        {:error, ["email: exceeds maximum length"]}
      
      byte_size(email) == 0 ->
        {:error, ["email: cannot be empty"]}
      
      not String.contains?(email, "@") ->
        {:error, ["email: invalid format"]}
      
      # RFC 5322 basic validation (simplified but secure)
      # Allows: alphanumeric, dots, underscores, percent, plus, minus before @
      # Domain: alphanumeric, dots, hyphens, must have TLD
      not String.match?(email, ~r/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/) ->
        {:error, ["email: invalid format"]}
      
      # Check for dangerous characters that could be used for injection
      String.contains?(email, ["\n", "\r", "\0", "\t"]) ->
        {:error, ["email: contains invalid characters"]}
      
      # Prevent multiple @ symbols
      String.split(email, "@") |> length() != 2 ->
        {:error, ["email: invalid format"]}
      
      # Prevent leading/trailing dots in local or domain parts
      String.starts_with?(email, ".") or String.ends_with?(email, ".") ->
        {:error, ["email: invalid format"]}
      
      true ->
        # Sanitize email (remove potentially dangerous characters, normalize)
        sanitized = email
          |> String.trim()
          |> String.downcase()
          |> String.replace(~r/[<>\"']/, "")
        
        # Additional validation: check for consecutive dots
        if String.contains?(sanitized, "..") do
          {:error, ["email: invalid format"]}
        else
          {:ok, sanitized}
        end
    end
  end

  defp validate_username(username) do
    cond do
      byte_size(username) > @max_username_length ->
        {:error, ["username: exceeds maximum length"]}
      
      username == "" ->
        {:error, ["username: cannot be empty"]}
      
      not String.match?(username, ~r/^[a-zA-Z0-9_-]+$/) ->
        {:error, ["username: contains invalid characters"]}
      
      true ->
        {:ok, String.trim(username)}
    end
  end

  defp validate_password(password) do
    cond do
      byte_size(password) < 8 ->
        {:error, ["password: must be at least 8 characters"]}
      
      byte_size(password) > 128 ->
        {:error, ["password: exceeds maximum length"]}
      
      true ->
        # Don't sanitize passwords, just validate length
        {:ok, password}
    end
  end

  defp validate_string(key, value) do
    cond do
      byte_size(value) > @max_string_length ->
        {:error, ["#{key}: exceeds maximum length"]}
      
      true ->
        # Sanitize HTML and script tags
        sanitized = value
          |> String.replace(~r/<script[^>]*>.*?<\/script>/is, "")
          |> String.replace(~r/<[^>]+>/, "")
          |> String.trim()
        {:ok, sanitized}
    end
  end
end
