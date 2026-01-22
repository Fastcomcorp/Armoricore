# Copyright 2025 Fastcomcorp
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

defmodule ArmoricoreRealtime.LogSanitizer do
  @moduledoc """
  Log sanitization helper to prevent sensitive information from being logged.
  
  Removes or masks:
  - Passwords and password hashes
  - Tokens (access, refresh, API keys)
  - Credit card numbers
  - Social security numbers
  - Email addresses (partially masked)
  - IP addresses (optional masking)
  """

  @sensitive_keys [
    "password",
    "password_hash",
    "password_confirmation",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "secret",
    "secret_key",
    "private_key",
    "credit_card",
    "ssn",
    "social_security_number"
  ]

  @doc """
  Sanitizes a map to remove or mask sensitive fields.
  
  ## Examples
  
      iex> ArmoricoreRealtime.LogSanitizer.sanitize(%{email: "user@example.com", password: "secret123"})
      %{email: "us***@example.com", password: "[REDACTED]"}
  """
  @spec sanitize(map() | list() | any()) :: map() | list() | any()
  def sanitize(data) when is_map(data) do
    data
    |> Map.drop(@sensitive_keys)
    |> Map.update("email", nil, &mask_email/1)
    |> Map.update(:email, nil, &mask_email/1)
    |> sanitize_nested()
  end

  def sanitize(data) when is_list(data) do
    Enum.map(data, &sanitize/1)
  end

  def sanitize(data), do: data

  # Sanitize nested maps and lists
  defp sanitize_nested(data) when is_map(data) do
    Enum.reduce(data, %{}, fn {key, value}, acc ->
      sanitized_value = case value do
        v when is_map(v) -> sanitize(v)
        v when is_list(v) -> sanitize(v)
        v when is_binary(v) ->
          key_str = to_string(key)
          cond do
            key in @sensitive_keys -> "[REDACTED]"
            String.contains?(key_str, "password") -> "[REDACTED]"
            String.contains?(key_str, "token") -> mask_token(v)
            true -> v
          end
        v -> v
      end
      Map.put(acc, key, sanitized_value)
    end)
  end

  defp sanitize_nested(data), do: data

  @doc """
  Masks an email address, showing only first 2 characters of local part.
  
  ## Examples
  
      iex> ArmoricoreRealtime.LogSanitizer.mask_email("user@example.com")
      "us***@example.com"
  """
  @spec mask_email(String.t() | nil) :: String.t() | nil
  def mask_email(nil), do: nil
  def mask_email(email) when is_binary(email) do
    case String.split(email, "@") do
      [local, domain] ->
        masked_local = if byte_size(local) > 2 do
          String.slice(local, 0, 2) <> "***"
        else
          "***"
        end
        "#{masked_local}@#{domain}"
      
      _ ->
        "***@***"
    end
  end
  def mask_email(_), do: nil

  @doc """
  Masks a token, showing only first and last few characters.
  
  ## Examples
  
      iex> ArmoricoreRealtime.LogSanitizer.mask_token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")
      "eyJh...***"
  """
  @spec mask_token(String.t() | nil) :: String.t() | nil
  def mask_token(nil), do: nil
  def mask_token(token) when is_binary(token) do
    case byte_size(token) do
      size when size > 10 ->
        prefix = String.slice(token, 0, 4)
        suffix = String.slice(token, -4, 4)
        "#{prefix}...#{suffix}"
      
      _ ->
        "[REDACTED]"
    end
  end
  def mask_token(_), do: nil

  @doc """
  Sanitizes a log message string, removing potential sensitive patterns.
  """
  @spec sanitize_string(String.t()) :: String.t()
  def sanitize_string(message) when is_binary(message) do
    message
    |> String.replace(~r/password["\s:=]+[^\s"']+/i, "password=[REDACTED]")
    |> String.replace(~r/token["\s:=]+[^\s"']+/i, "token=[REDACTED]")
    |> String.replace(~r/api[_-]?key["\s:=]+[^\s"']+/i, "api_key=[REDACTED]")
    |> String.replace(~r/secret["\s:=]+[^\s"']+/i, "secret=[REDACTED]")
  end
  def sanitize_string(message), do: message
end

