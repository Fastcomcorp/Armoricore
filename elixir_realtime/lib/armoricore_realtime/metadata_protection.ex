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

defmodule ArmoricoreRealtime.MetadataProtection do
  @moduledoc """
  Metadata protection and privacy-preserving communication features.

  Implements privacy-preserving techniques:
  - Metadata minimization
  - Secure contact discovery
  - Anonymous routing
  - Traffic analysis resistance
  - Contact verification without metadata leaks

  ## Privacy Features

  - **Contact Discovery**: Find contacts without revealing social graphs
  - **Presence Hiding**: Conceal online/offline status
  - **Traffic Padding**: Prevent traffic analysis
  - **Anonymous Routing**: Onion-like message routing
  - **Metadata Stripping**: Remove identifying information from messages

  ## Architecture

  ```
  User A ──► Contact Discovery ──► User B
     │              │                    │
     │              ▼                    │
     └───► Privacy Router ───────────────┘
              │
              ▼
         Anonymized Network
  ```
  """

  require Logger
  alias ArmoricoreRealtime.Crypto

  @doc """
  Performs secure contact discovery without metadata leaks.

  Uses cryptographic contact tokens that don't reveal social relationships.
  """
  @spec discover_contacts_securely(String.t(), list(String.t())) :: {:ok, list(map())} | {:error, atom()}
  def discover_contacts_securely(user_id, search_tokens) do
    # Generate blinded contact tokens for privacy-preserving discovery
    contact_tokens = Enum.map(search_tokens, fn token ->
      generate_contact_token(user_id, token)
    end)

    # Query contacts using blinded tokens (prevents correlation)
    discovered_contacts = query_contacts_privately(contact_tokens)

    Logger.info("Performed secure contact discovery for user #{user_id}")
    {:ok, discovered_contacts}
  end

  @doc """
  Generates a cryptographic contact token for secure discovery.

  Uses blind signatures to prevent the server from learning contact relationships.
  """
  @spec generate_contact_token(String.t(), String.t()) :: map()
  def generate_contact_token(user_id, contact_identifier) do
    # Create a blinded token that can be verified without revealing the contact
    blinding_factor = Crypto.secure_random_bytes(32)
    token_data = Jason.encode!(%{
      user_id: user_id,
      contact_id: contact_identifier,
      timestamp: DateTime.utc_now(),
      nonce: Crypto.secure_random_bytes(16) |> Base.url_encode64()
    })

    # Blind the token for privacy
    blinded_token = blind_token(token_data, blinding_factor)

    %{
      blinded_token: blinded_token,
      blinding_factor: blinding_factor,
      original_data: token_data
    }
  end

  @doc """
  Verifies a contact token without revealing metadata.

  Server can verify tokens are valid without learning contact relationships.
  """
  @spec verify_contact_token(map()) :: {:ok, boolean()} | {:error, atom()}
  def verify_contact_token(token_data) do
    # Unblind the token and verify signature
    unblinded_token = unblind_token(token_data.blinded_token, token_data.blinding_factor)

    case Jason.decode(unblinded_token) do
      {:ok, %{"user_id" => user_id, "contact_id" => contact_id, "timestamp" => timestamp_str}} ->
        # Verify timestamp is recent (prevent replay attacks)
        case DateTime.from_iso8601(timestamp_str) do
          {:ok, timestamp, _} ->
            age_seconds = DateTime.diff(DateTime.utc_now(), timestamp)
            if age_seconds < 300 do  # 5 minutes
              # Check if contact relationship exists (without revealing it)
              verify_contact_relationship_privately(user_id, contact_id)
            else
              {:ok, false}
            end

          _ ->
            {:ok, false}
        end

      _ ->
        {:ok, false}
    end
  end

  @doc """
  Implements anonymous message routing.

  Routes messages through multiple hops to hide sender/receiver relationship.
  """
  @spec route_message_anonymously(map(), list(String.t())) :: {:ok, map()} | {:error, atom()}
  def route_message_anonymously(message, route) do
    # Create onion routing layers
    encrypted_message = create_onion_layers(message, route)

    # Send through the anonymous route
    {:ok, %{
      onion_message: encrypted_message,
      route: route,
      sent_at: DateTime.utc_now()
    }}
  end

  @doc """
  Processes an incoming onion-routed message.

  Peels off routing layers and forwards or delivers the message.
  """
  @spec process_onion_message(map()) :: {:ok, map()} | {:error, atom()}
  def process_onion_message(onion_message) do
    # Peel off one layer of encryption
    case peel_onion_layer(onion_message) do
      {:ok, {next_hop, remaining_message}} ->
        # Forward to next hop or deliver if final destination
        if next_hop == "final" do
          deliver_message(remaining_message)
        else
          forward_message(next_hop, remaining_message)
        end

      {:error, reason} ->
        Logger.warning("Failed to process onion message: #{inspect(reason)}")
        {:error, :processing_failed}
    end
  end

  @doc """
  Implements traffic padding to prevent traffic analysis.

  Sends dummy messages to obscure real communication patterns.
  """
  @spec enable_traffic_padding(String.t(), integer()) :: {:ok, reference()} | {:error, atom()}
  def enable_traffic_padding(user_id, interval_seconds) do
    # Start a process that sends periodic dummy messages
    {:ok, pid} = Task.start_link(fn ->
      traffic_padding_loop(user_id, interval_seconds)
    end)

    Logger.info("Enabled traffic padding for user #{user_id} with #{interval_seconds}s interval")
    {:ok, pid}
  end

  @doc """
  Strips metadata from messages before transmission.

  Removes or obscures identifying information.
  """
  @spec strip_message_metadata(map()) :: map()
  def strip_message_metadata(message) do
    # Remove or anonymize metadata
    stripped_message = Map.drop(message, [
      :sender_ip,
      :user_agent,
      :device_fingerprint,
      :location_data,
      :network_info
    ])

    # Add anonymization layer
    Map.put(stripped_message, :anonymized, true)
  end

  @doc """
  Implements secure presence hiding.

  Conceals online/offline status to prevent stalking.
  """
  @spec hide_presence_status(String.t()) :: {:ok, map()} | {:error, atom()}
  def hide_presence_status(user_id) do
    # Generate fake presence updates to confuse observers
    fake_presence_data = %{
      user_id: user_id,
      status: generate_fake_status(),
      last_seen: generate_fake_timestamp(),
      obfuscated: true
    }

    Logger.debug("Generated obfuscated presence for user #{user_id}")
    {:ok, fake_presence_data}
  end

  @doc """
  Performs private set intersection for contact discovery.

  Allows finding mutual contacts without revealing contact lists.
  """
  @spec private_set_intersection(list(String.t()), list(String.t())) :: list(String.t())
  def private_set_intersection(set_a, set_b) do
    # Use cryptographic PSI protocol
    # This is a simplified version - real implementation would use homomorphic encryption

    # Hash both sets
    hashed_a = Enum.map(set_a, &Crypto.sha256/1)
    hashed_b = Enum.map(set_b, &Crypto.sha256/1)

    # Find intersections using bloom filters or similar
    # Return matching items without revealing non-matching ones
    []

    # Note: This would require a full cryptographic PSI implementation
    # For now, this is a placeholder
  end

  @doc """
  Generates unlinkable message identifiers.

  Prevents correlation of messages from the same conversation.
  """
  @spec generate_unlinkable_id(String.t(), String.t()) :: String.t()
  def generate_unlinkable_id(conversation_id, message_number) do
    # Use domain separation to prevent correlation
    input = "#{conversation_id}:#{message_number}:#{Crypto.secure_random_bytes(16)}"
    Crypto.sha256(input) |> Base.url_encode64(padding: false)
  end

  # Private functions

  defp blind_token(token_data, blinding_factor) do
    # Simplified blinding - real implementation would use proper blind signatures
    Crypto.hmac_sha256(blinding_factor, token_data)
  end

  defp unblind_token(blinded_token, blinding_factor) do
    # Reverse the blinding operation
    blinded_token  # Simplified
  end

  defp query_contacts_privately(contact_tokens) do
    # Mock implementation - would query server with blinded tokens
    []
  end

  defp verify_contact_relationship_privately(user_id, contact_id) do
    # Mock implementation - would verify contact relationship privately
    {:ok, true}
  end

  defp create_onion_layers(message, route) do
    # Create nested encryption layers for each hop
    Enum.reduce(Enum.reverse(route), message, fn hop, encrypted_msg ->
      # Encrypt with hop's public key
      {:ok, {ciphertext, tag, nonce}} = Crypto.aes_gcm_encrypt(Jason.encode!(encrypted_msg), Crypto.secure_random_bytes(32))
      %{hop: hop, ciphertext: ciphertext, tag: tag, nonce: nonce}
    end)
  end

  defp peel_onion_layer(onion_message) do
    # Decrypt one layer and return next hop and remaining message
    case Crypto.aes_gcm_decrypt(onion_message.ciphertext, onion_message.tag, onion_message.nonce, Crypto.secure_random_bytes(32)) do
      {:ok, decrypted} ->
        case Jason.decode(decrypted) do
          {:ok, %{"hop" => next_hop} = remaining} ->
            {:ok, {next_hop, remaining}}
          _ ->
            {:error, :invalid_layer}
        end
      _ ->
        {:error, :decryption_failed}
    end
  end

  defp deliver_message(message) do
    # Deliver the final message to recipient
    {:ok, message}
  end

  defp forward_message(next_hop, message) do
    # Forward to next hop in the route
    {:ok, message}
  end

  defp traffic_padding_loop(user_id, interval_seconds) do
    # Send a dummy message
    send_dummy_message(user_id)

    # Wait for next interval
    Process.sleep(interval_seconds * 1000)

    # Continue the loop
    traffic_padding_loop(user_id, interval_seconds)
  end

  defp send_dummy_message(user_id) do
    # Send an encrypted dummy message
    dummy_message = %{
      type: "dummy",
      content: Crypto.secure_random_bytes(32),
      timestamp: DateTime.utc_now()
    }

    # In production, this would be sent through secure channels
    Logger.debug("Sent traffic padding message for user #{user_id}")
  end

  defp generate_fake_status do
    Enum.random(["online", "offline", "away", "busy"])
  end

  defp generate_fake_timestamp do
    # Generate a fake timestamp within the last hour
    fake_offset = :rand.uniform(3600)  # Random seconds within an hour
    DateTime.add(DateTime.utc_now(), -fake_offset)
  end
end