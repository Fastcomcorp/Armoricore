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

defmodule ArmoricoreRealtime.KeyManager do
  @moduledoc """
  Key Management System for Armoricore (Elixir)
  
  Provides secure key storage, retrieval, and rotation capabilities.
  Supports local encrypted storage with extensibility for future KMS/HSM integration.
  """

  use GenServer
  require Logger

  @typedoc """
  Key identifier
  """
  @type key_id :: String.t()

  @typedoc """
  Key type classification
  """
  @type key_type :: :jwt_secret | :api_key | :encryption_key | :object_storage_key | :object_storage_secret | :apns_key | :secret

  @typedoc """
  Key metadata
  """
  @type key_metadata :: %{
    id: key_id(),
    key_type: key_type(),
    current_version: integer(),
    created_at: integer(),
    updated_at: integer(),
    metadata: map()
  }

  ## Client API

  def start_link(opts \\ []) do
    storage_path = Keyword.get(opts, :storage_path, "priv/keys")
    master_key = Keyword.get(opts, :master_key)
    
    GenServer.start_link(__MODULE__, {storage_path, master_key}, name: __MODULE__)
  end

  @doc """
  Store a JWT secret
  """
  @spec store_jwt_secret(key_id(), String.t()) :: :ok | {:error, term()}
  def store_jwt_secret(key_id, secret) do
    GenServer.call(__MODULE__, {:store_key, key_id, :jwt_secret, secret, nil})
  end

  @doc """
  Get JWT secret
  """
  @spec get_jwt_secret(key_id()) :: {:ok, String.t()} | {:error, term()}
  def get_jwt_secret(key_id) do
    GenServer.call(__MODULE__, {:get_key, key_id})
  end

  @doc """
  Store an API key
  """
  @spec store_api_key(key_id(), String.t(), map() | nil) :: :ok | {:error, term()}
  def store_api_key(key_id, api_key, metadata \\ nil) do
    GenServer.call(__MODULE__, {:store_key, key_id, :api_key, api_key, metadata})
  end

  @doc """
  Get API key
  """
  @spec get_api_key(key_id()) :: {:ok, String.t()} | {:error, term()}
  def get_api_key(key_id) do
    GenServer.call(__MODULE__, {:get_key, key_id})
  end

  @doc """
  Rotate a key
  """
  @spec rotate_key(key_id(), String.t()) :: :ok | {:error, term()}
  def rotate_key(key_id, new_value) do
    GenServer.call(__MODULE__, {:rotate_key, key_id, new_value})
  end

  @doc """
  Get key metadata
  """
  @spec get_metadata(key_id()) :: {:ok, key_metadata()} | {:error, term()}
  def get_metadata(key_id) do
    GenServer.call(__MODULE__, {:get_metadata, key_id})
  end

  @doc """
  List all keys
  """
  @spec list_keys() :: [key_id()]
  def list_keys() do
    GenServer.call(__MODULE__, :list_keys)
  end

  @doc """
  Check if key exists
  """
  @spec key_exists?(key_id()) :: boolean()
  def key_exists?(key_id) do
    GenServer.call(__MODULE__, {:key_exists, key_id})
  end

  @doc """
  Delete a key
  """
  @spec delete_key(key_id()) :: :ok | {:error, term()}
  def delete_key(key_id) do
    GenServer.call(__MODULE__, {:delete_key, key_id})
  end

  ## GenServer Callbacks

  @impl true
  def init({storage_path, master_key}) do
    # Create storage directory
    File.mkdir_p!(storage_path)

    # Derive master key
    master_key = derive_master_key(master_key)

    # Load existing metadata
    metadata_cache = load_metadata(storage_path)

    Logger.info("KeyManager started with #{map_size(metadata_cache)} keys")

    {:ok, %{
      storage_path: storage_path,
      master_key: master_key,
      metadata_cache: metadata_cache
    }}
  end

  @impl true
  def handle_call({:store_key, key_id, key_type, key_value, metadata}, _from, state) do
    case Map.get(state.metadata_cache, key_id) do
      nil ->
        # Encrypt and store key
        encrypted = encrypt_key(key_value, state.master_key)
        key_path = key_file_path(state.storage_path, key_id)
        File.write!(key_path, encrypted)

        # Create and save metadata
        metadata_map = create_metadata(key_id, key_type, metadata)
        save_metadata(state.storage_path, key_id, metadata_map)

        # Update cache
        new_cache = Map.put(state.metadata_cache, key_id, metadata_map)

        Logger.info("Stored key: #{key_id} (type: #{key_type})")

        {:reply, :ok, %{state | metadata_cache: new_cache}}

      _existing ->
        {:reply, {:error, :already_exists}, state}
    end
  end

  @impl true
  def handle_call({:get_key, key_id}, _from, state) do
    case Map.get(state.metadata_cache, key_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      _metadata ->
        # Load and decrypt key
        key_path = key_file_path(state.storage_path, key_id)
        encrypted = File.read!(key_path)
        decrypted = decrypt_key(encrypted, state.master_key)

        {:reply, {:ok, decrypted}, state}
    end
  end

  @impl true
  def handle_call({:rotate_key, key_id, new_value}, _from, state) do
    case Map.get(state.metadata_cache, key_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      metadata ->
        # Encrypt and store new key
        encrypted = encrypt_key(new_value, state.master_key)
        key_path = key_file_path(state.storage_path, key_id)
        File.write!(key_path, encrypted)

        # Update metadata with new version
        new_version = metadata.current_version + 1
        updated_metadata = %{
          metadata
          | current_version: new_version,
            updated_at: System.system_time(:second)
        }

        save_metadata(state.storage_path, key_id, updated_metadata)
        new_cache = Map.put(state.metadata_cache, key_id, updated_metadata)

        Logger.info("Rotated key: #{key_id} to version #{new_version}")

        {:reply, :ok, %{state | metadata_cache: new_cache}}
    end
  end

  @impl true
  def handle_call({:get_metadata, key_id}, _from, state) do
    case Map.get(state.metadata_cache, key_id) do
      nil ->
        {:reply, {:error, :not_found}, state}

      metadata ->
        {:reply, {:ok, metadata}, state}
    end
  end

  @impl true
  def handle_call(:list_keys, _from, state) do
    keys = Map.keys(state.metadata_cache)
    {:reply, keys, state}
  end

  @impl true
  def handle_call({:key_exists, key_id}, _from, state) do
    exists = Map.has_key?(state.metadata_cache, key_id)
    {:reply, exists, state}
  end

  @impl true
  def handle_call({:delete_key, key_id}, _from, state) do
    # Remove files
    key_path = key_file_path(state.storage_path, key_id)
    meta_path = metadata_file_path(state.storage_path, key_id)

    File.rm(key_path)
    File.rm(meta_path)

    # Remove from cache
    new_cache = Map.delete(state.metadata_cache, key_id)

    Logger.info("Deleted key: #{key_id}")

    {:reply, :ok, %{state | metadata_cache: new_cache}}
  end

  ## Private Functions

  defp derive_master_key(nil) do
    # Try to get from environment
    case System.get_env("ARMORICORE_MASTER_KEY") do
      nil ->
        Logger.warning("No ARMORICORE_MASTER_KEY found, generating a new one. This should be set in production!")
        :crypto.strong_rand_bytes(32)

      key_str ->
        # Derive from string using SHA256
        :crypto.hash(:sha256, key_str)
    end
  end

  defp derive_master_key(key) when is_binary(key) do
    if byte_size(key) == 32 do
      key
    else
      :crypto.hash(:sha256, key)
    end
  end

  defp derive_master_key(key) when is_list(key) do
    derive_master_key(:erlang.list_to_binary(key))
  end

  defp encrypt_key(plaintext, master_key) do
    # Use AES-256-GCM (simplified - in production use proper crypto library)
    iv = :crypto.strong_rand_bytes(12)
    {ciphertext, tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, master_key, iv, plaintext, "", true)
    
    # Prepend IV and tag
    iv <> tag <> ciphertext
  end

  defp decrypt_key(encrypted, master_key) do
    # Extract IV, tag, and ciphertext
    <<iv::binary-12, tag::binary-16, ciphertext::binary>> = encrypted
    
    # Decrypt
    {plaintext, _tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, master_key, iv, ciphertext, tag, false)
    
    plaintext
  end

  defp key_file_path(storage_path, key_id) do
    sanitized = sanitize_key_id(key_id)
    Path.join(storage_path, "#{sanitized}.key")
  end

  defp metadata_file_path(storage_path, key_id) do
    sanitized = sanitize_key_id(key_id)
    Path.join(storage_path, "#{sanitized}.meta")
  end

  defp sanitize_key_id(key_id) do
    key_id
    |> String.replace("/", "_")
     |> String.replace("\\", "_")
  end

  defp create_metadata(key_id, key_type, metadata) do
    now = System.system_time(:second)
    %{
      id: key_id,
      key_type: key_type,
      current_version: 1,
      created_at: now,
      updated_at: now,
      metadata: metadata || %{}
    }
  end

  defp save_metadata(storage_path, key_id, metadata) do
    meta_path = metadata_file_path(storage_path, key_id)
    json = Jason.encode!(metadata, pretty: true)
    File.write!(meta_path, json)
  end

  defp load_metadata(storage_path) do
    case File.ls(storage_path) do
      {:ok, files} ->
        files
        |> Enum.filter(&String.ends_with?(&1, ".meta"))
        |> Enum.reduce(%{}, fn file, acc ->
          key_id = String.replace_suffix(file, ".meta", "")
          meta_path = Path.join(storage_path, file)
          
          case File.read(meta_path) do
            {:ok, content} ->
              case Jason.decode(content) do
                {:ok, metadata} ->
                  Map.put(acc, key_id, metadata)
                
                {:error, _} ->
                  Logger.warning("Failed to parse metadata for #{key_id}")
                  acc
              end
            
            {:error, _} ->
              Logger.warning("Failed to read metadata for #{key_id}")
              acc
          end
        end)

      {:error, _} ->
        %{}
    end
  end
end
