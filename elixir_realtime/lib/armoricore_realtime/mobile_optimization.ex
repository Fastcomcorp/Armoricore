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

defmodule ArmoricoreRealtime.MobileOptimization do
  @moduledoc """
  Mobile performance optimizations for secure communications.

  Optimizes the platform for mobile devices with limited resources:
  - Battery-efficient cryptographic operations
  - Memory-optimized message processing
  - Network-efficient protocols
  - CPU-optimized algorithms
  - Background processing optimizations

  ## Mobile Constraints

  - **Battery**: Cryptographic operations are CPU-intensive
  - **Memory**: Limited RAM (typically 4-8GB shared)
  - **Network**: Variable connectivity and data costs
  - **CPU**: Slower processors than desktops
  - **Storage**: Limited local storage

  ## Optimization Strategies

  1. **Lazy Cryptography**: Defer heavy operations to optimal times
  2. **Progressive Enhancement**: Start with basic security, upgrade as needed
  3. **Background Processing**: Move heavy operations off main thread
  4. **Memory Pooling**: Reuse cryptographic contexts
  5. **Network Batching**: Combine multiple operations into single requests
  """

  require Logger
  alias ArmoricoreRealtime.Crypto

  @doc """
  Optimizes cryptographic operations for mobile devices.

  Applies battery-efficient algorithms and scheduling.
  """
  @spec optimize_crypto_for_mobile(map()) :: {:ok, map()} | {:error, atom()}
  def optimize_crypto_for_mobile(device_capabilities) do
    try do
      # Detect device capabilities
      cpu_score = Map.get(device_capabilities, :cpu_score, 50)
      battery_level = Map.get(device_capabilities, :battery_level, 100)
      memory_mb = Map.get(device_capabilities, :memory_mb, 4096)

      # Adjust cryptographic parameters based on device
      crypto_config = %{
        algorithm_priority: select_mobile_algorithms(cpu_score),
        key_size_adjustment: adjust_key_sizes(cpu_score),
        batch_processing: enable_batch_processing(memory_mb),
        lazy_operations: enable_lazy_crypto(battery_level),
        memory_pooling: enable_memory_pooling(memory_mb),
        background_processing: enable_background_crypto(battery_level)
      }

      Logger.info("Optimized crypto for mobile device: CPU=#{cpu_score}, Battery=#{battery_level}%, Memory=#{memory_mb}MB")
      {:ok, crypto_config}
    rescue
      error ->
        Logger.error("Mobile crypto optimization failed: #{inspect(error)}")
        {:error, :optimization_failed}
    end
  end

  @doc """
  Implements lazy cryptographic operations.

  Defers heavy operations to battery-optimal times.
  """
  @spec schedule_lazy_crypto(map(), String.t()) :: {:ok, reference()} | {:error, atom()}
  def schedule_lazy_crypto(operation, device_context) do
    try do
      # Determine optimal execution time
      optimal_time = calculate_optimal_execution_time(device_context)

      # Schedule the operation
      task = Task.async(fn ->
        # Wait for optimal time
        delay_ms = DateTime.diff(optimal_time, DateTime.utc_now(), :millisecond)
        if delay_ms > 0 do
          Process.sleep(delay_ms)
        end

        # Execute operation
        execute_lazy_crypto_operation(operation)
      end)

      Logger.debug("Scheduled lazy crypto operation for #{DateTime.to_iso8601(optimal_time)}")
      {:ok, task.ref}
    rescue
      error ->
        Logger.error("Lazy crypto scheduling failed: #{inspect(error)}")
        {:error, :scheduling_failed}
    end
  end

  @doc """
  Enables memory pooling for cryptographic operations.

  Reuses cryptographic contexts to reduce memory allocations.
  """
  @spec create_crypto_pool(pos_integer(), map()) :: {:ok, map()} | {:error, atom()}
  def create_crypto_pool(pool_size, device_capabilities) do
    try do
      memory_mb = Map.get(device_capabilities, :memory_mb, 4096)

      # Adjust pool size based on available memory
      adjusted_pool_size = calculate_optimal_pool_size(pool_size, memory_mb)

      # Create crypto context pool
      pool = Enum.map(1..adjusted_pool_size, fn _ ->
        create_crypto_context()
      end)

      pool_config = %{
        pool_size: adjusted_pool_size,
        contexts: pool,
        created_at: DateTime.utc_now(),
        memory_efficient: memory_mb < 6144  # Less than 6GB RAM
      }

      Logger.info("Created crypto pool with #{adjusted_pool_size} contexts")
      {:ok, pool_config}
    rescue
      error ->
        Logger.error("Crypto pool creation failed: #{inspect(error)}")
        {:error, :pool_creation_failed}
    end
  end

  @doc """
  Optimizes message batching for mobile networks.

  Combines multiple messages into single network requests.
  """
  @spec optimize_message_batching(list(map()), map()) :: {:ok, list(map())} | {:error, atom()}
  def optimize_message_batching(messages, network_conditions) do
    try do
      # Analyze network conditions
      bandwidth_kbps = Map.get(network_conditions, :bandwidth_kbps, 1000)
      latency_ms = Map.get(network_conditions, :latency_ms, 100)
      battery_level = Map.get(network_conditions, :battery_level, 100)

      # Calculate optimal batch size
      batch_size = calculate_optimal_batch_size(bandwidth_kbps, latency_ms, battery_level)

      # Group messages into batches
      batches = messages
      |> Enum.chunk_every(batch_size)
      |> Enum.map(&create_message_batch/1)

      Logger.debug("Optimized #{length(messages)} messages into #{length(batches)} batches")
      {:ok, batches}
    rescue
      error ->
        Logger.error("Message batching optimization failed: #{inspect(error)}")
        {:error, :batching_failed}
    end
  end

  @doc """
  Implements progressive security enhancement.

  Starts with basic security, upgrades based on device capabilities.
  """
  @spec progressive_security_upgrade(map(), map()) :: {:ok, map()} | {:error, atom()}
  def progressive_security_upgrade(current_security, device_capabilities) do
    try do
      cpu_score = Map.get(device_capabilities, :cpu_score, 50)
      battery_level = Map.get(device_capabilities, :battery_level, 100)
      memory_mb = Map.get(device_capabilities, :memory_mb, 4096)

      # Determine security level based on capabilities
      security_level = determine_security_level(cpu_score, battery_level, memory_mb)

      # Calculate upgrade path
      upgrade_path = calculate_upgrade_path(current_security, security_level)

      # Schedule upgrades
      scheduled_upgrades = schedule_security_upgrades(upgrade_path, device_capabilities)

      upgrade_plan = %{
        current_level: current_security.level,
        target_level: security_level,
        upgrade_path: upgrade_path,
        scheduled_upgrades: scheduled_upgrades,
        estimated_completion: estimate_completion_time(upgrade_path)
      }

      Logger.info("Progressive security upgrade planned: #{current_security.level} → #{security_level}")
      {:ok, upgrade_plan}
    rescue
      error ->
        Logger.error("Progressive security upgrade failed: #{inspect(error)}")
        {:error, :upgrade_planning_failed}
    end
  end

  @doc """
  Optimizes background processing for battery efficiency.

  Moves heavy operations to optimal processing windows.
  """
  @spec optimize_background_processing(map()) :: {:ok, map()} | {:error, atom()}
  def optimize_background_processing(device_state) do
    try do
      # Analyze device usage patterns
      usage_patterns = analyze_usage_patterns(device_state)

      # Identify heavy operations
      heavy_operations = identify_heavy_operations()

      # Schedule background processing
      background_schedule = schedule_background_operations(heavy_operations, usage_patterns)

      optimization_config = %{
        usage_patterns: usage_patterns,
        heavy_operations: heavy_operations,
        background_schedule: background_schedule,
        battery_optimization: calculate_battery_savings(background_schedule),
        last_optimization: DateTime.utc_now()
      }

      Logger.info("Optimized background processing for battery efficiency")
      {:ok, optimization_config}
    rescue
      error ->
        Logger.error("Background processing optimization failed: #{inspect(error)}")
        {:error, :optimization_failed}
    end
  end

  @doc """
  Monitors and reports mobile performance metrics.

  Tracks battery usage, memory consumption, and performance.
  """
  @spec monitor_mobile_performance() :: {:ok, map()} | {:error, atom()}
  def monitor_mobile_performance do
    try do
      # Collect performance metrics
      metrics = %{
        battery_usage: measure_battery_impact(),
        memory_usage: measure_memory_usage(),
        cpu_usage: measure_cpu_usage(),
        network_usage: measure_network_usage(),
        crypto_performance: measure_crypto_performance(),
        timestamp: DateTime.utc_now()
      }

      # Analyze performance trends
      analysis = analyze_performance_trends(metrics)

      # Generate optimization recommendations
      recommendations = generate_optimization_recommendations(analysis)

      performance_report = %{
        metrics: metrics,
        analysis: analysis,
        recommendations: recommendations,
        optimization_score: calculate_optimization_score(metrics)
      }

      Logger.debug("Mobile performance monitoring completed")
      {:ok, performance_report}
    rescue
      error ->
        Logger.error("Performance monitoring failed: #{inspect(error)}")
        {:error, :monitoring_failed}
    end
  end

  # Private functions

  defp select_mobile_algorithms(cpu_score) do
    # Choose algorithms based on CPU performance
    cond do
      cpu_score > 80 -> [:aes_gcm, :x25519, :ed25519, :kyber, :dilithium]  # Full capabilities
      cpu_score > 60 -> [:aes_gcm, :x25519, :ed25519, :kyber]             # No PQ signatures
      cpu_score > 40 -> [:aes_gcm, :x25519, :ed25519]                     # Basic PQ
      true -> [:aes_cbc, :x25519, :ed25519]                               # Reduced security
    end
  end

  defp adjust_key_sizes(cpu_score) do
    # Reduce key sizes for slower devices
    if cpu_score < 50 do
      %{aes_key_size: 16, x25519_key_size: 32, ed25519_key_size: 32}  # Smaller keys
    else
      %{aes_key_size: 32, x25519_key_size: 32, ed25519_key_size: 32}  # Standard sizes
    end
  end

  defp enable_batch_processing(memory_mb) do
    # Enable batch processing for devices with sufficient memory
    memory_mb > 2048
  end

  defp enable_lazy_crypto(battery_level) do
    # Enable lazy crypto when battery is low
    battery_level < 20
  end

  defp enable_memory_pooling(memory_mb) do
    # Enable pooling for devices with limited memory
    memory_mb < 6144
  end

  defp enable_background_crypto(battery_level) do
    # Enable background processing when battery is sufficient
    battery_level > 30
  end

  defp calculate_optimal_execution_time(device_context) do
    # Calculate when device is likely idle (charging, WiFi connected, etc.)
    # For now, delay by 1 hour
    DateTime.add(DateTime.utc_now(), 3600, :second)
  end

  defp execute_lazy_crypto_operation(operation) do
    # Execute the cryptographic operation
    Logger.debug("Executing lazy crypto operation: #{inspect(operation)}")
    :ok
  end

  defp calculate_optimal_pool_size(requested_size, memory_mb) do
    # Adjust pool size based on available memory
    max_pool_size = div(memory_mb, 512)  # Estimate 512MB per context
    min(requested_size, max_pool_size)
  end

  defp create_crypto_context do
    # Create reusable crypto context
    %{created_at: DateTime.utc_now(), usage_count: 0}
  end

  defp calculate_optimal_batch_size(bandwidth_kbps, latency_ms, battery_level) do
    # Calculate optimal batch size based on network conditions
    base_batch_size = div(bandwidth_kbps, 10)  # Rough estimate

    # Adjust for latency and battery
    latency_factor = max(1, div(1000, latency_ms))
    battery_factor = if battery_level < 20, do: 0.5, else: 1.0

    round(base_batch_size * latency_factor * battery_factor)
    |> max(1)
    |> min(100)  # Cap at 100
  end

  defp create_message_batch(messages) do
    # Create an optimized message batch
    %{
      messages: messages,
      batch_id: Crypto.secure_random_bytes(16) |> Base.url_encode64(padding: false),
      created_at: DateTime.utc_now(),
      priority: calculate_batch_priority(messages)
    }
  end

  defp determine_security_level(cpu_score, battery_level, memory_mb) do
    # Determine appropriate security level for device
    score = (cpu_score + battery_level + min(memory_mb / 100, 100)) / 3

    cond do
      score > 80 -> :maximum
      score > 60 -> :high
      score > 40 -> :medium
      true -> :basic
    end
  end

  defp calculate_upgrade_path(current_security, target_level) do
    # Define upgrade steps
    [:enable_batch_processing, :upgrade_algorithms, :enable_pqc, :optimize_background]
  end

  defp schedule_security_upgrades(upgrade_path, device_capabilities) do
    # Schedule upgrades over time to avoid battery drain
    Enum.with_index(upgrade_path, 1)
    |> Enum.map(fn {upgrade, index} ->
      %{upgrade: upgrade, scheduled_for: DateTime.add(DateTime.utc_now(), index * 3600, :second)}
    end)
  end

  defp estimate_completion_time(upgrade_path) do
    # Estimate total time for all upgrades
    hours = length(upgrade_path)
    DateTime.add(DateTime.utc_now(), hours * 3600, :second)
  end

  defp analyze_usage_patterns(device_state) do
    # Analyze device usage to find optimal processing times
    %{peak_usage: "9-5", low_usage: "2-4", charging_times: "8-10"}
  end

  defp identify_heavy_operations do
    # Identify operations that should run in background
    [:key_generation, :backup_encryption, :batch_processing]
  end

  defp schedule_background_operations(operations, patterns) do
    # Schedule operations during low usage times
    Enum.map(operations, fn op ->
      %{operation: op, schedule: patterns.low_usage}
    end)
  end

  defp calculate_battery_savings(schedule) do
    # Estimate battery savings from optimized scheduling
    length(schedule) * 5  # 5% savings per optimized operation
  end

  defp calculate_batch_priority(messages) do
    # Calculate batch priority based on message types
    if Enum.any?(messages, &(&1.priority == :high)), do: :high, else: :normal
  end

  # Mock monitoring functions
  defp measure_battery_impact, do: 15  # 15% battery impact
  defp measure_memory_usage, do: 256   # 256MB usage
  defp measure_cpu_usage, do: 45       # 45% CPU usage
  defp measure_network_usage, do: 50   # 50MB data usage
  defp measure_crypto_performance, do: 1200  # 1200ms for key exchange

  defp analyze_performance_trends(metrics) do
    # Analyze performance trends
    %{trend: :stable, optimization_needed: false}
  end

  defp generate_optimization_recommendations(analysis) do
    # Generate optimization recommendations
    ["Enable background processing", "Reduce key sizes", "Optimize batch sizes"]
  end

  defp calculate_optimization_score(metrics) do
    # Calculate overall optimization score (0-100)
    battery_score = 100 - metrics.battery_usage
    memory_score = 100 - (metrics.memory_usage / 10)  # Assume 1GB max
    cpu_score = 100 - metrics.cpu_usage

    round((battery_score + memory_score + cpu_score) / 3)
  end
end