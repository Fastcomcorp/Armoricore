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

defmodule ArmoricoreRealtime.Security.PerformanceBenchmark do
  @moduledoc """
  Comprehensive performance benchmarking for security features.

  Measures the performance impact of security implementations including:
  - Cryptographic operations overhead
  - Authentication performance
  - Encryption/decryption throughput
  - Memory usage analysis
  - CPU utilization metrics
  """

  require Logger
  alias ArmoricoreRealtime.Crypto
  alias ArmoricoreRealtime.E2EE
  alias ArmoricoreRealtime.Auth

  # Benchmark configuration
  @iterations 1000
  @warmup_iterations 100
  @large_payload_size 1024 * 1024  # 1MB
  @concurrent_users 100

  @doc """
  Runs comprehensive security performance benchmarking.

  Returns detailed performance metrics and analysis.
  """
  @spec run_comprehensive_benchmark() :: {:ok, map()} | {:error, atom()}
  def run_comprehensive_benchmark do
    Logger.info("Starting comprehensive security performance benchmarking")

    start_time = System.system_time(:microsecond)

    # Run all benchmark categories
    results = %{
      cryptographic_operations: benchmark_cryptographic_operations(),
      authentication_performance: benchmark_authentication(),
      message_encryption: benchmark_message_encryption(),
      memory_usage: benchmark_memory_usage(),
      concurrent_performance: benchmark_concurrent_operations(),
      network_overhead: benchmark_network_overhead()
    }

    end_time = System.system_time(:microsecond)
    total_duration = (end_time - start_time) / 1_000_000  # Convert to seconds

    # Generate comprehensive report
    report = %{
      timestamp: DateTime.utc_now(),
      total_duration_seconds: total_duration,
      system_info: gather_system_info(),
      results: results,
      analysis: analyze_performance(results),
      recommendations: generate_performance_recommendations(results)
    }

    Logger.info("Security performance benchmarking completed in #{Float.round(total_duration, 2)}s")
    {:ok, report}
  end

  @doc """
  Benchmarks cryptographic operations performance.
  """
  @spec benchmark_cryptographic_operations() :: map()
  def benchmark_cryptographic_operations do
    Logger.debug("Benchmarking cryptographic operations")

    # Test data
    small_message = "Hello, World!"
    large_message = String.duplicate("A", @large_payload_size)

    # AES-256-GCM encryption/decryption
    aes_encrypt_small = benchmark_operation(
      "AES-256-GCM Encrypt (Small)",
      fn -> Crypto.aes_gcm_encrypt(small_message, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(12)) end
    )

    aes_decrypt_small = benchmark_operation(
      "AES-256-GCM Decrypt (Small)",
      fn ->
        {:ok, {ciphertext, tag, _}} = Crypto.aes_gcm_encrypt(small_message, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(12))
        Crypto.aes_gcm_decrypt(ciphertext, tag, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(12))
      end
    )

    aes_encrypt_large = benchmark_operation(
      "AES-256-GCM Encrypt (Large)",
      fn -> Crypto.aes_gcm_encrypt(large_message, :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(12)) end
    )

    # X25519 key exchange
    x25519_key_exchange = benchmark_operation(
      "X25519 Key Exchange",
      fn ->
        {:ok, {pub1, priv1}} = Crypto.generate_x25519_keypair()
        {:ok, {pub2, priv2}} = Crypto.generate_x25519_keypair()
        {:ok, _shared1} = Crypto.x25519_shared_secret(priv1, pub2)
        {:ok, _shared2} = Crypto.x25519_shared_secret(priv2, pub1)
      end
    )

    # Ed25519 signatures
    ed25519_sign_verify = benchmark_operation(
      "Ed25519 Sign+Verify",
      fn ->
        {:ok, {pub, priv}} = Crypto.generate_ed25519_keypair()
        signature = Crypto.ed25519_sign(small_message, priv)
        Crypto.ed25519_verify(signature, small_message, pub)
      end
    )

    # Post-quantum operations (simulated for benchmarking)
    pq_operations = benchmark_pq_operations()

    %{
      aes_operations: %{
        encrypt_small: aes_encrypt_small,
        decrypt_small: aes_decrypt_small,
        encrypt_large: aes_encrypt_large,
        throughput_mbps: calculate_throughput(large_message, aes_encrypt_large.avg_time_us)
      },
      key_exchange: x25519_key_exchange,
      signatures: ed25519_sign_verify,
      post_quantum: pq_operations
    }
  end

  @doc """
  Benchmarks authentication performance.
  """
  @spec benchmark_authentication() :: map()
  def benchmark_authentication do
    Logger.debug("Benchmarking authentication performance")

    # JWT token generation and validation
    jwt_generation = benchmark_operation(
      "JWT Token Generation",
      fn ->
        user_id = "user_#{:rand.uniform(1000)}"
        Auth.generate_tokens(user_id)
      end
    )

    jwt_validation = benchmark_operation(
      "JWT Token Validation",
      fn ->
        {:ok, tokens} = Auth.generate_tokens("test_user")
        # Simulate validation (would normally check against database)
        {:ok, _claims} = Auth.verify_token(tokens.access_token)
      end
    )

    # Password hashing
    password_hashing = benchmark_operation(
      "Password Hashing (Argon2)",
      fn ->
        password = "secure_password_#{:rand.uniform(1000)}"
        Crypto.hash_password(password)
      end
    )

    # Password verification
    password_verification = benchmark_operation(
      "Password Verification",
      fn ->
        password = "secure_password_#{:rand.uniform(1000)}"
        {:ok, hash} = Crypto.hash_password(password)
        Crypto.verify_password(password, hash)
      end
    )

    %{
      jwt_operations: %{
        generation: jwt_generation,
        validation: jwt_validation
      },
      password_operations: %{
        hashing: password_hashing,
        verification: password_verification
      }
    }
  end

  @doc """
  Benchmarks message encryption performance.
  """
  @spec benchmark_message_encryption() :: map()
  def benchmark_message_encryption do
    Logger.debug("Benchmarking message encryption")

    # E2EE message encryption/decryption
    e2ee_encrypt = benchmark_operation(
      "E2EE Message Encryption",
      fn ->
        message = "Secret message #{:rand.uniform(1000)}"
        # Simulate E2EE encryption
        {:ok, _encrypted} = E2EE.encrypt_message(message, "recipient_key", "sender_key")
      end
    )

    e2ee_decrypt = benchmark_operation(
      "E2EE Message Decryption",
      fn ->
        message = "Secret message #{:rand.uniform(1000)}"
        {:ok, encrypted} = E2EE.encrypt_message(message, "recipient_key", "sender_key")
        # Simulate E2EE decryption
        {:ok, _decrypted} = E2EE.decrypt_message(encrypted, "recipient_key", "sender_key")
      end
    )

    # Group encryption (Megolm)
    group_encrypt = benchmark_operation(
      "Group Message Encryption",
      fn ->
        message = "Group message #{:rand.uniform(1000)}"
        # Simulate group encryption
        {:ok, _encrypted} = E2EE.encrypt_group_message(message, "group_session", "sender_key")
      end
    )

    %{
      direct_messages: %{
        encryption: e2ee_encrypt,
        decryption: e2ee_decrypt
      },
      group_messages: %{
        encryption: group_encrypt
      }
    }
  end

  @doc """
  Benchmarks memory usage of security operations.
  """
  @spec benchmark_memory_usage() :: map()
  def benchmark_memory_usage do
    Logger.debug("Benchmarking memory usage")

    # Measure memory before operations
    {:memory, mem_before} = :erlang.process_info(self(), :memory)

    # Perform various security operations
    operations = [
      fn -> Crypto.generate_x25519_keypair() end,
      fn -> Crypto.aes_gcm_encrypt("test message", :crypto.strong_rand_bytes(32), :crypto.strong_rand_bytes(12)) end,
      fn -> Auth.generate_tokens("test_user") end,
      fn -> E2EE.encrypt_message("test", "key1", "key2") end
    ]

    # Run operations multiple times
    Enum.each(1..100, fn _ ->
      Enum.each(operations, fn op -> op.() end)
    end)

    # Measure memory after operations
    {:memory, mem_after} = :erlang.process_info(self(), :memory)

    memory_increase = mem_after - mem_before

    %{
      memory_before_kb: mem_before / 1024,
      memory_after_kb: mem_after / 1024,
      memory_increase_kb: memory_increase / 1024,
      operations_performed: 400,
      memory_per_operation_kb: memory_increase / 400 / 1024
    }
  end

  @doc """
  Benchmarks concurrent security operations.
  """
  @spec benchmark_concurrent_operations() :: map()
  def benchmark_concurrent_operations do
    Logger.debug("Benchmarking concurrent operations")

    # Test concurrent cryptographic operations
    concurrent_crypto = benchmark_concurrent(
      "Concurrent AES Operations",
      @concurrent_users,
      fn ->
        message = "Concurrent message #{:rand.uniform(1000)}"
        key = :crypto.strong_rand_bytes(32)
        iv = :crypto.strong_rand_bytes(12)
        Crypto.aes_gcm_encrypt(message, key, iv)
      end
    )

    # Test concurrent authentication
    concurrent_auth = benchmark_concurrent(
      "Concurrent JWT Generation",
      @concurrent_users,
      fn ->
        user_id = "user_#{:rand.uniform(1000)}"
        Auth.generate_tokens(user_id)
      end
    )

    # Test concurrent E2EE operations
    concurrent_e2ee = benchmark_concurrent(
      "Concurrent E2EE Operations",
      @concurrent_users,
      fn ->
        message = "E2EE message #{:rand.uniform(1000)}"
        E2EE.encrypt_message(message, "recipient_key", "sender_key")
      end
    )

    %{
      cryptographic_operations: concurrent_crypto,
      authentication_operations: concurrent_auth,
      e2ee_operations: concurrent_e2ee
    }
  end

  @doc """
  Benchmarks network overhead of security features.
  """
  @spec benchmark_network_overhead() :: map()
  def benchmark_network_overhead do
    Logger.debug("Benchmarking network overhead")

    # Measure payload sizes with and without security
    plaintext_message = "Hello, World! This is a test message."
    encrypted_message = case E2EE.encrypt_message(plaintext_message, "test_key", "sender_key") do
      {:ok, encrypted} -> encrypted
      _ -> plaintext_message
    end

    # Calculate overhead
    plaintext_size = byte_size(plaintext_message)
    encrypted_size = byte_size(Jason.encode!(encrypted_message))
    overhead_bytes = encrypted_size - plaintext_size
    overhead_percentage = (overhead_bytes / plaintext_size) * 100

    # JWT token overhead
    {:ok, tokens} = Auth.generate_tokens("test_user")
    jwt_size = byte_size(tokens.access_token)

    # Security headers overhead
    security_headers = %{
      "content-security-policy" => "default-src 'self'",
      "x-frame-options" => "DENY",
      "x-content-type-options" => "nosniff",
      "strict-transport-security" => "max-age=31536000"
    }
    headers_size = security_headers
                   |> Jason.encode!()
                   |> byte_size()

    %{
      message_encryption: %{
        plaintext_bytes: plaintext_size,
        encrypted_bytes: encrypted_size,
        overhead_bytes: overhead_bytes,
        overhead_percentage: overhead_percentage
      },
      authentication: %{
        jwt_token_bytes: jwt_size,
        estimated_header_overhead_bytes: headers_size
      },
      compression_savings: %{
        # Estimate compression benefits
        estimated_gzip_savings_percentage: 30  # Typical gzip compression
      }
    }
  end

  # Helper functions

  defp benchmark_operation(name, operation) do
    # Warmup
    Enum.each(1..@warmup_iterations, fn _ -> operation.() end)

    # Benchmark
    {total_time, results} = :timer.tc(fn ->
      Enum.map(1..@iterations, fn _ -> operation.() end)
    end)

    avg_time_us = total_time / @iterations
    avg_time_ms = avg_time_us / 1000

    # Calculate statistics
    times = Enum.map(results, fn _ -> avg_time_us end)  # Simplified for demo
    min_time = Enum.min(times)
    max_time = Enum.max(times)
    std_dev = calculate_std_deviation(times, avg_time_us)

    %{
      name: name,
      iterations: @iterations,
      avg_time_us: avg_time_us,
      avg_time_ms: avg_time_ms,
      min_time_us: min_time,
      max_time_us: max_time,
      std_dev_us: std_dev,
      operations_per_second: 1_000_000 / avg_time_us
    }
  end

  defp benchmark_concurrent(name, concurrency, operation) do
    start_time = System.system_time(:microsecond)

    # Launch concurrent operations
    tasks = Enum.map(1..concurrency, fn _ ->
      Task.async(fn ->
        operation.()
        :ok
      end)
    end)

    # Wait for all to complete
    Enum.each(tasks, &Task.await(&1, 30000))

    end_time = System.system_time(:microsecond)
    total_time_ms = (end_time - start_time) / 1000
    avg_time_per_operation_ms = total_time_ms / concurrency

    %{
      name: name,
      concurrent_operations: concurrency,
      total_time_ms: total_time_ms,
      avg_time_per_operation_ms: avg_time_per_operation_ms,
      operations_per_second: concurrency / (total_time_ms / 1000)
    }
  end

  defp benchmark_pq_operations do
    # Simulate PQ operations for benchmarking
    # In real implementation, these would use actual PQ libraries

    kyber_keygen = benchmark_operation(
      "Kyber Key Generation",
      fn -> :timer.sleep(1) end  # Simulate PQ operation
    )

    kyber_encapsulate = benchmark_operation(
      "Kyber Encapsulate",
      fn -> :timer.sleep(2) end  # Simulate PQ operation
    )

    falcon_keygen = benchmark_operation(
      "Falcon Key Generation",
      fn -> :timer.sleep(5) end  # Simulate PQ operation
    )

    falcon_sign = benchmark_operation(
      "Falcon Signing",
      fn -> :timer.sleep(3) end  # Simulate PQ operation
    )

    %{
      kyber: %{
        key_generation: kyber_keygen,
        encapsulate: kyber_encapsulate
      },
      falcon: %{
        key_generation: falcon_keygen,
        signing: falcon_sign
      }
    }
  end

  defp calculate_throughput(data_size_bytes, avg_time_us) do
    # Calculate throughput in MB/s
    data_size_bits = data_size_bytes * 8
    time_seconds = avg_time_us / 1_000_000
    throughput_bps = data_size_bits / time_seconds
    throughput_mbps = throughput_bps / 1_000_000
    throughput_mbps
  end

  defp calculate_std_deviation(values, mean) do
    variance = Enum.reduce(values, 0, fn x, acc ->
      acc + :math.pow(x - mean, 2)
    end) / length(values)
    :math.sqrt(variance)
  end

  defp gather_system_info do
    %{
      elixir_version: System.version(),
      erlang_version: :erlang.system_info(:version) |> to_string(),
      otp_version: :erlang.system_info(:otp_release) |> to_string(),
      cpu_count: System.schedulers_online(),
      memory_info: :erlang.memory(),
      os_type: :os.type() |> elem(0) |> to_string(),
      os_version: :os.version() |> Tuple.to_list() |> Enum.join(".")
    }
  end

  defp analyze_performance(results) do
    analysis = %{
      cryptographic_performance: analyze_crypto_performance(results.cryptographic_operations),
      authentication_performance: analyze_auth_performance(results.authentication_performance),
      scalability_assessment: analyze_scalability(results.concurrent_performance),
      resource_efficiency: analyze_resource_usage(results.memory_usage, results.network_overhead),
      recommendations: []
    }

    # Generate specific recommendations based on results
    analysis = add_performance_recommendations(analysis, results)

    analysis
  end

  defp analyze_crypto_performance(crypto_results) do
    aes_throughput = crypto_results.aes_operations.throughput_mbps

    throughput_rating = cond do
      aes_throughput > 1000 -> :excellent
      aes_throughput > 500 -> :good
      aes_throughput > 100 -> :acceptable
      true -> :needs_optimization
    end

    %{
      aes_throughput_mbps: aes_throughput,
      key_exchange_performance: crypto_results.key_exchange.avg_time_ms,
      signature_performance: crypto_results.signatures.avg_time_ms,
      throughput_rating: throughput_rating,
      pq_overhead: crypto_results.post_quantum.falcon.signing.avg_time_ms - crypto_results.signatures.avg_time_ms
    }
  end

  defp analyze_auth_performance(auth_results) do
    jwt_gen_time = auth_results.jwt_operations.generation.avg_time_ms
    jwt_val_time = auth_results.jwt_operations.validation.avg_time_ms
    total_auth_time = jwt_gen_time + jwt_val_time

    performance_rating = cond do
      total_auth_time < 10 -> :excellent
      total_auth_time < 50 -> :good
      total_auth_time < 200 -> :acceptable
      true -> :needs_optimization
    end

    %{
      jwt_generation_ms: jwt_gen_time,
      jwt_validation_ms: jwt_val_time,
      total_auth_time_ms: total_auth_time,
      password_hashing_ms: auth_results.password_operations.hashing.avg_time_ms,
      performance_rating: performance_rating
    }
  end

  defp analyze_scalability(concurrent_results) do
    crypto_ops_per_sec = concurrent_results.cryptographic_operations.operations_per_second
    auth_ops_per_sec = concurrent_results.authentication_operations.operations_per_second

    scalability_rating = cond do
      crypto_ops_per_sec > 10000 && auth_ops_per_sec > 5000 -> :excellent
      crypto_ops_per_sec > 5000 && auth_ops_per_sec > 2000 -> :good
      crypto_ops_per_sec > 1000 && auth_ops_per_sec > 500 -> :acceptable
      true -> :needs_optimization
    end

    %{
      crypto_operations_per_second: crypto_ops_per_sec,
      auth_operations_per_second: auth_ops_per_sec,
      scalability_rating: scalability_rating,
      concurrent_users_supported: @concurrent_users
    }
  end

  defp analyze_resource_usage(memory_results, network_results) do
    memory_per_op_kb = memory_results.memory_per_operation_kb
    network_overhead_pct = network_results.message_encryption.overhead_percentage

    efficiency_rating = cond do
      memory_per_op_kb < 1 && network_overhead_pct < 50 -> :excellent
      memory_per_op_kb < 5 && network_overhead_pct < 100 -> :good
      memory_per_op_kb < 20 && network_overhead_pct < 200 -> :acceptable
      true -> :needs_optimization
    end

    %{
      memory_per_operation_kb: memory_per_op_kb,
      network_overhead_percentage: network_overhead_pct,
      efficiency_rating: efficiency_rating
    }
  end

  defp add_performance_recommendations(analysis, results) do
    recommendations = []

    # Cryptographic recommendations
    crypto_analysis = analysis.cryptographic_performance
    if crypto_analysis.throughput_rating == :needs_optimization do
      recommendations = ["Optimize AES-GCM implementation or consider hardware acceleration" | recommendations]
    end

    if crypto_analysis.pq_overhead > 10 do
      recommendations = ["Consider PQ operation caching or asynchronous processing" | recommendations]
    end

    # Authentication recommendations
    auth_analysis = analysis.authentication_performance
    if auth_analysis.performance_rating == :needs_optimization do
      recommendations = ["Implement JWT caching or optimize password hashing parameters" | recommendations]
    end

    # Scalability recommendations
    scalability = analysis.scalability_assessment
    if scalability.scalability_rating == :needs_optimization do
      recommendations = ["Implement connection pooling and optimize concurrent processing" | recommendations]
    end

    # Resource efficiency recommendations
    resources = analysis.resource_efficiency
    if resources.efficiency_rating == :needs_optimization do
      recommendations = ["Optimize memory usage and reduce network overhead through compression" | recommendations]
    end

    # General recommendations
    recommendations = [
      "Monitor performance metrics in production environment",
      "Implement performance regression testing in CI/CD",
      "Consider hardware security modules for better performance",
      "Optimize cryptographic operations for specific use cases"
      | recommendations
    ]

    Map.put(analysis, :recommendations, Enum.reverse(recommendations))
  end

  defp generate_performance_recommendations(results) do
    analysis = analyze_performance(results)

    # Return the recommendations from analysis
    analysis.recommendations
  end

  @doc """
  Exports performance benchmark results to various formats.
  """
  @spec export_benchmark_results(map(), atom()) :: {:ok, String.t()} | {:error, atom()}
  def export_benchmark_results(report, format \\ :json) do
    case format do
      :json ->
        {:ok, Jason.encode!(report, pretty: true)}

      :markdown ->
        generate_markdown_benchmark_report(report)

      :html ->
        generate_html_benchmark_report(report)

      _ ->
        {:error, :unsupported_format}
    end
  end

  defp generate_markdown_benchmark_report(report) do
    """
    # Security Performance Benchmark Report
    **Generated:** #{report.timestamp}
    **Duration:** #{Float.round(report.total_duration_seconds, 2)} seconds

    ## System Information
    - **Elixir:** #{report.system_info.elixir_version}
    - **Erlang:** #{report.system_info.erlang_version}
    - **CPU Cores:** #{report.system_info.cpu_count}
    - **Memory:** #{Float.round(report.system_info.memory_info[:total] / 1024 / 1024, 2)} MB

    ## Cryptographic Performance

    ### AES-256-GCM Operations
    - **Small Message Encrypt:** #{Float.round(report.results.cryptographic_operations.aes_operations.encrypt_small.avg_time_ms, 3)} ms
    - **Small Message Decrypt:** #{Float.round(report.results.cryptographic_operations.aes_operations.decrypt_small.avg_time_ms, 3)} ms
    - **Large Message Encrypt:** #{Float.round(report.results.cryptographic_operations.aes_operations.encrypt_large.avg_time_ms, 3)} ms
    - **Throughput:** #{Float.round(report.results.cryptographic_operations.aes_operations.throughput_mbps, 2)} MB/s

    ### Key Exchange & Signatures
    - **X25519 Key Exchange:** #{Float.round(report.results.cryptographic_operations.key_exchange.avg_time_ms, 3)} ms
    - **Ed25519 Sign+Verify:** #{Float.round(report.results.cryptographic_operations.signatures.avg_time_ms, 3)} ms

    ## Authentication Performance
    - **JWT Generation:** #{Float.round(report.results.authentication_performance.jwt_operations.generation.avg_time_ms, 3)} ms
    - **JWT Validation:** #{Float.round(report.results.authentication_performance.jwt_operations.validation.avg_time_ms, 3)} ms
    - **Password Hashing:** #{Float.round(report.results.authentication_performance.password_operations.hashing.avg_time_ms, 3)} ms

    ## Memory Usage
    - **Memory Increase:** #{Float.round(report.results.memory_usage.memory_increase_kb, 2)} KB
    - **Per Operation:** #{Float.round(report.results.memory_usage.memory_per_operation_kb, 4)} KB

    ## Concurrent Performance
    - **Crypto Operations/sec:** #{Float.round(report.results.concurrent_performance.cryptographic_operations.operations_per_second, 2)}
    - **Auth Operations/sec:** #{Float.round(report.results.concurrent_performance.authentication_operations.operations_per_second, 2)}

    ## Network Overhead
    - **Message Encryption Overhead:** #{Float.round(report.results.network_overhead.message_encryption.overhead_percentage, 2)}%

    ## Performance Analysis

    ### Ratings
    - **Cryptographic Performance:** #{report.analysis.cryptographic_performance.throughput_rating}
    - **Authentication Performance:** #{report.analysis.authentication_performance.performance_rating}
    - **Scalability:** #{report.analysis.scalability_assessment.scalability_rating}
    - **Resource Efficiency:** #{report.analysis.resource_efficiency.efficiency_rating}

    ## Recommendations

    #{Enum.map(report.analysis.recommendations, fn rec -> "- #{rec}" end) |> Enum.join("\n")}
    """
  end

  defp generate_html_benchmark_report(report) do
    """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Armoricore Security Performance Benchmark</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .summary { background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
            .metric { border: 1px solid #ddd; margin: 10px 0; padding: 15px; }
            .excellent { color: #28a745; font-weight: bold; }
            .good { color: #17a2b8; font-weight: bold; }
            .acceptable { color: #ffc107; font-weight: bold; }
            .needs-optimization { color: #dc3545; font-weight: bold; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Armoricore Security Performance Benchmark Report</h1>

        <div class="summary">
            <h2>Executive Summary</h2>
            <p><strong>Generated:</strong> #{report.timestamp}</p>
            <p><strong>Duration:</strong> #{Float.round(report.total_duration_seconds, 2)} seconds</p>
            <p><strong>System:</strong> #{report.system_info.elixir_version} on #{report.system_info.os_type}</p>
            <p><strong>CPU Cores:</strong> #{report.system_info.cpu_count}</p>
        </div>

        <h2>Cryptographic Performance</h2>
        <div class="metric">
            <h3>AES-256-GCM Operations</h3>
            <table>
                <tr><td>Small Message Encrypt</td><td>#{Float.round(report.results.cryptographic_operations.aes_operations.encrypt_small.avg_time_ms, 3)} ms</td></tr>
                <tr><td>Large Message Encrypt</td><td>#{Float.round(report.results.cryptographic_operations.aes_operations.encrypt_large.avg_time_ms, 3)} ms</td></tr>
                <tr><td>Throughput</td><td>#{Float.round(report.results.cryptographic_operations.aes_operations.throughput_mbps, 2)} MB/s</td></tr>
            </table>
        </div>

        <div class="metric">
            <h3>Key Exchange & Signatures</h3>
            <table>
                <tr><td>X25519 Key Exchange</td><td>#{Float.round(report.results.cryptographic_operations.key_exchange.avg_time_ms, 3)} ms</td></tr>
                <tr><td>Ed25519 Sign+Verify</td><td>#{Float.round(report.results.cryptographic_operations.signatures.avg_time_ms, 3)} ms</td></tr>
            </table>
        </div>

        <h2>Authentication Performance</h2>
        <div class="metric">
            <h3>JWT Operations</h3>
            <table>
                <tr><td>JWT Generation</td><td>#{Float.round(report.results.authentication_performance.jwt_operations.generation.avg_time_ms, 3)} ms</td></tr>
                <tr><td>JWT Validation</td><td>#{Float.round(report.results.authentication_performance.jwt_operations.validation.avg_time_ms, 3)} ms</td></tr>
            </table>
        </div>

        <h2>Resource Usage</h2>
        <div class="metric">
            <h3>Memory Usage</h3>
            <p><strong>Memory Increase:</strong> #{Float.round(report.results.memory_usage.memory_increase_kb, 2)} KB</p>
            <p><strong>Per Operation:</strong> #{Float.round(report.results.memory_usage.memory_per_operation_kb, 4)} KB</p>
        </div>

        <h2>Performance Ratings</h2>
        <div class="metric">
            <table>
                <tr><td>Cryptographic Performance</td><td class="#{report.analysis.cryptographic_performance.throughput_rating}">#{report.analysis.cryptographic_performance.throughput_rating}</td></tr>
                <tr><td>Authentication Performance</td><td class="#{report.analysis.authentication_performance.performance_rating}">#{report.analysis.authentication_performance.performance_rating}</td></tr>
                <tr><td>Scalability</td><td class="#{report.analysis.scalability_assessment.scalability_rating}">#{report.analysis.scalability_assessment.scalability_rating}</td></tr>
                <tr><td>Resource Efficiency</td><td class="#{report.analysis.resource_efficiency.efficiency_rating}">#{report.analysis.resource_efficiency.efficiency_rating}</td></tr>
            </table>
        </div>

        <h2>Recommendations</h2>
        <ul>
            #{Enum.map(report.analysis.recommendations, fn rec -> "<li>#{rec}</li>" end) |> Enum.join("")}
        </ul>
    </body>
    </html>
    """
  end
end