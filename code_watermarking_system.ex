# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# Licensed under the Fastcomcorp Commercial License.
# See LICENSE file for complete terms and conditions.
#
# For commercial licensing: licensing@fastcomcorp.com
# For personal use: Free under Fastcomcorp Commercial License terms

defmodule Armoricore.CodeWatermarking do
  @moduledoc """
  Advanced Code Watermarking System

  Embeds invisible digital watermarks in source code to:
  1. Prove ownership and origin
  2. Detect unauthorized commercial use
  3. Track code distribution and modifications
  4. Enable legal enforcement actions
  """

  require Logger

  # Watermark signatures
  @owner_signature "FASTCOMCORP_ARMORICORE_2026"
  @license_signature "COMMERCIAL_LICENSE_ENFORCED"
  @personal_use_signature "PERSONAL_USE_ONLY"

  # Watermark types
  @watermark_types [
    :comment_watermarks,
    :whitespace_watermarks,
    :string_watermarks,
    :variable_watermarks,
    :control_flow_watermarks,
    :metadata_watermarks
  ]

  @doc """
  Apply comprehensive watermarking to source code
  """
  @spec watermark_code(String.t(), map()) :: {:ok, String.t()} | {:error, atom()}
  def watermark_code(source_code, options \\ %{}) do
    try do
      watermarked = source_code

      # Apply different watermarking techniques
      watermarked = apply_comment_watermarks(watermarked, options)
      watermarked = apply_whitespace_watermarks(watermarked, options)
      watermarked = apply_string_watermarks(watermarked, options)
      watermarked = apply_variable_watermarks(watermarked, options)
      watermarked = apply_control_flow_watermarks(watermarked, options)
      watermarked = apply_metadata_watermarks(watermarked, options)

      # Add cryptographic signature
      watermarked = add_cryptographic_signature(watermarked)

      Logger.info("Code watermarking applied successfully")
      {:ok, watermarked}

    rescue
      error ->
        Logger.error("Failed to apply code watermarking: #{inspect(error)}")
        {:error, :watermarking_failed}
    end
  end

  @doc """
  Detect and verify watermarks in code
  """
  @spec detect_watermarks(String.t()) :: {:ok, map()} | {:error, atom()}
  def detect_watermarks(code) do
    try do
      detection_results = %{
        owner_signature: detect_owner_signature(code),
        license_type: detect_license_type(code),
        distribution_tracking: detect_distribution_info(code),
        modification_tracking: detect_modifications(code),
        commercial_usage: detect_commercial_usage_indicators(code),
        integrity_check: verify_code_integrity(code)
      }

      confidence_score = calculate_detection_confidence(detection_results)

      result = Map.put(detection_results, :confidence_score, confidence_score)

      Logger.info("Watermark detection completed", confidence: confidence_score)
      {:ok, result}

    rescue
      error ->
        Logger.error("Failed to detect watermarks: #{inspect(error)}")
        {:error, :detection_failed}
    end
  end

  @doc """
  Verify code integrity and ownership
  """
  @spec verify_ownership(String.t()) :: {:ok, boolean()} | {:error, atom()}
  def verify_ownership(code) do
    case detect_watermarks(code) do
      {:ok, results} ->
        owner_verified = results.owner_signature.detected
        signature_valid = results.integrity_check.valid

        if owner_verified and signature_valid do
          {:ok, true}
        else
          {:ok, false}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Watermarking implementation

  defp apply_comment_watermarks(code, _options) do
    # Embed watermarks in comments
    # Use invisible Unicode characters and encoded signatures

    watermark_comment = """
    <!-- Fastcomcorp Armoricore Watermark: #{Base.encode64(@owner_signature)} -->
    <!-- License: #{Base.encode64(@license_signature)} -->
    <!-- Distribution ID: #{generate_distribution_id()} -->
    """

    # Insert watermark comments in strategic locations
    code
    |> String.replace(~r/(defmodule\s+\w+)/, "#{watermark_comment}\\1")
    |> String.replace(~r/(def\s+\w+)/, "<!-- Watermark: #{invisible_signature()} -->\\1")
  end

  defp apply_whitespace_watermarks(code, _options) do
    # Embed watermarks in whitespace patterns
    # Use invisible characters and specific indentation patterns

    # Add invisible Unicode characters in whitespace
    invisible_chars = <<0x200B, 0x200C, 0x200D, 0xFEFF>>  # Zero-width characters

    # Encode signature in whitespace
    signature_bits = @owner_signature
                     |> :crypto.hash(:md5)
                     |> Base.encode16(case: :lower)
                     |> String.to_charlist()
                     |> Enum.map(&if rem(&1, 2) == 0, do: "  ", else: "   ")  # Even/odd -> 2/3 spaces

    whitespace_pattern = Enum.join(signature_bits)

    # Insert whitespace watermark after function definitions
    String.replace(code, ~r/(def\s+\w+.*do)/, "\\1#{whitespace_pattern}")
  end

  defp apply_string_watermarks(code, _options) do
    # Embed watermarks in string literals
    # Use Unicode homoglyphs and zero-width characters

    watermarked_string = "Fastcomcorp\u200B\u200CArmoricore\u200D\u200E"  # Invisible separators

    # Replace specific strings with watermarked versions
    code
    |> String.replace("\"Armoricore\"", "\"#{watermarked_string}\"")
    |> String.replace("'Armoricore'", "'#{watermarked_string}'")
  end

  defp apply_variable_watermarks(code, _options) do
    # Embed watermarks in variable names
    # Use Unicode homoglyphs that look identical but have different codepoints

    # Replace specific variable patterns
    code
    |> String.replace(~r/\buser_id\b/, "user_\uFF4D\uFF44")  # Unicode homoglyphs
    |> String.replace(~r/\buser\b/, "u\u200Bser")  # Zero-width character
  end

  defp apply_control_flow_watermarks(code, _options) do
    # Embed watermarks in control flow
    # Add opaque predicates and dead code paths

    watermark_check = """
    # Fastcomcorp watermark verification
    _watermark_check = fn ->
      signature = "#{@owner_signature}"
      hash = :crypto.hash(:sha256, signature)
      # This check always passes but embeds the watermark
      byte_size(signature) > 0
    end
    unless _watermark_check.() do
      # This code never executes but embeds the watermark
      Logger.debug("Watermark: #{Base.encode64(@owner_signature)}")
    end
    """

    # Insert after module definition
    String.replace(code, ~r/(defmodule\s+\w+.*do)/, "\\1\n#{watermark_check}")
  end

  defp apply_metadata_watermarks(code, options) do
    # Embed metadata watermarks
    # Add compilation metadata and distribution tracking

    metadata = %{
      owner: "Fastcomcorp, LLC",
      license: options[:license_type] || "commercial",
      distribution_id: generate_distribution_id(),
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      version: options[:version] || "1.0.0"
    }

    metadata_json = Jason.encode!(metadata) |> Base.encode64()

    metadata_comment = """
    # @fastcomcorp_metadata #{metadata_json}
    # @watermark_signature #{:crypto.hash(:sha256, @owner_signature) |> Base.encode64()}
    """

    code <> "\n" <> metadata_comment
  end

  defp add_cryptographic_signature(code) do
    # Add cryptographic signature to the entire code
    signature = :crypto.hash(:sha256, code <> @owner_signature)
                |> Base.encode64()

    signature_comment = """
    # @fastcomcorp_signature #{signature}
    # @integrity_verified #{DateTime.utc_now() |> DateTime.to_iso8601()}
    """

    code <> "\n" <> signature_comment
  end

  # Detection implementation

  defp detect_owner_signature(code) do
    owner_detected = String.contains?(code, @owner_signature) or
                     String.contains?(code, Base.encode64(@owner_signature))

    invisible_detected = String.contains?(code, invisible_signature())

    %{
      detected: owner_detected or invisible_detected,
      strength: if(owner_detected, do: :strong, else: :weak),
      locations: find_watermark_locations(code, @owner_signature)
    }
  end

  defp detect_license_type(code) do
    commercial_detected = String.contains?(code, @license_signature) or
                          String.contains?(code, "COMMERCIAL")

    personal_detected = String.contains?(code, @personal_use_signature) or
                        String.contains?(code, "PERSONAL")

    cond do
      commercial_detected -> %{type: :commercial, confidence: :high}
      personal_detected -> %{type: :personal, confidence: :high}
      true -> %{type: :unknown, confidence: :low}
    end
  end

  defp detect_distribution_info(code) do
    # Look for distribution tracking information
    distribution_pattern = ~r/@distribution_id\s+([A-Za-z0-9_-]+)/
    case Regex.run(distribution_pattern, code) do
      [_, distribution_id] ->
        %{detected: true, id: distribution_id}
      _ ->
        %{detected: false, id: nil}
    end
  end

  defp detect_modifications(code) do
    # Check if code has been significantly modified
    signature_pattern = ~r/@fastcomcorp_signature\s+([A-Za-z0-9+/=]+)/
    case Regex.run(signature_pattern, code) do
      [_, stored_signature] ->
        current_hash = :crypto.hash(:sha256, remove_watermarks(code))
        stored_hash = Base.decode64!(stored_signature)

        if current_hash == stored_hash do
          %{modified: false, confidence: :high}
        else
          %{modified: true, confidence: :high}
        end

      _ ->
        %{modified: :unknown, confidence: :low}
    end
  end

  defp detect_commercial_usage_indicators(code) do
    # Look for commercial usage patterns in the code
    commercial_patterns = [
      ~r/enterprise/i,
      ~r/commercial/i,
      ~r/business/i,
      ~r/revenue/i,
      ~r/monetization/i,
      ~r/licensing@fastcomcorp\.com/i
    ]

    matches = Enum.count(commercial_patterns, &Regex.match?(&1, code))

    %{
      indicators_found: matches,
      commercial_likelihood: if(matches > 3, do: :high, else: if(matches > 1, do: :medium, else: :low))
    }
  end

  defp verify_code_integrity(code) do
    # Verify that the code hasn't been tampered with
    signature_pattern = ~r/@fastcomcorp_signature\s+([A-Za-z0-9+/=]+)/
    metadata_pattern = ~r/@fastcomcorp_metadata\s+([A-Za-z0-9+/=]+)/

    with [_, signature] <- Regex.run(signature_pattern, code),
         [_, metadata] <- Regex.run(metadata_pattern, code),
         {:ok, _decoded_metadata} <- Base.decode64(metadata) do

      # Verify signature
      clean_code = remove_watermarks(code)
      expected_signature = :crypto.hash(:sha256, clean_code <> @owner_signature)
                           |> Base.encode64()

      if signature == expected_signature do
        %{valid: true, tampered: false}
      else
        %{valid: false, tampered: true}
      end
    else
      _ -> %{valid: false, reason: :missing_watermarks}
    end
  end

  # Helper functions

  defp invisible_signature do
    # Create invisible signature using zero-width characters
    @owner_signature
    |> String.graphemes()
    |> Enum.map(&(&1 <> <<0x200B>>))  # Add zero-width space
    |> Enum.join()
  end

  defp generate_distribution_id do
    # Generate unique distribution identifier
    timestamp = DateTime.utc_now() |> DateTime.to_unix()
    random = :crypto.strong_rand_bytes(8) |> Base.encode16(case: :lower)
    "#{timestamp}_#{random}"
  end

  defp find_watermark_locations(code, watermark) do
    # Find all locations of watermark in code
    String.split(code, "\n")
    |> Enum.with_index()
    |> Enum.filter(fn {line, _index} -> String.contains?(line, watermark) end)
    |> Enum.map(fn {_line, index} -> index + 1 end)
  end

  defp remove_watermarks(code) do
    # Remove watermark comments for integrity checking
    code
    |> String.replace(~r/# @fastcomcorp_signature.*\n/, "")
    |> String.replace(~r/# @fastcomcorp_metadata.*\n/, "")
    |> String.replace(~r/# @integrity_verified.*\n/, "")
  end

  defp calculate_detection_confidence(results) do
    score = 0

    # Owner signature detection
    score = score + if results.owner_signature.detected, do: 30, else: 0

    # License type detection
    score = score + case results.license_type.confidence do
      :high -> 20
      :medium -> 10
      _ -> 0
    end

    # Integrity check
    score = score + if results.integrity_check.valid, do: 25, else: 0

    # Distribution tracking
    score = score + if results.distribution_tracking.detected, do: 15, else: 0

    # Modification detection
    score = score + case results.modification_tracking do
      %{modified: false} -> 10
      %{modified: true} -> 0
      _ -> 5
    end

    min(100, score)
  end

  @doc """
  Batch watermark multiple files
  """
  @spec watermark_files([String.t()], map()) :: {:ok, map()} | {:error, atom()}
  def watermark_files(file_paths, options \\ %{}) do
    results = Enum.map(file_paths, fn path ->
      case File.read(path) do
        {:ok, content} ->
          case watermark_code(content, options) do
            {:ok, watermarked} ->
              # Write back to file
              File.write!(path, watermarked)
              {:ok, path}

            {:error, reason} ->
              {:error, path, reason}
          end

        {:error, reason} ->
          {:error, path, reason}
      end
    end)

    successful = Enum.count(results, &match?({:ok, _}, &1))
    failed = Enum.count(results, &match?({:error, _, _}, &1))

    {:ok, %{processed: successful, failed: failed, results: results}}
  end

  @doc """
  Scan directory for watermarked files
  """
  @spec scan_directory(String.t()) :: {:ok, map()} | {:error, atom()}
  def scan_directory(dir_path) do
    try do
      files = Path.wildcard(Path.join(dir_path, "**/*.ex")) ++
              Path.wildcard(Path.join(dir_path, "**/*.exs"))

      results = Enum.map(files, fn file ->
        case File.read(file) do
          {:ok, content} ->
            case detect_watermarks(content) do
              {:ok, detection} ->
                {file, detection}
              {:error, _} ->
                {file, %{error: :detection_failed}}
            end

          {:error, _} ->
            {file, %{error: :file_read_failed}}
        end
      end)

      watermarked_files = Enum.count(results, fn {_file, result} ->
        Map.get(result, :confidence_score, 0) > 50
      end)

      {:ok, %{
        total_files: length(results),
        watermarked_files: watermarked_files,
        results: results
      }}

    rescue
      error ->
        Logger.error("Failed to scan directory: #{inspect(error)}")
        {:error, :scan_failed}
    end
  end
end