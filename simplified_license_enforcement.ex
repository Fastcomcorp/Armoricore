# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# Licensed under the Fastcomcorp Commercial License.
# See LICENSE file for complete terms and conditions.
#
# For commercial licensing: licensing@fastcomcorp.com
# For personal use: Free under Fastcomcorp Commercial License terms

defmodule Armoricore.Protection.Enforcement do
  @moduledoc """
  Simplified Commercial License Enforcement

  Focuses on watermarking verification and basic commercial usage detection.
  Provides clear warnings and enforcement for unauthorized commercial use.
  """

  require Logger
  use GenServer

  # Commercial indicators thresholds
  @commercial_user_threshold 10
  @commercial_api_threshold 1000  # requests per hour
  @grace_period_hours 168  # 1 week

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(opts) do
    # Start periodic checks
    schedule_compliance_check()

    state = %{
      watermarks_verified: false,
      commercial_score: 0,
      warnings_issued: 0,
      last_check: DateTime.utc_now(),
      enforcement_active: Keyword.get(opts, :enforcement_active, true)
    }

    Logger.info("Armoricore protection enforcement started")
    {:ok, state}
  end

  # Public API

  @doc """
  Check if deployment is compliant with licensing
  """
  @spec check_compliance() :: {:ok, map()} | {:error, atom()}
  def check_compliance do
    GenServer.call(__MODULE__, :check_compliance)
  end

  @doc """
  Verify watermarks on all source files
  """
  @spec verify_watermarks() :: {:ok, map()} | {:error, atom()}
  def verify_watermarks do
    GenServer.call(__MODULE__, :verify_watermarks)
  end

  @doc """
  Get current protection status
  """
  @spec get_status() :: map()
  def get_status do
    GenServer.call(__MODULE__, :get_status)
  end

  # GenServer callbacks

  def handle_call(:check_compliance, _from, state) do
    # Check watermarks first
    watermark_status = verify_watermark_integrity()

    # Check commercial usage
    commercial_score = calculate_commercial_score()

    # Determine compliance
    compliant = watermark_status.integrity_score >= 90 && commercial_score < 50

    compliance = %{
      compliant: compliant,
      watermark_integrity: watermark_status.integrity_score,
      commercial_score: commercial_score,
      risk_level: calculate_risk_level(commercial_score),
      recommendations: get_compliance_recommendations(compliant, commercial_score)
    }

    # Log compliance check
    Logger.info("Compliance check completed", compliance: compliance)

    {:reply, {:ok, compliance}, %{state | commercial_score: commercial_score}}
  end

  def handle_call(:verify_watermarks, _from, state) do
    result = verify_watermark_integrity()
    {:reply, {:ok, result}, %{state | watermarks_verified: true}}
  end

  def handle_call(:get_status, _from, state) do
    {:reply, state, state}
  end

  def handle_info(:compliance_check, state) do
    # Periodic compliance check
    {:ok, compliance} = check_compliance()

    unless compliance.compliant do
      handle_compliance_violation(compliance, state)
    end

    # Schedule next check (daily)
    schedule_compliance_check()

    {:noreply, %{state | last_check: DateTime.utc_now()}}
  end

  # Private functions

  defp verify_watermark_integrity do
    # This would run the watermark verification script
    # For now, simulate verification
    %{
      total_files: 150,  # Approximate
      verified_files: 148,
      integrity_score: 99,  # 99% integrity
      compromised_files: 2,
      last_verified: DateTime.utc_now()
    }
  end

  defp calculate_commercial_score do
    score = 0

    # Check concurrent users
    concurrent_users = get_concurrent_users()
    if concurrent_users > @commercial_user_threshold do
      score = score + min(30, concurrent_users - @commercial_user_threshold)
    end

    # Check API usage
    api_calls = get_api_calls_per_hour()
    if api_calls > @commercial_api_threshold do
      score = score + min(30, div(api_calls - @commercial_api_threshold, 100))
    end

    # Check for commercial domain
    if commercial_domain?() do
      score = score + 20
    end

    # Check for enterprise features
    if enterprise_features_used?() do
      score = score + 20
    end

    # Check for large non-profit indicators
    if large_nonprofit_detected?() do
      score = score + 25  # Non-profits with budgets must license
    end

    score
  end

  defp calculate_risk_level(score) do
    cond do
      score >= 80 -> :critical
      score >= 60 -> :high
      score >= 40 -> :medium
      score >= 20 -> :low
      true -> :minimal
    end
  end

  defp get_compliance_recommendations(compliant, commercial_score) do
    if compliant do
      ["Current usage is compliant with licensing terms."]
    else
      recommendations = ["Contact licensing@fastcomcorp.com for commercial licensing options."]

      if commercial_score >= 80 do
        recommendations = ["URGENT: System may be disabled within 24 hours unless licensed." | recommendations]
      end

      if commercial_score >= 60 do
        recommendations = ["HIGH PRIORITY: Commercial license required for current usage scale." | recommendations]
      end

      if commercial_score >= 40 do
        recommendations = ["NOTICE: Usage patterns indicate commercial deployment." | recommendations]
      end

      recommendations ++ [
        "Small Business License: $4,999/year (≤100 users)",
        "Enterprise License: $24,999/year (≤1,000 users)",
        "Unlimited License: $99,999/year (unlimited users)"
      ]
    end
  end

  defp handle_compliance_violation(compliance, state) do
    warning_count = state.warnings_issued + 1

    message = """
    🚨 ARMORICORE COMMERCIAL LICENSE VIOLATION DETECTED

    Risk Level: #{compliance.risk_level}
    Commercial Score: #{compliance.commercial_score}/100
    Warnings Issued: #{warning_count}

    Recommendations:
    #{Enum.join(compliance.recommendations, "\n    ")}

    Contact: licensing@fastcomcorp.com
    Phone: +1 (251) 645-2261
    """

    # Log violation
    Logger.error("Commercial license violation detected", compliance: compliance)

    # Send to console (in production, would send email/SMS alerts)
    IO.puts(message)

    # Progressive enforcement
    case compliance.risk_level do
      :critical ->
        Logger.error("CRITICAL: System will be disabled in 24 hours")
        schedule_shutdown()
      :high ->
        Logger.warn("HIGH RISK: Performance will be degraded")
        degrade_performance()
      :medium ->
        Logger.warn("MEDIUM RISK: Features will be limited")
        limit_features()
      _ ->
        Logger.info("LOW RISK: Monitoring continued")
    end

    # Update state
    %{state | warnings_issued: warning_count}
  end

  # Helper functions (simplified implementations)

  defp get_concurrent_users do
    # In production, would query actual metrics
    15  # Simulated
  end

  defp get_api_calls_per_hour do
    # In production, would query actual metrics
    800  # Simulated
  end

  defp commercial_domain? do
    # Check deployment domain
    # In production, would check actual domain
    false  # Simulated
  end

  defp enterprise_features_used? do
    # Check if enterprise features are active
    # In production, would check actual feature usage
    false  # Simulated
  end

  defp large_nonprofit_detected? do
    # Check for large non-profit organizations
    # Signal Foundation, Mozilla Foundation, etc.
    # In production, would check user agent, domain, etc.
    false  # Simulated
  end

  defp schedule_compliance_check do
    # Check daily (24 hours)
    Process.send_after(self(), :compliance_check, 24 * 60 * 60 * 1000)
  end

  defp schedule_shutdown do
    # Schedule system shutdown (24 hours from now)
    Process.send_after(self(), :emergency_shutdown, 24 * 60 * 60 * 1000)
  end

  defp degrade_performance do
    # Implement performance degradation
    Logger.warn("Implementing performance degradation for unlicensed commercial use")
    # In production, would slow down operations, limit throughput, etc.
  end

  defp limit_features do
    # Implement feature limitations
    Logger.warn("Implementing feature limitations for unlicensed commercial use")
    # In production, would disable advanced features
  end

  # Emergency shutdown handler
  def handle_info(:emergency_shutdown, state) do
    Logger.error("EMERGENCY SHUTDOWN: Unlicensed commercial usage detected")
    Logger.error("System will shut down in 1 hour unless valid license is provided")

    # Final warning and shutdown
    Process.send_after(self(), :final_shutdown, 60 * 60 * 1000)  # 1 hour

    {:noreply, state}
  end

  def handle_info(:final_shutdown, state) do
    Logger.error("FINAL SHUTDOWN: System disabled due to unlicensed commercial usage")
    Logger.error("Contact licensing@fastcomcorp.com to restore service")

    # In production, this would gracefully shut down the application
    System.stop(1)

    {:noreply, state}
  end
end