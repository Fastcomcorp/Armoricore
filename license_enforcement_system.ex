# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# Licensed under the Fastcomcorp Commercial License.
# See LICENSE file for complete terms and conditions.
#
# For commercial licensing: licensing@fastcomcorp.com
# For personal use: Free under Fastcomcorp Commercial License terms

defmodule Armoricore.LicenseEnforcement do
  @moduledoc """
  Commercial License Enforcement System

  Automatically detects and prevents unauthorized commercial use of Armoricore.
  Implements progressive protection measures based on usage patterns and license status.
  """

  require Logger
  use GenServer
  alias Armoricore.LicenseManager

  # Protection levels
  @protection_levels [:none, :warning, :degraded, :limited, :shutdown]

  # Commercial indicators
  @commercial_indicators [
    :high_concurrent_users,
    :revenue_generation,
    :enterprise_features,
    :commercial_domain,
    :business_hours_usage,
    :api_abuse_patterns,
    :data_export_volume
  ]

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  def init(opts) do
    # Start monitoring schedule
    schedule_monitoring()

    # Initialize protection state
    state = %{
      protection_level: :none,
      violations: [],
      last_check: DateTime.utc_now(),
      license_valid: check_license_status(),
      commercial_score: 0
    }

    {:ok, state}
  end

  # Public API

  @doc """
  Check if current usage is within license bounds
  """
  @spec check_compliance() :: {:ok, map()} | {:error, atom()}
  def check_compliance do
    GenServer.call(__MODULE__, :check_compliance)
  end

  @doc """
  Report a potential license violation
  """
  @spec report_violation(atom(), map()) :: :ok
  def report_violation(type, details) do
    GenServer.cast(__MODULE__, {:violation, type, details})
  end

  @doc """
  Get current protection status
  """
  @spec get_protection_status() :: map()
  def get_protection_status do
    GenServer.call(__MODULE__, :get_status)
  end

  # GenServer callbacks

  def handle_call(:check_compliance, _from, state) do
    commercial_score = calculate_commercial_score()
    license_valid = check_license_status()

    assessment = %{
      commercial_score: commercial_score,
      license_valid: license_valid,
      protection_level: determine_protection_level(commercial_score, license_valid),
      violations: state.violations,
      recommendation: get_recommendation(commercial_score, license_valid)
    }

    {:reply, {:ok, assessment}, %{state | commercial_score: commercial_score}}
  end

  def handle_call(:get_status, _from, state) do
    {:reply, state, state}
  end

  def handle_cast({:violation, type, details}, state) do
    violation = %{
      type: type,
      details: details,
      timestamp: DateTime.utc_now(),
      severity: calculate_violation_severity(type)
    }

    new_violations = [violation | state.violations]
    new_protection_level = escalate_protection(state.protection_level, violation)

    Logger.warning("License violation detected", violation: violation)

    # Apply protection measures
    apply_protection_measures(new_protection_level)

    {:noreply, %{state | violations: new_violations, protection_level: new_protection_level}}
  end

  def handle_info(:monitor_usage, state) do
    # Periodic monitoring
    {:ok, assessment} = check_compliance()

    # Check for violations
    if assessment.protection_level != :none do
      Logger.warning("Commercial usage detected without valid license",
        assessment: assessment
      )
    end

    # Schedule next check
    schedule_monitoring()

    {:noreply, %{state | last_check: DateTime.utc_now()}}
  end

  # Private functions

  defp calculate_commercial_score do
    score = 0

    # Check concurrent users
    if Armoricore.Metrics.get_concurrent_users() > 10 do
      score = score + 2
    end

    # Check for revenue indicators
    if detect_revenue_generation?() do
      score = score + 3
    end

    # Check enterprise features usage
    if using_enterprise_features?() do
      score = score + 2
    end

    # Check domain patterns
    if commercial_domain?() do
      score = score + 2
    end

    # Check business hours usage
    if business_hours_usage?() do
      score = score + 1
    end

    # Check API abuse patterns
    if detect_api_abuse?() do
      score = score + 1
    end

    score
  end

  defp determine_protection_level(score, license_valid) do
    cond do
      license_valid -> :none
      score >= 8 -> :shutdown
      score >= 6 -> :limited
      score >= 4 -> :degraded
      score >= 2 -> :warning
      true -> :none
    end
  end

  defp get_recommendation(score, license_valid) do
    cond do
      license_valid ->
        "License is valid. No action required."
      score >= 8 ->
        "CRITICAL: Immediate shutdown imminent. Contact licensing@fastcomcorp.com immediately."
      score >= 6 ->
        "HIGH RISK: Features will be limited. Purchase commercial license immediately."
      score >= 4 ->
        "MODERATE RISK: Performance degradation active. Consider commercial licensing."
      score >= 2 ->
        "LOW RISK: Usage monitoring active. Review commercial licensing options."
      true ->
        "No commercial usage detected. Personal use license sufficient."
    end
  end

  defp calculate_violation_severity(type) do
    case type do
      :license_expired -> :high
      :commercial_abuse -> :high
      :unauthorized_features -> :medium
      :api_abuse -> :low
      _ -> :low
    end
  end

  defp escalate_protection(current_level, violation) do
    current_index = Enum.find_index(@protection_levels, &(&1 == current_level)) || 0
    escalation = case violation.severity do
      :high -> 2
      :medium -> 1
      :low -> 0
    end

    new_index = min(current_index + escalation, length(@protection_levels) - 1)
    Enum.at(@protection_levels, new_index)
  end

  defp apply_protection_measures(level) do
    case level do
      :none ->
        :ok
      :warning ->
        Logger.warning("COMMERCIAL LICENSE WARNING: This deployment appears to be used commercially. Please ensure you have a valid commercial license or contact licensing@fastcomcorp.com")
      :degraded ->
        Logger.warning("PERFORMANCE DEGRADATION ACTIVE: Commercial usage detected without valid license. Performance reduced by 50%.")
        Armoricore.Performance.degrade_performance(0.5)
      :limited ->
        Logger.error("FEATURE LIMITATION ACTIVE: Advanced features disabled due to commercial usage without valid license.")
        Armoricore.Features.disable_enterprise_features()
      :shutdown ->
        Logger.error("EMERGENCY SHUTDOWN: Unauthorized commercial usage detected. System will shut down in 24 hours unless valid license is provided.")
        Armoricore.System.schedule_shutdown(24 * 60 * 60 * 1000) # 24 hours
    end
  end

  # Detection functions

  defp check_license_status do
    # Check if valid commercial license exists
    case LicenseManager.get_license_status() do
      {:ok, %{valid: true, type: "commercial"}} -> true
      _ -> false
    end
  end

  defp detect_revenue_generation? do
    # Check for revenue indicators
    # This is a simplified check - in practice, you'd monitor:
    # - Payment integrations
    # - Subscription systems
    # - Advertising revenue
    # - Commercial API usage
    Armoricore.Metrics.has_revenue_indicators?()
  end

  defp using_enterprise_features? do
    # Check if enterprise features are being used
    enterprise_features = [
      :advanced_audit_logging,
      :multi_region_deployment,
      :custom_integrations,
      :priority_support,
      :white_label_branding
    ]

    Enum.any?(enterprise_features, &Armoricore.Features.enabled?(&1))
  end

  defp commercial_domain? do
    # Check if running on commercial domain patterns
    # This would check the deployment domain against known commercial patterns
    case Armoricore.Config.get_deployment_domain() do
      domain when is_binary(domain) ->
        commercial_patterns = [
          ~r/\.com$/,
          ~r/\.net$/,
          ~r/\.org$/,  # Many commercial orgs use .org
          ~r/company/i,
          ~r/corp/i,
          ~r/enterprise/i
        ]
        Enum.any?(commercial_patterns, &Regex.match?(&1, domain))
      _ -> false
    end
  end

  defp business_hours_usage? do
    # Check if usage peaks during business hours
    # This indicates commercial/business use vs personal use
    usage_patterns = Armoricore.Metrics.get_usage_patterns()
    business_hours_usage = Map.get(usage_patterns, :business_hours_percent, 0)
    business_hours_usage > 60  # >60% usage during business hours
  end

  defp detect_api_abuse? do
    # Check for API abuse patterns
    metrics = Armoricore.Metrics.get_api_metrics()

    # High API call volume
    high_volume = metrics.calls_per_hour > 10000

    # Unusual patterns
    unusual_patterns = metrics.error_rate > 0.1 or metrics.timeout_rate > 0.05

    high_volume or unusual_patterns
  end

  defp schedule_monitoring do
    # Check every 15 minutes
    Process.send_after(self(), :monitor_usage, 15 * 60 * 1000)
  end
end