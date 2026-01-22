# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp, LLC
#
# Licensed under the Fastcomcorp Commercial License.
# See LICENSE file for complete terms and conditions.
#
# For commercial licensing: licensing@fastcomcorp.com
# For personal use: Free under Fastcomcorp Commercial License terms

defmodule Armoricore.SaaSGateway do
  @moduledoc """
  SaaS Gateway for Commercial Usage Detection and Enforcement

  Routes users based on usage patterns:
  - Personal use: Full access to open-source features
  - Commercial evaluation: Time-limited trial
  - Commercial licensed: Full SaaS features
  - Unlicensed commercial: Redirect to licensing page
  """

  require Logger
  use Plug.Router

  # SaaS configuration
  @saas_base_url "https://app.armoricore.com"
  @licensing_url "https://fastcomcorp.com/licensing"
  @trial_duration_days 30
  @grace_period_hours 24

  plug :match
  plug :dispatch

  # Main routing logic
  get "/" do
    case analyze_usage_context(conn) do
      {:personal, _context} ->
        # Allow full access for personal use
        forward_to_application(conn, "personal")

      {:commercial_evaluation, context} ->
        # Allow trial access
        serve_trial_page(conn, context)

      {:commercial_licensed, context} ->
        # Allow full SaaS access
        forward_to_saas(conn, context)

      {:commercial_unlicensed, context} ->
        # Block and redirect to licensing
        serve_licensing_page(conn, context)

      {:error, reason} ->
        serve_error_page(conn, reason)
    end
  end

  post "/api/*_path" do
    case analyze_usage_context(conn) do
      {:personal, _} ->
        forward_to_application(conn, "personal")

      {:commercial_licensed, _} ->
        forward_to_saas(conn, "licensed")

      _ ->
        # Block commercial API usage without license
        send_resp(conn, 402, Jason.encode!(%{
          error: "Commercial API usage requires licensing",
          licensing_url: @licensing_url,
          contact: "licensing@fastcomcorp.com"
        }))
    end
  end

  # Catch-all route
  match _ do
    case analyze_usage_context(conn) do
      {:personal, _} ->
        forward_to_application(conn, "personal")

      {:commercial_licensed, _} ->
        forward_to_saas(conn, "licensed")

      _ ->
        serve_licensing_page(conn, %{})
    end
  end

  # Usage analysis functions

  defp analyze_usage_context(conn) do
    try do
      context = %{
        ip_address: get_client_ip(conn),
        user_agent: get_user_agent(conn),
        domain: get_domain(conn),
        timestamp: DateTime.utc_now(),
        request_count: get_request_count(conn),
        concurrent_users: get_concurrent_users(),
        commercial_indicators: detect_commercial_indicators(conn)
      }

      # Analyze context to determine usage type
      determine_usage_type(context)

    rescue
      error ->
        Logger.error("Failed to analyze usage context: #{inspect(error)}")
        {:error, :analysis_failed}
    end
  end

  defp determine_usage_type(context) do
    # Check for existing license
    case check_existing_license(context) do
      {:licensed, license_info} ->
        {:commercial_licensed, Map.put(context, :license, license_info)}

      :evaluation_active ->
        {:commercial_evaluation, Map.put(context, :trial_remaining, calculate_trial_remaining(context))}

      :evaluation_expired ->
        {:commercial_unlicensed, Map.put(context, :reason, :trial_expired)}

      :no_license ->
        # Analyze usage patterns
        if personal_usage?(context) do
          {:personal, context}
        else
          commercial_score = calculate_commercial_score(context)
          if commercial_score > 5 do
            {:commercial_unlicensed, Map.put(context, :commercial_score, commercial_score)}
          else
            {:personal, context}
          end
        end
    end
  end

  # Detection functions

  defp personal_usage?(context) do
    # Check for personal usage indicators
    personal_indicators = [
      context.concurrent_users <= 5,
      context.request_count < 1000,  # Per day
      not commercial_domain?(context.domain),
      not business_hours_peak?(context.timestamp),
      not revenue_indicators?(context)
    ]

    # Must have majority of personal indicators
    personal_count = Enum.count(personal_indicators, & &1)
    total_indicators = length(personal_indicators)

    personal_count >= (total_indicators / 2)
  end

  defp calculate_commercial_score(context) do
    score = 0

    # High concurrent users
    score = score + if context.concurrent_users > 50, do: 3, else: 0

    # High request volume
    score = score + if context.request_count > 10000, do: 2, else: 0

    # Commercial domain
    score = score + if commercial_domain?(context.domain), do: 2, else: 0

    # Business hours usage
    score = score + if business_hours_peak?(context.timestamp), do: 1, else: 0

    # Commercial indicators
    score = score + length(context.commercial_indicators)

    score
  end

  defp commercial_domain?(domain) do
    commercial_patterns = [
      ~r/\.com$/,
      ~r/\.net$/,
      ~r/corp/i,
      ~r/company/i,
      ~r/enterprise/i,
      ~r/business/i
    ]

    Enum.any?(commercial_patterns, &Regex.match?(&1, domain || ""))
  end

  defp business_hours_peak?(timestamp) do
    # Check if request is during business hours (9 AM - 6 PM)
    hour = timestamp.hour
    weekday = Date.day_of_week(timestamp)

    # Business hours: Monday-Friday, 9 AM - 6 PM
    weekday in 1..5 and hour in 9..17
  end

  defp revenue_indicators?(context) do
    # Check for revenue-related indicators
    revenue_indicators = [
      String.contains?(context.user_agent || "", "payment"),
      String.contains?(context.user_agent || "", "stripe"),
      String.contains?(context.user_agent || "", "paypal"),
      context.request_count > 5000  # High volume suggests commercial use
    ]

    Enum.any?(revenue_indicators)
  end

  defp detect_commercial_indicators(conn) do
    indicators = []

    # Check headers for commercial indicators
    headers = get_req_headers(conn)

    # API key usage
    if headers["authorization"] && String.starts_with?(headers["authorization"], "Bearer sk_") do
      indicators = [:api_key_usage | indicators]
    end

    # Custom domains
    if headers["origin"] && not String.contains?(headers["origin"], "localhost") do
      indicators = [:custom_domain | indicators]
    end

    # Enterprise user agents
    if headers["user-agent"] && String.contains?(headers["user-agent"], "Enterprise") do
      indicators = [:enterprise_user_agent | indicators]
    end

    indicators
  end

  # License checking functions

  defp check_existing_license(context) do
    # Check for license key in headers or database
    license_key = get_req_header(context.conn || %{}, "x-license-key")

    if license_key do
      # Validate license key
      case validate_license_key(license_key, context) do
        {:valid, license_info} -> {:licensed, license_info}
        {:expired, _} -> :evaluation_expired
        {:invalid, _} -> :no_license
      end
    else
      :no_license
    end
  end

  defp validate_license_key(key, context) do
    # In practice, this would validate against a license server
    # For demonstration, we'll simulate license validation

    cond do
      String.starts_with?(key, "trial_") ->
        # Trial license - check if expired
        trial_start = get_trial_start_date(key)
        trial_end = DateTime.add(trial_start, @trial_duration_days, :day)

        if DateTime.compare(DateTime.utc_now(), trial_end) == :lt do
          {:valid, %{type: :trial, expires: trial_end}}
        else
          {:expired, trial_end}
        end

      String.starts_with?(key, "commercial_") ->
        # Commercial license - assume valid
        {:valid, %{type: :commercial, tier: :enterprise}}

      true ->
        {:invalid, :unknown_format}
    end
  end

  defp get_trial_start_date(key) do
    # Extract trial start date from key (simplified)
    # In practice, this would decode the license key
    DateTime.utc_now() |> DateTime.add(-15, :day)  # 15 days ago
  end

  defp calculate_trial_remaining(context) do
    # Calculate remaining trial time
    trial_start = DateTime.utc_now() |> DateTime.add(-15, :day)
    trial_end = DateTime.add(trial_start, @trial_duration_days, :day)
    remaining_seconds = DateTime.diff(trial_end, DateTime.utc_now())

    if remaining_seconds > 0 do
      days = div(remaining_seconds, 86400)
      hours = div(rem(remaining_seconds, 86400), 3600)
      "#{days} days, #{hours} hours"
    else
      "expired"
    end
  end

  # Response functions

  defp serve_trial_page(conn, context) do
    trial_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Armoricore - Trial Access</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .trial-banner { background: #e3f2fd; border: 2px solid #2196f3; padding: 20px; border-radius: 10px; margin: 20px auto; max-width: 600px; }
            .upgrade-button { background: #4caf50; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px; margin: 10px; }
        </style>
    </head>
    <body>
        <h1>🚀 Welcome to Armoricore!</h1>
        <div class="trial-banner">
            <h2>Commercial Trial Active</h2>
            <p>You have <strong>#{context.trial_remaining}</strong> remaining in your trial.</p>
            <p>Experience all enterprise features free for 30 days.</p>
        </div>

        <a href="#{continue_to_app_url()}" class="upgrade-button">Continue to Armoricore</a>
        <br><br>
        <a href="#{@licensing_url}" class="upgrade-button">Upgrade to Commercial License</a>

        <p style="margin-top: 30px; color: #666;">
            Trial includes: Unlimited users, Enterprise features, Priority support
        </p>
    </body>
    </html>
    """

    send_resp(conn, 200, trial_html)
  end

  defp serve_licensing_page(conn, context) do
    commercial_score = Map.get(context, :commercial_score, 0)

    licensing_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Armoricore - Commercial Licensing Required</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .license-banner { background: #fff3cd; border: 2px solid #ffc107; padding: 20px; border-radius: 10px; margin: 20px auto; max-width: 600px; }
            .license-button { background: #2196f3; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px; margin: 10px; }
            .personal-button { background: #4caf50; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px; margin: 10px; }
        </style>
    </head>
    <body>
        <h1>💼 Commercial License Required</h1>

        <div class="license-banner">
            <h2>Commercial Usage Detected</h2>
            <p>Our analysis indicates commercial usage of Armoricore.</p>
            <p><strong>Commercial Score: #{commercial_score}/10</strong></p>
            <p>A commercial license is required for business use.</p>
        </div>

        <a href="#{@licensing_url}" class="license-button">Get Commercial License</a>
        <br><br>
        <a href="#{personal_use_url()}" class="personal-button">Personal Use Only</a>

        <h3>Why Commercial License?</h3>
        <ul style="text-align: left; max-width: 600px; margin: 20px auto;">
            <li>✅ Unlimited commercial usage</li>
            <li>✅ Priority technical support</li>
            <li>✅ Enterprise security features</li>
            <li>✅ SLA guarantees</li>
            <li>✅ Custom development</li>
        </ul>

        <h3>Licensing Options</h3>
        <div style="display: flex; justify-content: center; gap: 20px; flex-wrap: wrap;">
            <div style="border: 1px solid #ddd; padding: 20px; border-radius: 5px; min-width: 200px;">
                <h4>Small Business</h4>
                <p style="font-size: 24px; font-weight: bold;">$4,999/year</p>
                <p>Up to 100 users</p>
            </div>
            <div style="border: 1px solid #ddd; padding: 20px; border-radius: 5px; min-width: 200px;">
                <h4>Enterprise</h4>
                <p style="font-size: 24px; font-weight: bold;">$24,999/year</p>
                <p>Up to 1,000 users</p>
            </div>
            <div style="border: 1px solid #ddd; padding: 20px; border-radius: 5px; min-width: 200px;">
                <h4>Unlimited</h4>
                <p style="font-size: 24px; font-weight: bold;">$99,999/year</p>
                <p>Unlimited users</p>
            </div>
        </div>

        <p style="margin-top: 30px; color: #666;">
            Questions? Contact <a href="mailto:licensing@fastcomcorp.com">licensing@fastcomcorp.com</a>
        </p>
    </body>
    </html>
    """

    send_resp(conn, 402, licensing_html)
  end

  defp serve_error_page(conn, reason) do
    error_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Armoricore - Service Error</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
            .error-banner { background: #f8d7da; border: 2px solid #dc3545; padding: 20px; border-radius: 10px; margin: 20px auto; max-width: 600px; }
        </style>
    </head>
    <body>
        <h1>⚠️ Service Temporarily Unavailable</h1>
        <div class="error-banner">
            <h2>Analysis Error</h2>
            <p>Unable to analyze usage context: #{reason}</p>
            <p>Please try again or contact support.</p>
        </div>
        <p><a href="mailto:support@fastcomcorp.com">Contact Support</a></p>
    </body>
    </html>
    """

    send_resp(conn, 503, error_html)
  end

  # Forwarding functions

  defp forward_to_application(conn, tier) do
    # Forward to open-source application
    headers = [{"x-usage-tier", tier} | conn.req_headers]
    %{conn | req_headers: headers}
    |> ArmoricoreWeb.Endpoint.call(%{})
  end

  defp forward_to_saas(conn, tier) do
    # Forward to SaaS application
    saas_url = "#{@saas_base_url}#{conn.request_path}?#{conn.query_string}"
    redirect(conn, saas_url)
  end

  # Helper functions

  defp get_client_ip(conn) do
    # Get real client IP (considering proxies)
    forwarded_for = get_req_header(conn, "x-forwarded-for")
    if forwarded_for do
      String.split(forwarded_for, ",") |> List.first() |> String.trim()
    else
      conn.remote_ip |> :inet.ntoa() |> to_string()
    end
  end

  defp get_user_agent(conn) do
    get_req_header(conn, "user-agent")
  end

  defp get_domain(conn) do
    case get_req_header(conn, "host") do
      host when is_binary(host) ->
        # Extract domain from host header
        host |> String.split(":") |> List.first()
      _ -> nil
    end
  end

  defp get_request_count(conn) do
    # Get request count for this client (simplified)
    # In practice, this would check a database/cache
    100  # Placeholder
  end

  defp get_concurrent_users do
    # Get current concurrent user count
    # In practice, this would check active connections
    25  # Placeholder
  end

  defp continue_to_app_url do
    # URL to continue to the application
    "/app"
  end

  defp personal_use_url do
    # URL for personal use documentation
    "https://docs.fastcomcorp.com/personal-use"
  end

  # Module functions for external use

  @doc """
  Analyze usage context for any request
  """
  @spec analyze_request(map()) :: {:ok, map()} | {:error, atom()}
  def analyze_request(request_data) do
    # Convert request data to conn-like structure
    mock_conn = %{
      remote_ip: request_data[:ip_address] || {127, 0, 0, 1},
      req_headers: request_data[:headers] || []
    }

    analyze_usage_context(mock_conn)
  end

  @doc """
  Get licensing recommendations for detected usage
  """
  @spec get_licensing_recommendation(map()) :: map()
  def get_licensing_recommendation(context) do
    case analyze_usage_context(context) do
      {:personal, _} ->
        %{recommended: :personal_use, reason: "Usage patterns indicate personal use"}

      {:commercial_evaluation, _} ->
        %{recommended: :trial_extension, reason: "Trial period active"}

      {:commercial_licensed, license} ->
        %{recommended: :current_license, license: license}

      {:commercial_unlicensed, analysis} ->
        commercial_score = Map.get(analysis, :commercial_score, 0)
        recommended_tier = cond do
          commercial_score <= 3 -> :small_business
          commercial_score <= 7 -> :enterprise
          true -> :unlimited
        end

        %{
          recommended: recommended_tier,
          commercial_score: commercial_score,
          reason: "Commercial usage detected without valid license"
        }

      {:error, reason} ->
        %{error: reason}
    end
  end
end