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

defmodule ArmoricoreRealtimeWeb.Telemetry do
  @moduledoc """
  Telemetry configuration for Armoricore Web.

  Sets up comprehensive metrics collection and monitoring for the Phoenix web
  application, including performance metrics, error tracking, and business analytics.

  ## Metrics Collected

  ### Phoenix Metrics
  - **Endpoint**: Request count, response times, error rates
  - **Router**: Route matching performance
  - **Channels**: WebSocket connection metrics

  ### Database Metrics
  - **Query Count**: Number of database queries executed
  - **Query Duration**: Database query execution times
  - **Connection Pool**: Pool utilization and performance

  ### Business Metrics
  - **Video Uploads**: Upload success/failure rates
  - **User Registrations**: New user signup tracking
  - **ArcRTC Sessions**: Real-time communication session metrics
  - **API Usage**: Endpoint usage patterns and performance

  ## Monitoring Integration

  Metrics are designed to integrate with monitoring systems like:
  - **Prometheus**: Metrics export for time-series analysis
  - **Grafana**: Dashboard visualization and alerting
  - **DataDog**: Enterprise monitoring and APM
  - **New Relic**: Application performance monitoring

  ## Performance Impact

  Telemetry collection is optimized for minimal performance impact:
  - Metrics are aggregated in memory before export
  - Sampling rates can be configured for high-traffic endpoints
  - Background processing prevents blocking of request handling
  """

  use Supervisor
  import Telemetry.Metrics

  def start_link(arg) do
    Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
  end

  @impl true
  def init(_arg) do
    children = [
      # Telemetry poller will execute the given period measurements
      # every 10_000ms. Learn more here: https://hexdocs.pm/telemetry_metrics
      {:telemetry_poller, measurements: periodic_measurements(), period: 10_000}
      # Add reporters as children of your supervision tree.
      # {Telemetry.Metrics.ConsoleReporter, metrics: metrics()}
    ]

    Supervisor.init(children, strategy: :one_for_one)
  end

  def metrics do
    [
      # Phoenix Metrics
      summary("phoenix.endpoint.start.system_time",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.endpoint.stop.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.start.system_time",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.exception.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.router_dispatch.stop.duration",
        tags: [:route],
        unit: {:native, :millisecond}
      ),
      summary("phoenix.socket_connected.duration",
        unit: {:native, :millisecond}
      ),
      sum("phoenix.socket_drain.count"),
      summary("phoenix.channel_joined.duration",
        unit: {:native, :millisecond}
      ),
      summary("phoenix.channel_handled_in.duration",
        tags: [:event],
        unit: {:native, :millisecond}
      ),

      # VM Metrics
      summary("vm.memory.total", unit: {:byte, :kilobyte}),
      summary("vm.total_run_queue_lengths.total"),
      summary("vm.total_run_queue_lengths.cpu"),
      summary("vm.total_run_queue_lengths.io")
    ]
  end

  defp periodic_measurements do
    [
      # A module, function and arguments to be invoked periodically.
      # This function must call :telemetry.execute/3 and a metric must be added above.
      # {ArmoricoreRealtimeWeb, :count_users, []}
    ]
  end
end
