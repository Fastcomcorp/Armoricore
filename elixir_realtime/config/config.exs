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

# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :armoricore_realtime,
  generators: [timestamp_type: :utc_datetime],
  # Message bus configuration
  message_bus_url: System.get_env("MESSAGE_BUS_URL", "nats://localhost:4222"),
  # JWT configuration
  jwt_secret: System.get_env("JWT_SECRET", "default-secret-change-in-production"),
  # Database configuration
  ecto_repos: [ArmoricoreRealtime.Repo],
  # Media Engine gRPC configuration (read at runtime in MediaEngineClient)
  # Don't use compile_env here - read directly in init/1
  media_engine_grpc_url: "http://localhost:50051",
  # Redis configuration for distributed rate limiting (optional)
  # Set REDIS_URL environment variable to enable (e.g., "redis://localhost:6379")
  redis_url: System.get_env("REDIS_URL")

# Configure the database
config :armoricore_realtime, ArmoricoreRealtime.Repo,
  url: System.get_env("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/armoricore_realtime_dev"),
  pool_size: 10,
  show_sensitive_data_on_connection_error: true

# Configure the endpoint
config :armoricore_realtime, ArmoricoreRealtimeWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: ArmoricoreRealtimeWeb.ErrorHTML, json: ArmoricoreRealtimeWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: ArmoricoreRealtime.PubSub,
  live_view: [signing_salt: "DDQNJESs"]

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.25.4",
  armoricore_realtime: [
    args:
      ~w(js/app.js --bundle --target=es2022 --outdir=../priv/static/assets/js --external:/fonts/* --external:/images/* --alias:@=.),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => [Path.expand("../deps", __DIR__), Mix.Project.build_path()]}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "4.1.12",
  armoricore_realtime: [
    args: ~w(
      --input=assets/css/app.css
      --output=priv/static/assets/css/app.css
    ),
    cd: Path.expand("..", __DIR__)
  ]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message
",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
