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

import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/armoricore_realtime start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :armoricore_realtime, ArmoricoreRealtimeWeb.Endpoint, server: true
end

config :armoricore_realtime, ArmoricoreRealtimeWeb.Endpoint,
  http: [port: String.to_integer(System.get_env("PORT", "4000"))]

# Database configuration
# Only require DATABASE_URL in production
if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: postgresql://user:password@localhost:5432/armoricore_realtime
      """

  config :armoricore_realtime, ArmoricoreRealtime.Repo,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE", "10")),
    ssl: true,
    ssl_opts: [verify: :verify_none]
else
  # For dev and test, use default or environment variable if provided
  if database_url = System.get_env("DATABASE_URL") do
    # Check if connection string requires SSL (cloud databases)
    ssl_enabled = String.contains?(database_url, "sslmode=require") || 
                  String.contains?(database_url, "sslmode=prefer")
    
    repo_config = [
      url: database_url,
      pool_size: String.to_integer(System.get_env("POOL_SIZE", "10"))
    ]
    
    # Add SSL config if needed
    repo_config = if ssl_enabled do
      repo_config ++ [ssl: true, ssl_opts: [verify: :verify_none]]
    else
      repo_config
    end
    
    config :armoricore_realtime, ArmoricoreRealtime.Repo, repo_config
  end
end

# Redis configuration for distributed rate limiting (optional, all environments)
# Set REDIS_URL to enable distributed rate limiting across nodes
# Example: redis://localhost:6379 or redis://user:password@host:6379
if redis_url = System.get_env("REDIS_URL") do
  config :armoricore_realtime, :redis_url, redis_url
end

if config_env() == :prod do
  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"

  config :armoricore_realtime, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  # NATS Message Bus configuration
  # Required for production deployment and ArcRTC integration
  nats_url = System.get_env("NATS_URL") || "nats://localhost:4222"
  nats_token = System.get_env("NATS_TOKEN")

  config :armoricore_realtime, ArmoricoreRealtime.MessageBus,
    url: nats_url,
    token: nats_token,
    connection_name: "armoricore-realtime-prod",
    jetstream_domain: "armoricore"

  # Store NATS configuration for other modules
  config :armoricore_realtime, :nats_url, nats_url
  config :armoricore_realtime, :nats_token, nats_token

  # SSL Configuration - only enable HTTPS if certificates are available
  ssl_config = if System.get_env("SSL_CERT_PATH") && System.get_env("SSL_KEY_PATH") do
    certfile = System.get_env("SSL_CERT_PATH")
    keyfile = System.get_env("SSL_KEY_PATH")
    cafile = System.get_env("SSL_CA_PATH")

    # Verify certificate files exist
    if File.exists?(certfile) && File.exists?(keyfile) do
      ssl_opts = [
        port: 443,
        cipher_suite: :strong,
        certfile: certfile,
        keyfile: keyfile
      ]

      # Add CA bundle if available
      ssl_opts = if cafile && File.exists?(cafile) do
        ssl_opts ++ [cacertfile: cafile]
      else
        ssl_opts
      end

      [https: ssl_opts]
    else
      # Certificates not found, disable HTTPS
      []
    end
  else
    # No SSL configuration provided
    []
  end

  config :armoricore_realtime, ArmoricoreRealtimeWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://hexdocs.pm/bandit/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base
    |> Keyword.merge(ssl_config)
end

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :armoricore_realtime, ArmoricoreRealtimeWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://hexdocs.pm/plug/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :armoricore_realtime, ArmoricoreRealtimeWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.
