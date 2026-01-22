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
# Licensed under the Fastcomcorp Commercial License.
# See LICENSE file for complete terms and conditions.
#
# For commercial licensing: licensing@fastcomcorp.com
# For personal use: Free under Fastcomcorp Commercial License terms

defmodule ArmoricoreRealtime.MixProject do
  use Mix.Project

  def project do
    [
      app: :armoricore_realtime,
      version: "1.0.0",
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      compilers: [:phoenix_live_view] ++ Mix.compilers(),
      listeners: [Phoenix.CodeReloader],
      description: "Secure communications platform with post-quantum cryptography",
      package: package()
    ]
  end

  defp package do
    [
      licenses: ["Fastcomcorp Commercial License"],
      links: %{
        "GitHub" => "https://github.com/Fastcomcorp/Armoricore",
        "Homepage" => "https://fastcomcorp.com",
        "Commercial Licensing" => "https://fastcomcorp.com/licensing"
      },
      maintainers: ["Francisco F. Pinochet", "Fastcomcorp, LLC"]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {ArmoricoreRealtime.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:phoenix, "~> 1.8.2"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:phoenix_live_view, "~> 1.1.0"},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:esbuild, "~> 0.10", runtime: Mix.env() == :dev},
      {:tailwind, "~> 0.3", runtime: Mix.env() == :dev},
      {:heroicons,
       github: "tailwindlabs/heroicons",
       tag: "v2.2.0",
       sparse: "optimized",
       app: false,
       compile: false,
       depth: 1},
      {:telemetry_metrics, "~> 1.0"},
      {:telemetry_poller, "~> 1.0"},
      {:phoenix_live_dashboard, "~> 0.8"},
      {:jason, "~> 1.2"},
      {:dns_cluster, "~> 0.2.0"},
      {:bandit, "~> 1.5"},
      {:gnat, "~> 1.6"},
      {:joken, "~> 2.6"},
      {:uuid, "~> 1.1"},
      {:httpoison, "~> 2.0"},
      # Database
      {:ecto_sql, "~> 3.10"},
      {:postgrex, "~> 0.18"},
      # Password hashing
      {:bcrypt_elixir, "~> 3.0"},
      # gRPC client for Rust media engine
      {:grpc, "~> 0.6"},
      {:protobuf, "~> 0.11"},
      # GenStage for backpressure and pipelines
      {:gen_stage, "~> 1.2"},
      # Redis for distributed rate limiting
      {:redix, "~> 1.2", optional: true},
      # Cryptographic libraries for secure communications
      # {:libsodium, "~> 2.0", optional: true},
      # {:enacl, "~> 1.2"},
      # Post-quantum cryptography (when NIFs are available)
      # {:pqclean, "~> 0.1.0", optional: true},  # Kyber, Dilithium, Falcon
      # Secure random generation
      {:crypto_rand, "~> 1.0"},
      # Base64 URL encoding for tokens
      {:base64url, "~> 1.0"}
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to install project dependencies and perform other setup tasks, run:
  #
  #     $ mix setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      setup: ["deps.get", "assets.setup", "assets.build"],
      "assets.setup": ["tailwind.install --if-missing", "esbuild.install --if-missing"],
      "assets.build": ["compile", "tailwind armoricore_realtime", "esbuild armoricore_realtime"],
      "assets.deploy": [
        "tailwind armoricore_realtime --minify",
        "esbuild armoricore_realtime --minify",
        "phx.digest"
      ],
      precommit: ["compile --warnings-as-errors", "deps.unlock --unused", "format", "test"]
    ]
  end
end
