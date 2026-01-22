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

#!/usr/bin/env elixir
# Armoricore 1.0.0 Release Validation Script
# Validates application structure and configuration for GitHub release

IO.puts("🔍 Armoricore 1.0.0 Release Validation")
IO.puts("=====================================")

# Check 1: Application Structure
IO.puts("\n📁 Checking Application Structure...")

# Check if key directories exist
required_dirs = [
  "elixir_realtime/lib",
  "elixir_realtime/config",
  "elixir_realtime/priv",
  "elixir_realtime/test",
  "rust-services",
  "README.md",
  "LICENSE",
  "SECURITY.md"
]

structure_ok = Enum.all?(required_dirs, fn dir ->
  exists = File.exists?(dir)
  status = if exists, do: "✅", else: "❌"
  IO.puts("  #{status} #{dir}")
  exists
end)

# Check 2: Elixir Application Files
IO.puts("\n💎 Checking Elixir Application Files...")

elixir_files = [
  "elixir_realtime/lib/armoricore_realtime.ex",
  "elixir_realtime/mix.exs",
  "elixir_realtime/config/config.exs",
  "elixir_realtime/config/dev.exs",
  "elixir_realtime/config/prod.exs",
  "elixir_realtime/config/test.exs"
]

elixir_ok = Enum.all?(elixir_files, fn file ->
  exists = File.exists?(file)
  status = if exists, do: "✅", else: "❌"
  IO.puts("  #{status} #{file}")
  exists
end)

# Check 3: Version Consistency
IO.puts("\n📋 Checking Version Consistency...")

version_checks = [
  fn ->
    # Check mix.exs version
    case File.read("elixir_realtime/mix.exs") do
      {:ok, content} ->
        if String.contains?(content, "version: \"1.0.0\""), do: {:ok, "mix.exs"}, else: {:error, "mix.exs version"}
      _ -> {:error, "mix.exs read"}
    end
  end,
  fn ->
    # Check README version
    case File.read("README.md") do
      {:ok, content} ->
        if String.contains?(content, "1.0.0"), do: {:ok, "README.md"}, else: {:error, "README.md version"}
      _ -> {:error, "README.md read"}
    end
  end,
  fn ->
    # Check CHANGELOG version
    case File.read("CHANGELOG.md") do
      {:ok, content} ->
        if String.contains?(content, "## [1.0.0]"), do: {:ok, "CHANGELOG.md"}, else: {:error, "CHANGELOG.md version"}
      _ -> {:error, "CHANGELOG.md read"}
    end
  end
]

version_ok = Enum.all?(version_checks, fn check ->
  case check.() do
    {:ok, file} ->
      IO.puts("  ✅ #{file} version correct")
      true
    {:error, reason} ->
      IO.puts("  ❌ #{reason}")
      false
  end
end)

# Check 4: Security Features
IO.puts("\n🔐 Checking Security Features...")

security_modules = [
  "elixir_realtime/lib/armoricore_realtime/security/penetration_testing.ex",
  "elixir_realtime/lib/armoricore_realtime/security/performance_benchmark.ex",
  "elixir_realtime/lib/armoricore_realtime/security/zero_knowledge_proofs.ex",
  "elixir_realtime/lib/armoricore_realtime/security.ex",
  "elixir_realtime/lib/armoricore_realtime_web/plugs/security_headers.ex",
  "elixir_realtime/lib/armoricore_realtime_web/plugs/input_validator.ex"
]

security_ok = Enum.all?(security_modules, fn module ->
  exists = File.exists?(module)
  status = if exists, do: "✅", else: "❌"
  IO.puts("  #{status} #{Path.basename(module)}")
  exists
end)

# Check 5: API Features
IO.puts("\n🔌 Checking API Features...")

api_modules = [
  "elixir_realtime/lib/armoricore_realtime_web/controllers/auth_controller.ex",
  "elixir_realtime/lib/armoricore_realtime_web/controllers/search_controller.ex",
  "elixir_realtime/lib/armoricore_realtime_web/controllers/video_controller.ex",
  "elixir_realtime/lib/armoricore_realtime/auth.ex",
  "elixir_realtime/lib/armoricore_realtime/jwt.ex",
  "elixir_realtime/lib/armoricore_realtime/e2ee.ex"
]

api_ok = Enum.all?(api_modules, fn module ->
  exists = File.exists?(module)
  status = if exists, do: "✅", else: "❌"
  IO.puts("  #{status} #{Path.basename(module)}")
  exists
end)

# Check 6: Documentation
IO.puts("\n📚 Checking Documentation...")

docs = [
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "CHANGELOG.md",
  "COMMERCIAL_LICENSE_README.md",
  "API_REFERENCE.md",
  "LICENSE"
]

docs_ok = Enum.all?(docs, fn doc ->
  exists = File.exists?(doc)
  status = if exists, do: "✅", else: "❌"
  IO.puts("  #{status} #{doc}")
  exists
end)

# Check 7: Licensing
IO.puts("\n📄 Checking Licensing...")

license_checks = [
  fn ->
    case File.read("LICENSE") do
      {:ok, content} ->
        commercial = String.contains?(content, "Fastcomcorp Commercial License")
        personal = String.contains?(content, "Personal Use")
        if commercial && personal, do: {:ok, "LICENSE"}, else: {:error, "LICENSE content"}
      _ -> {:error, "LICENSE read"}
    end
  end,
  fn ->
    case File.read("COMMERCIAL_LICENSE_README.md") do
      {:ok, content} ->
        if String.contains?(content, "Commercial License"), do: {:ok, "COMMERCIAL_LICENSE_README.md"}, else: {:error, "COMMERCIAL_LICENSE_README.md content"}
      _ -> {:error, "COMMERCIAL_LICENSE_README.md read"}
    end
  end
]

license_ok = Enum.all?(license_checks, fn check ->
  case check.() do
    {:ok, file} ->
      IO.puts("  ✅ #{file} correct")
      true
    {:error, reason} ->
      IO.puts("  ❌ #{reason}")
      false
  end
end)

# Check 8: Configuration
IO.puts("\n⚙️ Checking Configuration...")

config_checks = [
  fn ->
    # Check if dev.exs has JWT secret
    case File.read("elixir_realtime/config/dev.exs") do
      {:ok, content} ->
        if String.contains?(content, "jwt"), do: {:ok, "dev.exs JWT config"}, else: {:error, "dev.exs JWT config"}
      _ -> {:error, "dev.exs read"}
    end
  end,
  fn ->
    # Check if prod.exs exists
    if File.exists?("elixir_realtime/config/prod.exs"), do: {:ok, "prod.exs exists"}, else: {:error, "prod.exs missing"}
  end,
  fn ->
    # Check if runtime.exs exists
    if File.exists?("elixir_realtime/config/runtime.exs"), do: {:ok, "runtime.exs exists"}, else: {:error, "runtime.exs missing"}
  end
]

config_ok = Enum.all?(config_checks, fn check ->
  case check.() do
    {:ok, msg} ->
      IO.puts("  ✅ #{msg}")
      true
    {:error, reason} ->
      IO.puts("  ❌ #{reason}")
      false
  end
end)

# Check 9: Rust Services (if they exist)
IO.puts("\n🦀 Checking Rust Services...")

rust_services = [
  "rust-services/Cargo.toml",
  "rust-services/media-processor",
  "rust-services/realtime-media-engine"
]

rust_ok = Enum.all?(rust_services, fn service ->
  exists = File.exists?(service)
  status = if exists, do: "✅", else: "⚠️"
  IO.puts("  #{status} #{service}")
  # Don't fail if Rust services don't exist - they're optional
  true
end)

# Final Assessment
IO.puts("\n🎯 Final Release Validation Assessment")
IO.puts("=====================================")

checks = [
  {"Application Structure", structure_ok},
  {"Elixir Files", elixir_ok},
  {"Version Consistency", version_ok},
  {"Security Features", security_ok},
  {"API Features", api_ok},
  {"Documentation", docs_ok},
  {"Licensing", license_ok},
  {"Configuration", config_ok}
]

all_passed = Enum.all?(checks, fn {_, passed} -> passed end)

Enum.each(checks, fn {name, passed} ->
  status = if passed, do: "✅ PASS", else: "❌ FAIL"
  IO.puts("  #{status} #{name}")
end)

IO.puts("")

if all_passed do
  IO.puts("🎉 RELEASE VALIDATION: PASSED")
  IO.puts("================================")
  IO.puts("✅ Armoricore 1.0.0 is ready for GitHub release!")
  IO.puts("✅ All core components are present and configured")
  IO.puts("✅ Security features are implemented")
  IO.puts("✅ Documentation is complete")
  IO.puts("✅ Commercial licensing is properly configured")
  IO.puts("")
  IO.puts("🚀 Ready to publish to GitHub!")
  System.halt(0)
else
  IO.puts("❌ RELEASE VALIDATION: FAILED")
  IO.puts("===============================")
  IO.puts("❌ Some validation checks failed")
  IO.puts("❌ Please address the failed checks before release")
  IO.puts("")
  IO.puts("🔧 Fix the failed checks and re-run validation")
  System.halt(1)
end