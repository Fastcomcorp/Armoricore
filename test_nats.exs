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

# Test NATS MessageBus functionality
IO.puts("Testing NATS MessageBus...")

# Start the MessageBus
{:ok, _pid} = ArmoricoreRealtime.MessageBus.start_link([])
Process.sleep(2000)  # Wait for connection

# Test status
status = ArmoricoreRealtime.MessageBus.status()
IO.inspect(status, label: "NATS Status")

# Test publish
IO.puts("Testing publish...")
result = ArmoricoreRealtime.MessageBus.publish("test.topic", %{message: "Hello NATS!", timestamp: DateTime.utc_now()})
IO.inspect(result, label: "Publish Result")

# Test subscribe
IO.puts("Testing subscribe...")
callback = fn payload ->
  IO.inspect(payload, label: "Received Message")
end

sub_result = ArmoricoreRealtime.MessageBus.subscribe("test.topic", callback)
IO.inspect(sub_result, label: "Subscribe Result")

# Publish again to test subscription
Process.sleep(100)
IO.puts("Publishing to test subscription...")
pub_result2 = ArmoricoreRealtime.MessageBus.publish("test.topic", %{message: "Hello subscribers!", timestamp: DateTime.utc_now()})
IO.inspect(pub_result2, label: "Second Publish Result")

# Wait for message processing
Process.sleep(1000)

IO.puts("NATS test completed!")