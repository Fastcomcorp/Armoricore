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

defmodule ArmoricoreRealtimeWeb.ConnCase do
  @moduledoc """
  This module defines the test case to be used by
  tests that require setting up a connection.

  Such tests rely on `Phoenix.ConnTest` and also
  import other functionality to make it easier
  to build common data structures and query the data layer.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use ArmoricoreRealtimeWeb.ConnCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      # The default endpoint for testing
      @endpoint ArmoricoreRealtimeWeb.Endpoint

      use ArmoricoreRealtimeWeb, :verified_routes

      # Import conveniences for testing with connections
      import Plug.Conn
      import Phoenix.ConnTest
      import ArmoricoreRealtimeWeb.ConnCase
    end
  end

  setup tags do
    # Start database sandbox for each test
    # Use start_owner for controller tests to allow controller process to access DB
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(
      ArmoricoreRealtime.Repo,
      shared: not tags[:async]
    )
    
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
    
    # Allow the endpoint process to access the sandbox
    # This is critical for Phoenix controller tests where the endpoint runs in a different process
    Ecto.Adapters.SQL.Sandbox.mode(ArmoricoreRealtime.Repo, {:shared, self()})
    
    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end

  @doc """
  Builds an authenticated connection for testing.
  """
  def build_authenticated_conn(conn, user) do
    alias ArmoricoreRealtime.Auth
    import Plug.Conn
    user_id_str = to_string(user.id)
    {:ok, tokens} = Auth.generate_tokens(user_id_str)
    put_req_header(conn, "authorization", "Bearer #{tokens.access_token}")
  end
end
