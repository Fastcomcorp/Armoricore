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

defmodule ArmoricoreRealtime.Audit do
  @moduledoc """
  Audit logging context for security and analytics.
  """

  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Audit.Log

  @doc """
  Logs an audit event.
  """
  def log_event(attrs) do
    %Log{}
    |> Log.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Logs authentication events.
  """
  def log_auth_event(user_id, action, success, metadata \\ %{}) do
    log_event(%{
      user_id: user_id,
      event_type: "authentication",
      action: action,
      success: success,
      metadata: metadata
    })
  end

  @doc """
  Logs token events.
  """
  def log_token_event(user_id, action, success, metadata \\ %{}) do
    log_event(%{
      user_id: user_id,
      event_type: "token",
      resource_type: "token",
      action: action,
      success: success,
      metadata: metadata
    })
  end

  @doc """
  Logs user events.
  """
  def log_user_event(user_id, action, resource_id, success, metadata \\ %{}) do
    log_event(%{
      user_id: user_id,
      event_type: "user",
      resource_type: "user",
      resource_id: resource_id,
      action: action,
      success: success,
      metadata: metadata
    })
  end

  @doc """
  Gets audit logs for a user.
  """
  def get_user_logs(user_id, limit \\ 100) do
    import Ecto.Query

    from(l in Log,
      where: l.user_id == ^user_id,
      order_by: [desc: l.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end
end
