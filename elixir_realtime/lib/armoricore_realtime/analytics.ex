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

defmodule ArmoricoreRealtime.Analytics do
  @moduledoc """
  Analytics context for tracking events and metrics.
  """

  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Analytics.Event

  @doc """
  Tracks an analytics event.
  """
  def track_event(attrs) do
    %Event{}
    |> Event.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Tracks media events.
  """
  def track_media_event(user_id, event_type, properties \\ %{}) do
    track_event(%{
      user_id: user_id,
      event_type: event_type,
      event_category: "media",
      properties: properties
    })
  end

  @doc """
  Tracks notification events.
  """
  def track_notification_event(user_id, event_type, properties \\ %{}) do
    track_event(%{
      user_id: user_id,
      event_type: event_type,
      event_category: "notification",
      properties: properties
    })
  end

  @doc """
  Tracks authentication events.
  """
  def track_auth_event(user_id, event_type, properties \\ %{}) do
    track_event(%{
      user_id: user_id,
      event_type: event_type,
      event_category: "authentication",
      properties: properties
    })
  end

  @doc """
  Gets analytics events for a user.
  """
  def get_user_events(user_id, limit \\ 100) do
    import Ecto.Query

    from(e in Event,
      where: e.user_id == ^user_id,
      order_by: [desc: e.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Gets events by category.
  """
  def get_events_by_category(category, limit \\ 100) do
    import Ecto.Query

    from(e in Event,
      where: e.event_category == ^category,
      order_by: [desc: e.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end
end
