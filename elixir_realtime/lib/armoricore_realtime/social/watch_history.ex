# Copyright 2025 Francisco F. Pinochet
# Copyright 2026 Fastcomcorp
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

defmodule ArmoricoreRealtime.Social.WatchHistory do
  @moduledoc """
  Watch history schema.
  Tracks user viewing progress for videos.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "watch_history" do
    field :watch_progress, :integer, default: 0  # Seconds watched
    field :watch_percentage, :float, default: 0.0  # 0.0 to 1.0
    field :completed, :boolean, default: false
    field :last_watched_at, :utc_datetime
    belongs_to :user, ArmoricoreRealtime.Accounts.User
    belongs_to :video, ArmoricoreRealtime.Content.Video

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(watch_history, attrs) do
    watch_history
    |> cast(attrs, [:user_id, :video_id, :watch_progress, :watch_percentage, :completed, :last_watched_at])
    |> validate_required([:user_id, :video_id, :last_watched_at])
    |> validate_number(:watch_progress, greater_than_or_equal_to: 0)
    |> validate_number(:watch_percentage, greater_than_or_equal_to: 0.0, less_than_or_equal_to: 1.0)
    |> unique_constraint([:user_id, :video_id], name: :watch_history_user_video_unique)
  end
end

