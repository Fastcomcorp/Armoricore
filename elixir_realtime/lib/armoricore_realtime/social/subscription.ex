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

defmodule ArmoricoreRealtime.Social.Subscription do
  @moduledoc """
  User subscription schema.
  Tracks which users subscribe to which channels/users.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "user_subscriptions" do
    field :notifications_enabled, :boolean, default: true
    belongs_to :subscriber, ArmoricoreRealtime.Accounts.User, foreign_key: :subscriber_id
    belongs_to :subscribed_to, ArmoricoreRealtime.Accounts.User, foreign_key: :subscribed_to_id

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(subscription, attrs) do
    subscription
    |> cast(attrs, [:subscriber_id, :subscribed_to_id, :notifications_enabled])
    |> validate_required([:subscriber_id, :subscribed_to_id])
    |> validate_no_self_subscription()
    |> unique_constraint([:subscriber_id, :subscribed_to_id], name: :subscriptions_unique)
  end

  defp validate_no_self_subscription(changeset) do
    subscriber_id = get_field(changeset, :subscriber_id)
    subscribed_to_id = get_field(changeset, :subscribed_to_id)

    if subscriber_id && subscribed_to_id && subscriber_id == subscribed_to_id do
      add_error(changeset, :subscribed_to_id, "cannot subscribe to yourself")
    else
      changeset
    end
  end
end

