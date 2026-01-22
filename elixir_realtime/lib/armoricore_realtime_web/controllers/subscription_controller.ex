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

defmodule ArmoricoreRealtimeWeb.SubscriptionController do
  @moduledoc """
  Controller for subscription operations.
  """

  use ArmoricoreRealtimeWeb, :controller

  alias ArmoricoreRealtime.Social
  alias ArmoricoreRealtime.Repo

  @doc """
  Subscribe to a user/channel (protected endpoint).
  POST /api/v1/subscriptions
  """
  def create(conn, %{"subscribed_to_id" => subscribed_to_id}) do
    user_id = conn.assigns.current_user_id

    case Social.subscribe(user_id, subscribed_to_id) do
      {:ok, subscription} ->
        subscription = Repo.preload(subscription, [:subscriber, :subscribed_to])
        conn
        |> put_status(:created)
        |> json(%{data: serialize_subscription(subscription)})

      {:error, :cannot_subscribe_to_self} ->
        conn
        |> put_status(:bad_request)
        |> json(%{error: "Cannot subscribe to yourself"})

      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{error: "Failed to create subscription", errors: format_errors(changeset)})
    end
  end

  @doc """
  Unsubscribe from a user/channel (protected endpoint).
  DELETE /api/v1/subscriptions/:subscribed_to_id
  """
  def delete(conn, %{"subscribed_to_id" => subscribed_to_id}) do
    user_id = conn.assigns.current_user_id

    case Social.unsubscribe(user_id, subscribed_to_id) do
      {:ok, _subscription} ->
        conn
        |> put_status(:no_content)
        |> json(%{})

      {:error, :not_found} ->
        conn
        |> put_status(:not_found)
        |> json(%{error: "Subscription not found"})
    end
  end

  @doc """
  List user's subscriptions (protected endpoint).
  GET /api/v1/subscriptions
  """
  def index(conn, _params) do
    user_id = conn.assigns.current_user_id
    subscriptions = Social.list_subscriptions(user_id)
    json(conn, %{
      data: Enum.map(subscriptions, &serialize_subscription/1),
      count: length(subscriptions)
    })
  end

  @doc """
  List user's subscribers (protected endpoint).
  GET /api/v1/subscribers
  """
  def subscribers(conn, _params) do
    user_id = conn.assigns.current_user_id
    subscribers = Social.list_subscribers(user_id)
    json(conn, %{
      data: Enum.map(subscribers, &serialize_subscriber/1),
      count: length(subscribers)
    })
  end

  @doc """
  Check if subscribed (protected endpoint).
  GET /api/v1/subscriptions/check/:subscribed_to_id
  """
  def check(conn, %{"subscribed_to_id" => subscribed_to_id}) do
    user_id = conn.assigns.current_user_id
    is_subscribed = Social.is_subscribed?(user_id, subscribed_to_id)
    json(conn, %{subscribed: is_subscribed})
  end

  # Helper functions

  defp format_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end

  defp serialize_subscription(subscription) do
    %{
      id: subscription.id,
      subscriber: serialize_user(subscription.subscriber),
      subscribed_to: serialize_user(subscription.subscribed_to),
      notifications_enabled: subscription.notifications_enabled,
      created_at: subscription.inserted_at
    }
  end

  defp serialize_subscriber(subscription) do
    %{
      id: subscription.id,
      subscriber: serialize_user(subscription.subscriber),
      notifications_enabled: subscription.notifications_enabled,
      created_at: subscription.inserted_at
    }
  end

  defp serialize_user(nil), do: nil
  defp serialize_user(user) do
    %{
      id: user.id,
      username: user.username,
      email: user.email
    }
  end
end

