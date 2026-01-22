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

defmodule ArmoricoreRealtime.Accounts do
  @moduledoc """
  Accounts context for user management.
  """

  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Accounts.User

  @doc """
  Gets a user by ID.
  """
  def get_user(id), do: Repo.get(User, id)

  @doc """
  Gets a user by email.
  """
  def get_user_by_email(email) when is_binary(email) do
    Repo.get_by(User, email: email)
  end

  @doc """
  Gets a user by username.
  """
  def get_user_by_username(username) when is_binary(username) do
    Repo.get_by(User, username: username)
  end

  @doc """
  Registers a user.
  
  ## Examples
  
      iex> register_user(%{email: "user@example.com", password: "password123"})
      {:ok, %User{}}
      
      iex> register_user(%{email: "invalid"})
      {:error, %Ecto.Changeset{}}
  """
  def register_user(attrs) do
    %User{}
    |> User.registration_changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Authenticates a user by email and password.
  
  ## Examples
  
      iex> authenticate_user("user@example.com", "password123")
      {:ok, %User{}}
      
      iex> authenticate_user("user@example.com", "wrong_password")
      {:error, :invalid_credentials}
  """
  def authenticate_user(email, password) when is_binary(email) and is_binary(password) do
    user = get_user_by_email(email)

    cond do
      user && User.valid_password?(user, password) && user.is_active ->
        # Update last login
        user
        |> User.update_last_login_changeset()
        |> Repo.update()
        
        {:ok, user}

      user && User.valid_password?(user, password) ->
        {:error, :account_inactive}

      user ->
        {:error, :invalid_credentials}

      true ->
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}
    end
  end

  @doc """
  Updates a user.
  """
  def update_user(%User{} = user, attrs) do
    user
    |> User.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Updates user password.
  """
  def update_user_password(user, password, opts \\ []) do
    changeset =
      user
      |> User.password_changeset(%{password: password}, opts)

    Ecto.Multi.new()
    |> Ecto.Multi.update(:user, changeset)
    |> Repo.transaction()
    |> case do
      {:ok, %{user: user}} -> {:ok, user}
      {:error, :user, changeset, _} -> {:error, changeset}
    end
  end

  @doc """
  Deactivates a user account.
  """
  def deactivate_user(%User{} = user) do
    update_user(user, %{is_active: false})
  end

  @doc """
  Activates a user account.
  """
  def activate_user(%User{} = user) do
    update_user(user, %{is_active: true})
  end

  @doc """
  Verifies a user email.
  """
  def verify_user(%User{} = user) do
    update_user(user, %{is_verified: true})
  end
end
