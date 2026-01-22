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

defmodule ArmoricoreRealtime.AccountsTest do
  use ExUnit.Case, async: true
  use ArmoricoreRealtimeWeb.ConnCase

  alias ArmoricoreRealtime.Accounts
  alias ArmoricoreRealtime.Accounts.User
  alias ArmoricoreRealtime.Repo

  @valid_attrs %{
    email: "test@example.com",
    password: "StrongPassword123!",
    password_confirmation: "StrongPassword123!",
    username: "testuser",
    first_name: "Test",
    last_name: "User"
  }

  @invalid_attrs %{
    email: "invalid-email",
    password: "short",
    username: ""
  }

  setup do
    # Clean up any existing test data
    Repo.delete_all(User)
    :ok
  end

  describe "register_user/1" do
    test "creates a user with valid attributes" do
      assert {:ok, %User{} = user} = Accounts.register_user(@valid_attrs)
      assert user.email == @valid_attrs.email
      assert user.username == @valid_attrs.username
      assert user.first_name == @valid_attrs.first_name
      assert user.last_name == @valid_attrs.last_name
      assert user.is_verified == false
      assert user.is_active == true
      assert user.password_hash != nil
      assert user.password_hash != @valid_attrs.password
    end

    test "rejects invalid email" do
      attrs = Map.put(@valid_attrs, :email, "invalid-email")
      assert {:error, %Ecto.Changeset{} = changeset} = Accounts.register_user(attrs)
      assert "has invalid format" in errors_on(changeset).email |> List.first()
    end

    test "rejects short password" do
      attrs = Map.put(@valid_attrs, :password, "short")
      assert {:error, %Ecto.Changeset{} = changeset} = Accounts.register_user(attrs)
      assert "should be at least 8 character(s)" in errors_on(changeset).password |> List.first()
    end

    test "rejects duplicate email" do
      assert {:ok, %User{}} = Accounts.register_user(@valid_attrs)
      assert {:error, %Ecto.Changeset{} = changeset} = Accounts.register_user(@valid_attrs)
      assert "has already been taken" in errors_on(changeset).email |> List.first()
    end

    test "rejects duplicate username" do
      assert {:ok, %User{}} = Accounts.register_user(@valid_attrs)
      attrs = Map.put(@valid_attrs, :email, "different@example.com")
      assert {:error, %Ecto.Changeset{} = changeset} = Accounts.register_user(attrs)
      assert "has already been taken" in errors_on(changeset).username |> List.first()
    end

    test "hashes password" do
      {:ok, user} = Accounts.register_user(@valid_attrs)
      assert user.password_hash != @valid_attrs.password
      assert Bcrypt.verify_pass(@valid_attrs.password, user.password_hash)
    end
  end

  describe "authenticate_user/2" do
    test "authenticates user with valid credentials" do
      {:ok, user} = Accounts.register_user(@valid_attrs)
      assert {:ok, authenticated_user} = Accounts.authenticate_user(@valid_attrs.email, @valid_attrs.password)
      assert authenticated_user.id == user.id
      assert authenticated_user.email == user.email
    end

    test "rejects invalid password" do
      {:ok, _user} = Accounts.register_user(@valid_attrs)
      assert {:error, :invalid_credentials} = Accounts.authenticate_user(@valid_attrs.email, "wrong_password")
    end

    test "rejects non-existent email" do
      assert {:error, :invalid_credentials} = Accounts.authenticate_user("nonexistent@example.com", "password123")
    end

    test "rejects inactive account" do
      {:ok, user} = Accounts.register_user(@valid_attrs)
      Accounts.deactivate_user(user)
      assert {:error, :account_inactive} = Accounts.authenticate_user(@valid_attrs.email, @valid_attrs.password)
    end
  end

  describe "get_user/1" do
    test "gets user by id" do
      {:ok, user} = Accounts.register_user(@valid_attrs)
      assert %User{} = Accounts.get_user(user.id)
      assert Accounts.get_user(user.id).email == @valid_attrs.email
    end

    test "returns nil for non-existent id" do
      assert Accounts.get_user(Ecto.UUID.generate()) == nil
    end
  end

  describe "get_user_by_email/1" do
    test "gets user by email" do
      {:ok, user} = Accounts.register_user(@valid_attrs)
      assert %User{} = Accounts.get_user_by_email(@valid_attrs.email)
      assert Accounts.get_user_by_email(@valid_attrs.email).id == user.id
    end

    test "returns nil for non-existent email" do
      assert Accounts.get_user_by_email("nonexistent@example.com") == nil
    end
  end

  describe "get_user_by_username/1" do
    test "gets user by username" do
      {:ok, user} = Accounts.register_user(@valid_attrs)
      assert %User{} = Accounts.get_user_by_username(@valid_attrs.username)
      assert Accounts.get_user_by_username(@valid_attrs.username).id == user.id
    end

    test "returns nil for non-existent username" do
      assert Accounts.get_user_by_username("nonexistent") == nil
    end
  end

  describe "update_user/2" do
    test "updates user with valid attributes" do
      {:ok, user} = Accounts.register_user(@valid_attrs)
      update_attrs = %{first_name: "Updated", last_name: "Name"}
      assert {:ok, updated_user} = Accounts.update_user(user, update_attrs)
      assert updated_user.first_name == "Updated"
      assert updated_user.last_name == "Name"
      assert updated_user.email == user.email
    end
  end

  describe "verify_user/1" do
    test "verifies user email" do
      {:ok, user} = Accounts.register_user(@valid_attrs)
      assert user.is_verified == false
      assert {:ok, verified_user} = Accounts.verify_user(user)
      assert verified_user.is_verified == true
    end
  end

  describe "deactivate_user/1 and activate_user/1" do
    test "deactivates and activates user" do
      {:ok, user} = Accounts.register_user(@valid_attrs)
      assert user.is_active == true

      assert {:ok, deactivated_user} = Accounts.deactivate_user(user)
      assert deactivated_user.is_active == false

      assert {:ok, activated_user} = Accounts.activate_user(deactivated_user)
      assert activated_user.is_active == true
    end
  end

  # Helper function to get errors from changeset
  defp errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Enum.reduce(opts, message, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end

