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

defmodule ArmoricoreRealtime.Accounts.User do
  @moduledoc """
  User schema for accounts and profiles.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "users" do
    field :email, :string
    field :password_hash, :string
    field :password, :string, virtual: true, redact: true
    field :password_confirmation, :string, virtual: true, redact: true
    field :username, :string
    field :first_name, :string
    field :last_name, :string
    field :avatar_url, :string
    field :is_active, :boolean, default: true
    field :is_verified, :boolean, default: false
    field :last_login_at, :utc_datetime
    field :metadata, :map, default: %{}

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(user, attrs) do
    user
    |> cast(attrs, [:email, :username, :first_name, :last_name, :avatar_url, :is_active, :is_verified, :metadata])
    |> validate_required([:email])
    |> validate_format(:email, ~r/^[^\s]+@[^\s]+$/, message: "must have the @ sign and no spaces")
    |> validate_length(:email, max: 255)
    |> validate_length(:username, max: 100)
    |> unique_constraint(:email)
    |> unique_constraint(:username)
  end

  @doc """
  Changeset for user registration (includes password).
  """
  def registration_changeset(user, attrs, opts \\ []) do
    user
    |> changeset(attrs)
    |> cast(attrs, [:password])
    |> validate_required([:password])
    |> validate_length(:password, min: 12, max: 72)  # SECURITY: Increased minimum to 12 characters
    |> validate_confirmation(:password, required: true)
    |> validate_password_strength()  # SECURITY: Added password strength validation
    |> maybe_hash_password(opts)
  end

  @doc """
  Changeset for password updates.
  """
  def password_changeset(user, attrs, opts \\ []) do
    user
    |> cast(attrs, [:password])
    |> validate_confirmation(:password, required: true)
    |> validate_length(:password, min: 12, max: 72)  # SECURITY: Increased minimum to 12 characters
    |> validate_password_strength()  # SECURITY: Added password strength validation
    |> maybe_hash_password(opts)
  end

  defp maybe_hash_password(changeset, opts) do
    hash_password? = Keyword.get(opts, :hash_password, true)
    password = get_change(changeset, :password)

    if hash_password? && password && changeset.valid? do
      changeset
      |> validate_length(:password, min: 8, max: 72)
      |> put_change(:password_hash, Bcrypt.hash_pwd_salt(password))
      |> delete_change(:password)
    else
      changeset
    end
  end

  @doc """
  Verifies the password.
  """
  def valid_password?(%ArmoricoreRealtime.Accounts.User{password_hash: hash}, password)
      when is_binary(hash) and byte_size(password) > 0 do
    Bcrypt.verify_pass(password, hash)
  end

  def valid_password?(_, _) do
    Bcrypt.no_user_verify()
    false
  end

  @doc """
  Updates the last login timestamp.
  """
  def update_last_login_changeset(user) do
    change(user, last_login_at: DateTime.utc_now() |> DateTime.truncate(:second))
  end
  
  # SECURITY: Validate password strength
  defp validate_password_strength(changeset) do
    password = get_change(changeset, :password)
    
    if password do
      errors = []
      
      # Check minimum length (already validated, but double-check)
      errors = if byte_size(password) < 12 do
        [{:password, "must be at least 12 characters"} | errors]
      else
        errors
      end
      
      # Check for lowercase letters
      errors = if not String.match?(password, ~r/[a-z]/) do
        [{:password, "must contain at least one lowercase letter"} | errors]
      else
        errors
      end
      
      # Check for uppercase letters
      errors = if not String.match?(password, ~r/[A-Z]/) do
        [{:password, "must contain at least one uppercase letter"} | errors]
      else
        errors
      end
      
      # Check for numbers
      errors = if not String.match?(password, ~r/[0-9]/) do
        [{:password, "must contain at least one number"} | errors]
      else
        errors
      end
      
      # Check for special characters
      errors = if not String.match?(password, ~r/[^a-zA-Z0-9]/) do
        [{:password, "must contain at least one special character"} | errors]
      else
        errors
      end
      
      # Check against common passwords
      errors = if password in common_passwords() do
        [{:password, "is too common. Please choose a more unique password"} | errors]
      else
        errors
      end
      
      # Add all errors to changeset
      Enum.reduce(errors, changeset, fn {field, message}, acc ->
        add_error(acc, field, message)
      end)
    else
      changeset
    end
  end
  
  # SECURITY: List of common passwords to reject
  defp common_passwords do
    [
      "password", "password123", "Password1", "Password123",
      "12345678", "123456789", "1234567890", "qwerty123",
      "abc123", "monkey123", "1234567", "letmein",
      "trustno1", "dragon", "baseball", "iloveyou",
      "master", "sunshine", "ashley", "bailey",
      "passw0rd", "shadow", "123123", "654321",
      "superman", "qazwsx", "michael", "football"
    ]
  end
end
