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

defmodule ArmoricoreRealtime.Content.Category do
  @moduledoc """
  Category schema for organizing videos.
  Supports nested categories via parent_id.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "categories" do
    field :name, :string
    field :slug, :string
    field :description, :string
    belongs_to :parent, ArmoricoreRealtime.Content.Category
    has_many :children, ArmoricoreRealtime.Content.Category, foreign_key: :parent_id
    has_many :videos, ArmoricoreRealtime.Content.Video

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(category, attrs) do
    category
    |> cast(attrs, [:name, :slug, :description, :parent_id])
    |> validate_required([:name])
    |> validate_length(:name, max: 100)
    |> generate_slug()
    |> validate_required([:slug])
    |> validate_length(:slug, max: 100)
    |> unique_constraint(:slug)
  end

  defp generate_slug(changeset) do
    case get_change(changeset, :slug) do
      nil ->
        case get_field(changeset, :name) do
          nil -> changeset
          name -> put_change(changeset, :slug, slugify(name))
        end
      _slug ->
        changeset
    end
  end

  defp slugify(name) do
    name
    |> String.downcase()
    |> String.replace(~r/[^\w\s-]/, "")
    |> String.replace(~r/\s+/, "-")
    |> String.trim("-")
  end
end

