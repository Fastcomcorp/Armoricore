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

defmodule ArmoricoreRealtime.Media.MediaFile do
  @moduledoc """
  Media file schema.
  """

  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "media" do
    field :original_filename, :string
    field :content_type, :string
    field :file_size, :integer
    field :duration, :integer
    field :resolution, :string
    field :status, :string, default: "processing"
    field :playback_urls, :map, default: %{}
    field :thumbnail_urls, :map, default: %{}
    field :metadata, :map, default: %{}
    field :error_message, :string

    belongs_to :user, ArmoricoreRealtime.Accounts.User

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(media_file, attrs) do
    media_file
    |> cast(attrs, [
      :user_id,
      :original_filename,
      :content_type,
      :file_size,
      :duration,
      :resolution,
      :status,
      :playback_urls,
      :thumbnail_urls,
      :metadata,
      :error_message
    ])
    |> validate_required([:user_id, :original_filename, :content_type, :file_size, :status])
    |> validate_inclusion(:status, ["processing", "ready", "failed"])
  end
end
