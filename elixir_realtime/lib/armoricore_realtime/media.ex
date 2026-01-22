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

defmodule ArmoricoreRealtime.Media do
  @moduledoc """
  Media context for managing media files and metadata.
  
  This module provides high-level functions for media processing with:
  - Task pool for concurrent processing
  - Priority queue for ordered processing
  - GenStage pipeline for high-volume processing
  - Distributed processing across multiple nodes
  """

  import Ecto.Query
  alias ArmoricoreRealtime.Repo
  alias ArmoricoreRealtime.Media.MediaFile
  alias ArmoricoreRealtime.Media.ProcessorPool
  alias ArmoricoreRealtime.Media.PriorityQueue
  alias ArmoricoreRealtime.Media.Pipeline
  alias ArmoricoreRealtime.Media.Distributed

  @doc """
  Gets a media file by ID.
  """
  def get_media(id), do: Repo.get(MediaFile, id)

  @doc """
  Gets all media files for a user.
  """
  def get_user_media(user_id, limit \\ 50) do
    from(m in MediaFile,
      where: m.user_id == ^user_id,
      order_by: [desc: m.inserted_at],
      limit: ^limit
    )
    |> Repo.all()
  end

  @doc """
  Creates a media record.
  """
  def create_media(attrs) do
    %MediaFile{}
    |> MediaFile.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a media record.
  """
  def update_media(%MediaFile{} = media, attrs) do
    media
    |> MediaFile.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Updates media status.
  """
  def update_media_status(media_id, status, metadata \\ %{}) do
    case get_media(media_id) do
      nil ->
        {:error, :not_found}

      media ->
        attrs = Map.merge(metadata, %{status: status})
        update_media(media, attrs)
    end
  end

  @doc """
  Process multiple videos concurrently using task pool.
  
  ## Parameters
  - `videos` - List of video maps with `:media_id`, `:file_path`, `:content_type`, and optional `:priority`
  - `opts` - Options for processing (see `ProcessorPool.process_batch/2`)
  
  ## Returns
  - List of results
  """
  def process_batch(videos, opts \\ []) do
    ProcessorPool.process_batch(videos, opts)
  end

  @doc """
  Process videos using async stream for better backpressure control.
  
  ## Parameters
  - `videos` - List of video maps
  - `opts` - Options (see `ProcessorPool.process_stream/2`)
  
  ## Returns
  - Stream of results
  """
  def process_stream(videos, opts \\ []) do
    ProcessorPool.process_stream(videos, opts)
  end

  @doc """
  Submit a video to the priority queue for processing.
  
  ## Parameters
  - `video` - Map with `:media_id`, `:file_path`, `:content_type`, and `:priority`
  
  ## Returns
  - `:ok` on success
  """
  def enqueue_video(video) do
    PriorityQueue.enqueue(video)
  end

  @doc """
  Submit a video to the GenStage pipeline.
  
  ## Parameters
  - `video` - Map with video information
  
  ## Returns
  - `:ok` on success
  """
  def submit_to_pipeline(video) do
    Pipeline.submit(video)
  end

  @doc """
  Process videos across the cluster (distributed processing).
  
  ## Parameters
  - `videos` - List of video maps
  - `opts` - Options:
    - `:strategy` - Distribution strategy: `:round_robin`, `:random`, `:least_loaded`
  
  ## Returns
  - List of results
  """
  def process_distributed(videos, opts \\ []) do
    Distributed.process_distributed(videos, opts)
  end

  @doc """
  Get pipeline statistics.
  """
  def pipeline_stats do
    Pipeline.stats()
  end

  @doc """
  Get queue statistics.
  """
  def queue_stats do
    PriorityQueue.stats()
  end

  @doc """
  Get cluster statistics.
  """
  def cluster_stats do
    Distributed.cluster_stats()
  end
end
