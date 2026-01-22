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

defmodule ArmoricoreRealtimeWeb.ErrorHTML do
  @moduledoc """
  This module is invoked by your endpoint in case of errors on HTML requests.

  See config/config.exs.
  """
  use ArmoricoreRealtimeWeb, :html

  # If you want to customize your error pages,
  # uncomment the embed_templates/1 call below
  # and add pages to the error directory:
  #
  #   * lib/armoricore_realtime_web/controllers/error_html/404.html.heex
  #   * lib/armoricore_realtime_web/controllers/error_html/500.html.heex
  #
  # embed_templates "error_html/*"

  # The default is to render a plain text page based on
  # the template name. For example, "404.html" becomes
  # "Not Found".
  def render(template, _assigns) do
    Phoenix.Controller.status_message_from_template(template)
  end
end
