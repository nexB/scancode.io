# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/nexB/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/nexB/scancode.io for support and download.

from pipeline import LoopProgress


class XgettextNotFound(Exception):
    pass


def collect_and_store_resource_strings(project, logger=None):
    """
    Collect source strings from codebase files using xgettext and store
    them in the extra data field.
    """
    from source_inspector import strings_xgettext

    if not strings_xgettext.is_xgettext_installed():
        raise XgettextNotFound(
            "``xgettext`` not found. Install ``gettext`` to use this pipeline."
        )

    project_files = project.codebaseresources.files()

    resources = project_files.filter(
        is_binary=False,
        is_archive=False,
        is_media=False,
    )

    resources_count = resources.count()

    resource_iterator = resources.iterator(chunk_size=2000)
    progress = LoopProgress(resources_count, logger)

    for resource in progress.iter(resource_iterator):
        _collect_and_store_resource_strings(resource)


def _collect_and_store_resource_strings(resource):
    """
    Collect strings from a resource using xgettext and store
    them in the extra data field.
    """
    from source_inspector import strings_xgettext

    result = strings_xgettext.collect_strings(resource.location)
    strings = [item["string"] for item in result if "string" in item]
    resource.update_extra_data({"source_strings": strings})
