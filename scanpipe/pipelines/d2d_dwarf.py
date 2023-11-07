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

from scanpipe.pipelines.deploy_to_develop import DeployToDevelop
from scanpipe.pipes import d2d
from scanpipe.pipes import input


class DWARF(DeployToDevelop):
    """ELFs and DWARFs."""

    @classmethod
    def steps(cls):
        return (
            cls.get_inputs,
            cls.build_inventory_from_scans,
            cls.flag_ignored_resources,
            cls.map_dwarf_paths,
            cls.flag_mapped_resources_archives_and_ignored_directories,
        )



    def build_inventory_from_scans(self):
        """Build inventories"""
        for input_paths, tag in [(self.from_files, "from"), (self.to_files, "to")]:
            for input_path in input_paths:
                input.load_inventory_from_toolkit_scan(
                    self.project, input_path, resource_defaults={"tag": tag}
                )

    def map_dwarf_paths(self):
        """Map DWARF paths"""
        d2d.map_dwarf_path(project=self.project, logger=self.log)
