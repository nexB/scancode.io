# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/aboutcode-org/scancode.io
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
# Visit https://github.com/aboutcode-org/scancode.io for support and download.

from scanpipe.models import DiscoveredDependency
from scanpipe.pipelines.scan_codebase import ScanCodebase
from scanpipe.pipes import resolve


class LoadSBOM(ScanCodebase):
    """
    Load package data from one or more SBOMs.

    Supported SBOMs:
    - SPDX document
    - CycloneDX BOM
    Other formats:
    - AboutCode .ABOUT files for package curations.
    """

    @classmethod
    def steps(cls):
        return (
            cls.copy_inputs_to_codebase_directory,
            cls.extract_archives,
            cls.collect_and_create_codebase_resources,
            cls.flag_empty_files,
            cls.flag_ignored_resources,
            cls.get_sbom_inputs,
            cls.get_data_from_sboms,
            cls.create_packages_from_sboms,
            cls.create_dependencies_from_sboms,
        )

    def get_sbom_inputs(self):
        """Locate all the SBOMs among the codebase resources."""
        self.manifest_resources = resolve.get_manifest_resources(self.project)

    def get_data_from_sboms(self):
        """Get packages data from SBOMs."""
        self.packages, self.dependencies = resolve.get_data_from_manifests(
            project=self.project,
            package_registry=resolve.sbom_registry,
            manifest_resources=self.manifest_resources,
            model="get_data_from_sboms",
        )

    def create_packages_from_sboms(self):
        """Create the packages declared in the SBOMs."""
        resolve.create_packages_and_dependencies(
            project=self.project,
            packages=self.packages,
        )

    def create_dependencies_from_sboms(self):
        """Create the dependency relationship declared in the SBOMs."""
        # TODO: Migrate the CycloneDX behavior too, see get_dependencies_from_manifest
        resolve.create_dependencies_from_packages_extra_data(project=self.project)

        for dependency_data in self.dependencies:
            DiscoveredDependency.create_from_data(
                project=self.project,
                dependency_data=dependency_data,
            )
