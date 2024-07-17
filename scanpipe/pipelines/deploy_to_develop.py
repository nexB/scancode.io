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

from scanpipe import pipes
from scanpipe.pipelines import Pipeline
from scanpipe.pipelines import group
from scanpipe.pipes import d2d
from scanpipe.pipes import flag
from scanpipe.pipes import matchcode
from scanpipe.pipes import purldb
from scanpipe.pipes import scancode


class DeployToDevelop(Pipeline):
    """
    Establish relationships between two code trees: deployment and development.

    This pipeline requires a minimum of two archive files, each properly tagged with:

    - **from** for archives containing the development source code.
    - **to** for archives containing the deployment compiled code.

    When using download URLs as inputs, the "from" and "to" tags can be
    provided by adding a "#from" or "#to" fragment at the end of the download URLs.

    When uploading local files:

    - **User Interface:** Use the "Edit flag" link in the "Inputs" panel of the Project
      details view.
    - **REST API:** Utilize the "upload_file_tag" field in addition to the
      "upload_file".
    - **Command Line Interface:** Tag uploaded files using the "filename:tag" syntax,
      for example, ``--input-file path/filename:tag``.
    """

    @classmethod
    def steps(cls):
        return (
            cls.get_inputs,
            cls.extract_inputs_to_codebase_directory,
            cls.extract_archives,
            cls.collect_and_create_codebase_resources,
            cls.fingerprint_codebase_directories,
            cls.flag_empty_files,
            cls.flag_whitespace_files,
            cls.flag_ignored_resources,
            cls.map_about_files,
            cls.map_checksum,
            cls.match_archives_to_purldb,
            cls.find_java_packages,
            cls.map_java_to_class,
            cls.map_jar_to_source,
            cls.map_javascript,
            cls.map_elf,
            cls.map_go,
            cls.match_directories_to_purldb,
            cls.match_resources_to_purldb,
            cls.map_javascript_post_purldb_match,
            cls.map_javascript_path,
            cls.map_javascript_colocation,
            cls.map_thirdparty_npm_packages,
            cls.map_path,
            cls.flag_mapped_resources_archives_and_ignored_directories,
            cls.perform_house_keeping_tasks,
            cls.match_purldb_resources_post_process,
            cls.remove_packages_without_resources,
            cls.scan_unmapped_to_files,
            cls.scan_mapped_from_for_files,
            cls.collect_and_create_license_detections,
            cls.flag_deployed_from_resources_with_missing_license,
            cls.create_local_files_packages,
        )

    purldb_package_extensions = [".jar", ".war", ".zip"]
    purldb_resource_extensions = [
        ".map",
        ".js",
        ".mjs",
        ".ts",
        ".d.ts",
        ".jsx",
        ".tsx",
        ".css",
        ".scss",
        ".less",
        ".sass",
        ".soy",
        ".class",
    ]
    doc_extensions = [
        ".pdf",
        ".doc",
        ".docx",
        ".ppt",
        ".pptx",
        ".tex",
        ".odt",
        ".odp",
    ]

    def get_inputs(self):
        """Locate the ``from`` and ``to`` input files."""
        self.from_files, self.to_files = d2d.get_inputs(self.project)

    def extract_inputs_to_codebase_directory(self):
        """Extract input files to the project's codebase/ directory."""
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project.codebase_path / d2d.FROM),
            (self.to_files, self.project.codebase_path / d2d.TO),
        ]

        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                self.extract_archive(input_file_path, codebase_path)

        # Reload the project env post-extraction as the scancode-config.yml file
        # may be located in one of the extracted archives.
        self.env = self.project.get_env()

    def collect_and_create_codebase_resources(self):
        """Collect and create codebase resources."""
        pipes.collect_and_create_codebase_resources(self.project)

    def fingerprint_codebase_directories(self):
        """Compute directory fingerprints for matching"""
        matchcode.fingerprint_codebase_directories(self.project, to_codebase_only=True)

    def flag_whitespace_files(self):
        """Flag whitespace files with size less than or equal to 100 byte as ignored."""
        d2d.flag_whitespace_files(project=self.project)

    def map_about_files(self):
        """Map ``from/`` .ABOUT files to their related ``to/`` resources."""
        d2d.map_about_files(project=self.project, logger=self.log)

    def map_checksum(self):
        """Map using SHA1 checksum."""
        d2d.map_checksum(project=self.project, checksum_field="sha1", logger=self.log)

    def match_archives_to_purldb(self):
        """Match selected package archives by extension to PurlDB."""
        if not purldb.is_available():
            self.log("PurlDB is not available. Skipping.")
            return

        d2d.match_purldb_resources(
            project=self.project,
            extensions=self.purldb_package_extensions,
            matcher_func=d2d.match_purldb_package,
            logger=self.log,
        )

    @group("Java")
    def find_java_packages(self):
        """Find the java package of the .java source files."""
        d2d.find_java_packages(self.project, logger=self.log)

    @group("Java")
    def map_java_to_class(self):
        """Map a .class compiled file to its .java source."""
        d2d.map_java_to_class(project=self.project, logger=self.log)

    @group("Java")
    def map_jar_to_source(self):
        """Map .jar files to their related source directory."""
        d2d.map_jar_to_source(project=self.project, logger=self.log)

    @group("JavaScript")
    def map_javascript(self):
        """
        Map a packed or minified JavaScript, TypeScript, CSS and SCSS
        to its source.
        """
        d2d.map_javascript(project=self.project, logger=self.log)

    @group("Elf")
    def map_elf(self):
        """Map ELF binaries to their sources."""
        d2d.map_elfs(project=self.project, logger=self.log)

    @group("Go")
    def map_go(self):
        """Map Go binaries to their sources."""
        d2d.map_go_paths(project=self.project, logger=self.log)

    def match_directories_to_purldb(self):
        """Match selected directories in PurlDB."""
        if not purldb.is_available():
            self.log("PurlDB is not available. Skipping.")
            return

        d2d.match_purldb_directories(
            project=self.project,
            logger=self.log,
        )

    def match_resources_to_purldb(self):
        """Match selected files by extension in PurlDB."""
        if not purldb.is_available():
            self.log("PurlDB is not available. Skipping.")
            return

        d2d.match_purldb_resources(
            project=self.project,
            extensions=self.purldb_resource_extensions,
            matcher_func=d2d.match_purldb_resource,
            logger=self.log,
        )

    @group("JavaScript")
    def map_javascript_post_purldb_match(self):
        """Map minified javascript file based on existing PurlDB match."""
        d2d.map_javascript_post_purldb_match(project=self.project, logger=self.log)

    @group("JavaScript")
    def map_javascript_path(self):
        """Map javascript file based on path."""
        d2d.map_javascript_path(project=self.project, logger=self.log)

    @group("JavaScript")
    def map_javascript_colocation(self):
        """Map JavaScript files based on neighborhood file mapping."""
        d2d.map_javascript_colocation(project=self.project, logger=self.log)

    @group("JavaScript")
    def map_thirdparty_npm_packages(self):
        """Map thirdparty package using package.json metadata."""
        d2d.map_thirdparty_npm_packages(project=self.project, logger=self.log)

    def map_path(self):
        """Map using path similarities."""
        d2d.map_path(project=self.project, logger=self.log)

    def flag_mapped_resources_archives_and_ignored_directories(self):
        """Flag all codebase resources that were mapped during the pipeline."""
        flag.flag_mapped_resources(self.project)
        flag.flag_ignored_directories(self.project)
        d2d.flag_processed_archives(self.project)

    def perform_house_keeping_tasks(self):
        """
        On deployed side
            - PurlDB match files with ``no-java-source`` and empty status,
                if no match is found update status to ``requires-review``.
            - Update status for uninteresting files.
            - Flag the dangling legal files for review.

        On devel side
            - Update status for not deployed files.
        """
        d2d.match_resources_with_no_java_source(project=self.project, logger=self.log)
        d2d.handle_dangling_deployed_legal_files(project=self.project, logger=self.log)
        d2d.match_unmapped_resources(
            project=self.project,
            matched_extensions=self.purldb_resource_extensions,
            logger=self.log,
        )
        d2d.flag_undeployed_resources(project=self.project)

    def match_purldb_resources_post_process(self):
        """Choose the best package for PurlDB matched resources."""
        d2d.match_purldb_resources_post_process(self.project, logger=self.log)

    def remove_packages_without_resources(self):
        """Remove packages without any resources."""
        package_without_resources = self.project.discoveredpackages.filter(
            codebase_resources__isnull=True
        )
        package_without_resources.delete()

    def scan_unmapped_to_files(self):
        """
        Scan unmapped/matched ``to/`` files for copyrights, licenses,
        emails, and urls and update the status to `requires-review`.
        """
        d2d.scan_unmapped_to_files(project=self.project, logger=self.log)

    def scan_mapped_from_for_files(self):
        """Scan mapped ``from/`` files for copyrights, licenses, emails, and urls."""
        scan_files = d2d.get_from_files_for_scanning(self.project.codebaseresources)
        scancode.scan_for_files(self.project, scan_files, progress_logger=self.log)

    def collect_and_create_license_detections(self):
        """
        Collect and create unique license detections from resources and
        package data.
        """
        scancode.collect_and_create_license_detections(project=self.project)

    def create_local_files_packages(self):
        """Create local-files packages for codebase resources not part of a package."""
        d2d.create_local_files_packages(self.project)

    def flag_deployed_from_resources_with_missing_license(self):
        """Update the status for deployed from files with missing license."""
        d2d.flag_deployed_from_resources_with_missing_license(
            self.project,
            doc_extensions=self.doc_extensions,
        )
