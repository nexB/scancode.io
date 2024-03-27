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

from scanpipe.pipelines.root_filesystem import RootFS
from scanpipe.pipes import docker
from scanpipe.pipes import rootfs


class Docker(RootFS):
    """Analyze Docker images."""

    @classmethod
    def steps(cls):
        return (
            cls.extract_images,
            cls.extract_layers,
            cls.find_images_os_and_distro,
            cls.collect_images_information,
            cls.collect_and_create_codebase_resources,
            cls.collect_and_create_system_packages,
            cls.flag_uninteresting_codebase_resources,
            cls.flag_empty_files,
            cls.flag_ignored_resources,
            cls.scan_for_application_packages,
            cls.scan_for_files,
            cls.collect_and_create_license_detections,
            cls.analyze_scanned_files,
            cls.flag_not_analyzed_codebase_resources,
        )

    def extract_images(self):
        """Extract images from input tarballs."""
        self.images, errors = docker.extract_images_from_inputs(self.project)
        if not self.images:
            raise Exception("No images found in project input files.")
        if errors:
            self.add_error("\n".join(errors))

    def extract_layers(self):
        """Extract layers from input images."""
        errors = docker.extract_layers_from_images(self.project, self.images)
        if errors:
            self.add_error("\n".join(errors))

    def find_images_os_and_distro(self):
        """Find the operating system and distro of input images."""
        for image in self.images:
            image.get_and_set_distro()

    def collect_images_information(self):
        """Collect and store image information in a project."""
        images_data = [docker.get_image_data(image) for image in self.images]
        self.project.update_extra_data({"images": images_data})

    def collect_and_create_codebase_resources(self):
        """Collect and labels all image files as CodebaseResources."""
        for image in self.images:
            docker.create_codebase_resources(self.project, image)

    def collect_and_create_system_packages(self):
        """Collect installed system packages for each layer based on the distro."""
        with self.save_errors(rootfs.DistroNotFound, rootfs.DistroNotSupported):
            for image in self.images:
                docker.scan_image_for_system_packages(self.project, image)

    def flag_uninteresting_codebase_resources(self):
        """Flag files that don't belong to any system package."""
        docker.flag_whiteout_codebase_resources(self.project)
        rootfs.flag_uninteresting_codebase_resources(self.project)
