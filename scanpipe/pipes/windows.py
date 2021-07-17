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

import re

from django.db.models import Q

from scanpipe import pipes

from packagedcode import win_reg
from packagedcode.models import Package


def package_getter(root_dir, **kwargs):
    """
    Yield installed package objects.
    """
    packages = win_reg.get_installed_packages(root_dir)
    for package in packages:
        yield package.purl, package


def tag_uninteresting_windows_codebase_resources(project):
    """
    Tag known uninteresting files as uninteresting
    """
    uninteresting_files = (
        'DefaultUser_Delta',
        'Sam_Delta',
        'Security_Delta',
        'Software_Delta',
        'System_Delta',
        'NTUSER.DAT',
        'desktop.ini',
    )

    uninteresting_file_extensions = (
        '.lnk',
        '.library-ms',
        '.LOG1',
        '.LOG2',
    )

    lookups = Q()
    for file_name in uninteresting_files:
        lookups |= Q(path__endswith=file_name)
    for file_extension in uninteresting_file_extensions:
        lookups |= Q(path__endswith=file_extension)

    qs = project.codebaseresources.no_status()
    qs.filter(lookups).update(status="ignored-not-interesting")


def tag_installed_package_files(project, root_dir_pattern, package):
    """
    For all CodebaseResources from `project` whose `rootfs_path` starts with
    `root_dir_pattern`, add `package` to the discovered_packages of each
    CodebaseResource and set the status
    """
    qs = project.codebaseresources.no_status()
    installed_package_files = qs.filter(rootfs_path__startswith=root_dir_pattern)
    # If we find files whose names start with `root_dir_pattern`, we consider
    # these files to be part of the Package `package` and tag these files as
    # such
    if installed_package_files:
        created_package = pipes.update_or_create_package(project=project, package_data=package.to_dict())
        for installed_package_file in installed_package_files:
            installed_package_file.discovered_packages.add(created_package)
            installed_package_file.status = "installed-package"
            installed_package_file.save()
        created_package.save()


def tag_known_software(project):
    """
    Find Windows software in `project` by checking `project`s CodebaseResources
    to see if their rootfs_path is is under a known software root directory. If
    there are CodebaseResources that are under a known software root directory,
    a DiscoveredPackage is created for that software package and all files under
    that software package's root directory are considered installed files for
    that package.

    Currently, we are only checking for Python and openjdk in Windows Docker
    image layers.
    """
    qs = project.codebaseresources.no_status()
    python_root_directory_name_pattern = r"/Files/Python(\d*)"
    python_root_directory_name_pattern_compiled = re.compile(python_root_directory_name_pattern)
    python_paths_by_versions = {}
    for python_codebase_resource in qs.filter(rootfs_path__regex=python_root_directory_name_pattern):
        _, version, _ = re.split(
            python_root_directory_name_pattern_compiled,
            python_codebase_resource.rootfs_path
        )
        if not version:
            version = 'nv'
        if version in python_paths_by_versions:
            continue
        if version != 'nv':
            version_with_dots = '.'.join(digit for digit in version)
            python_paths_by_versions[version_with_dots] = f'/Files/Python{version}'
        else:
            python_paths_by_versions[version] = '/Files/Python'

    for python_version, python_path in python_paths_by_versions.items():
        python_package = Package(
                type="windows-program",
                name="Python",
                version=python_version,
                license_expression="python",
                copyright="Copyright (c) Python Software Foundation",
                homepage_url="https://www.python.org/"
        )
        tag_installed_package_files(
            project=project,
            root_dir_pattern=python_path,
            package=python_package
        )

    qs = project.codebaseresources.no_status()
    openjdk_root_directory_name_pattern = r"/Files/(open)?jdk(-((\d*)(\.\d+)*))*"
    openjdk_root_directory_name_pattern_compiled = re.compile(openjdk_root_directory_name_pattern)
    openjdk_paths_by_versions = {}
    for openjdk_codebase_resource in qs.filter(rootfs_path__regex=openjdk_root_directory_name_pattern):
        _, open_prefix, _, openjdk_version, _, _, _ = re.split(
            openjdk_root_directory_name_pattern_compiled,
            openjdk_codebase_resource.rootfs_path
        )
        if not openjdk_version:
            openjdk_version = 'nv'
        if not open_prefix:
            open_prefix = ''
        if openjdk_version in openjdk_paths_by_versions:
            continue
        if openjdk_version != 'nv':
            openjdk_path = f'/Files/{open_prefix}jdk-{openjdk_version}'
        else:
            openjdk_path = f'/Files/{open_prefix}jdk'
        openjdk_paths_by_versions[openjdk_version] = openjdk_path

    for openjdk_version, openjdk_path in openjdk_paths_by_versions.items():
        openjdk_package = Package(
            type="windows-program",
            name="OpenJDK",
            version=openjdk_version,
            license_expression="gpl-2.0 WITH oracle-openjdk-classpath-exception-2.0",
            copyright="Copyright (c) Oracle and/or its affiliates",
            homepage_url="http://openjdk.java.net/",
        )
        tag_installed_package_files(
            project=project,
            root_dir_pattern=openjdk_path,
            package=openjdk_package
        )


PROGRAM_FILES_DIRS_TO_IGNORE = (
    "Common Files",
    "Common_Files",
    "common_files",
    "Microsoft",
)


def tag_program_files(project):
    """
    Report all subdirectories of Program Files and Program Files (x86) as
    packages
    """
    qs = project.codebaseresources.no_status()
    # Get all files from Program_Files and Program_Files_(x86)
    program_files_one_directory_below_pattern = r"(/Files/Program_Files(_\(x86\))?/([^/]+))"
    program_files_one_directory_below_pattern_compiled = re.compile(program_files_one_directory_below_pattern)
    program_files_dirname_by_path = {}
    lookup = Q(rootfs_path__startswith="/Files/Program_Files") | Q(rootfs_path__startswith="/Files/Program_Files_(x86)")
    for program_file in qs.filter(lookup):
        _, program_files_subdir, _, dirname, _ = re.split(
            program_files_one_directory_below_pattern_compiled,
            program_file.rootfs_path
        )
        if (program_files_subdir in program_files_dirname_by_path
                or dirname in PROGRAM_FILES_DIRS_TO_IGNORE):
            continue
        program_files_dirname_by_path[program_files_subdir] = dirname

    for program_root_dir, program_root_dir_name in program_files_dirname_by_path.items():
        package = Package(
            type="windows-program",
            name=program_root_dir_name,
            version="nv",
        )
        tag_installed_package_files(
            project=project,
            root_dir_pattern=program_root_dir,
            package=package
        )
