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

from django.db.models import Q

from packagedcode import win_reg


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
        lookups |= Q(name=file_name)
    for file_extension in uninteresting_file_extensions:
        lookups |= Q(rootfs_path__endsswith=file_extension)

    qs = project.codebaseresources.no_status()
    qs.filter(lookups).update(status="ignored-not-interesting")
