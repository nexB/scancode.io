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

from django.core.exceptions import ObjectDoesNotExist

from scanpipe.models import Project


def sort_by_lower_name(resource):
    return resource["name"].lower()


def get_tree(resource, fields, codebase=None):
    """
    Return a tree as a dict structure starting from the provided `resource`.

    The following classes are supported for the input `resource` object:
     - scanpipe.models.CodebaseResource
     - commoncode.resource.Resource

    The data included for each child is controlled with the `fields` argument.
    The `codebase` is only required in the context of a commoncode `Resource`
    input.
    """
    resource_dict = {field: getattr(resource, field) for field in fields}

    if resource.is_dir:
        children = [
            get_tree(child, fields, codebase) for child in resource.children(codebase)
        ]
        if children:
            resource_dict["children"] = sorted(children, key=sort_by_lower_name)

    return resource_dict


class ProjectCodebase:
    """
    Represent the Codebase of a Project stored in the Database.
    A Codebase is a tree of Resources.
    """

    project = None

    def __init__(self, project):
        assert isinstance(project, Project)
        self.project = project

    @property
    def root(self):
        try:
            return self.project.codebaseresources.get(path="codebase")
        except ObjectDoesNotExist:
            raise AttributeError("Codebase root cannot be determined.")

    @property
    def resources(self):
        return self.project.codebaseresources.all()

    def walk(self, topdown=True):
        root = self.root
        if topdown:
            yield root
        for resource in root.walk(topdown=topdown):
            yield resource
        if not topdown:
            yield root

    def get_tree(self):
        return get_tree(self.root, fields=["name", "path"])
