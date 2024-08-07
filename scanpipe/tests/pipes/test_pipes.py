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

import datetime
import io
from pathlib import Path
from unittest import mock

from django.test import TestCase
from django.test import TransactionTestCase

from pipeline import LoopProgress
from scanpipe import pipes
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredPackage
from scanpipe.models import Project
from scanpipe.pipes import flag
from scanpipe.pipes import get_resource_diff_ratio
from scanpipe.pipes import get_text_str_diff_ratio
from scanpipe.pipes import scancode
from scanpipe.pipes.input import copy_input
from scanpipe.pipes.input import copy_inputs
from scanpipe.tests import dependency_data1
from scanpipe.tests import make_resource_file
from scanpipe.tests import mocked_now
from scanpipe.tests import package_data1
from scanpipe.tests import resource_data1


class ScanPipePipesTest(TestCase):
    data = Path(__file__).parent.parent / "data"

    def test_scanpipe_pipes_strip_root(self):
        input_paths = [
            "/root/dir/file",
            "/root/dir/file/",
            "//root/dir/file",
            "//root/dir/file/",
            "root/dir/file",
            "root/dir/file/",
        ]
        expected = "dir/file"

        for path in input_paths:
            self.assertEqual(expected, pipes.strip_root(path))
            self.assertEqual(expected, pipes.strip_root(Path(path)))

    @mock.patch("scanpipe.pipes.datetime", mocked_now)
    def test_scanpipe_pipes_filename_now(self):
        self.assertEqual("2010-10-10-10-10-10", pipes.filename_now())

    def test_scanpipe_pipes_update_or_create_resource(self):
        p1 = Project.objects.create(name="Analysis")
        package = pipes.update_or_create_package(p1, package_data1)
        resource_data = dict(resource_data1)
        resource_data["for_packages"] = [package.package_uid]

        resource = pipes.update_or_create_resource(p1, resource_data)
        for field_name, value in resource_data.items():
            self.assertEqual(value, getattr(resource, field_name), msg=field_name)

        resource_data["status"] = flag.SCANNED
        resource = pipes.update_or_create_resource(p1, resource_data)
        self.assertEqual("scanned", resource.status)

        resource_data["for_packages"] = ["does_not_exists"]
        with self.assertRaises(DiscoveredPackage.DoesNotExist):
            pipes.update_or_create_resource(p1, resource_data)

    def test_scanpipe_pipes_update_or_create_package(self):
        p1 = Project.objects.create(name="Analysis")
        package = pipes.update_or_create_package(p1, package_data1)
        self.assertEqual("pkg:deb/debian/adduser@3.118?arch=all", package.purl)
        self.assertEqual("bash", package.primary_language)
        self.assertEqual(datetime.date(1999, 10, 10), package.release_date)

        updated_data = dict(package_data1)
        updated_data["sha1"] = "123456789"
        updated_package = pipes.update_or_create_package(p1, updated_data)
        self.assertEqual("pkg:deb/debian/adduser@3.118?arch=all", updated_package.purl)
        self.assertEqual("123456789", updated_package.sha1)
        self.assertEqual(package.pk, updated_package.pk)

        resource1 = make_resource_file(project=p1, path="filename.ext")
        package_data2 = dict(package_data1)
        package_data2["name"] = "new name"
        package_data2["package_uid"] = ""
        package_data2["release_date"] = "2020-11-01T01:40:20"
        package2 = pipes.update_or_create_package(p1, package_data2, [resource1])
        self.assertNotEqual(package.pk, package2.pk)
        self.assertIn(resource1, package2.codebase_resources.all())
        self.assertEqual(datetime.date(2020, 11, 1), package2.release_date)

        # Make sure we can assign a package to multiple Resources calling
        # update_or_create_package() several times.
        package_data2["package_uid"] = package2.package_uid
        resource2 = make_resource_file(project=p1, path="filename2.ext")
        package2 = pipes.update_or_create_package(p1, package_data2, [resource2])
        self.assertIn(package2, resource1.discovered_packages.all())
        self.assertIn(package2, resource2.discovered_packages.all())

        # Make sure the following does not raise an exception
        self.assertIsNone(pipes.update_or_create_package(p1, {}, [resource1]))

    def test_scanpipe_pipes_update_or_create_package_codebase_resources(self):
        p1 = Project.objects.create(name="Analysis")
        resource1 = make_resource_file(project=p1, path="filename.ext")
        resource2 = make_resource_file(project=p1, path="filename2.ext")
        resources = [resource1, resource2]

        # On creation
        package = pipes.update_or_create_package(p1, package_data1, resources)
        self.assertIn(resource1, package.codebase_resources.all())
        self.assertIn(resource2, package.codebase_resources.all())

        # On update
        package.delete()
        package = pipes.update_or_create_package(p1, package_data1)
        self.assertEqual(0, package.codebase_resources.count())
        package = pipes.update_or_create_package(p1, package_data1, resources)
        self.assertIn(resource1, package.codebase_resources.all())
        self.assertIn(resource2, package.codebase_resources.all())

    @mock.patch("uuid.uuid4")
    def test_scanpipe_pipes_create_local_files_package(self, mock_uuid4):
        forced_uuid = "b74fe5df-e965-415e-ba65-f38421a0695d"
        mock_uuid4.return_value = forced_uuid

        p1 = Project.objects.create(name="P1")
        resource1 = make_resource_file(project=p1, path="filename.ext")

        defaults = {
            "declared_license_expression": "mit",
            "copyright": "Copyright",
        }
        local_package = pipes.create_local_files_package(
            p1, defaults, codebase_resources=[resource1.pk]
        )
        expected_purl = f"pkg:local-files/{p1.slug}/{forced_uuid}"
        self.assertEqual(expected_purl, local_package.purl)
        self.assertEqual("mit", local_package.declared_license_expression)
        self.assertEqual("Copyright", local_package.copyright)
        self.assertEqual(
            [f"{expected_purl}?uuid={forced_uuid}"], resource1.for_packages
        )

    def test_scanpipe_pipes_update_or_create_package_package_uid(self):
        p1 = Project.objects.create(name="Analysis")
        package_data = dict(package_data1)

        package_data["package_uid"] = None
        package1 = pipes.update_or_create_package(p1, package_data)
        self.assertTrue(package1.package_uid)

        package_data["package_uid"] = ""
        package2 = pipes.update_or_create_package(p1, package_data)
        self.assertTrue(package2.package_uid)

        del package_data["package_uid"]
        package3 = pipes.update_or_create_package(p1, package_data)
        self.assertTrue(package3.package_uid)

        self.assertNotEqual(package1.package_uid, package2.package_uid)
        self.assertNotEqual(package2.package_uid, package3.package_uid)

        # A `package_uid` value is generated when not provided, making each
        # package instance unique.
        self.assertEqual(3, DiscoveredPackage.objects.count())

        # In that case, there is a match in the db, the object is updated
        package_data["package_uid"] = package1.package_uid
        package_data["sha1"] = "sha1"
        # We need to use an empty field since override=False in update_from_data
        self.assertEqual("", package1.sha1)
        pipes.update_or_create_package(p1, package_data)
        package1.refresh_from_db()
        self.assertEqual("sha1", package1.sha1)
        self.assertEqual(3, DiscoveredPackage.objects.count())

    def test_scanpipe_pipes_update_or_create_dependency(self):
        p1 = Project.objects.create(name="Analysis")
        make_resource_file(p1, "daglib-0.3.2.tar.gz-extract/daglib-0.3.2/PKG-INFO")
        pipes.update_or_create_package(p1, package_data1)

        dependency_data = dict(dependency_data1)
        dependency_data["scope"] = ""
        dependency = pipes.update_or_create_dependency(p1, dependency_data)
        for field_name, value in dependency_data.items():
            self.assertEqual(value, getattr(dependency, field_name), msg=field_name)

        dependency_data["scope"] = "install"
        dependency = pipes.update_or_create_dependency(p1, dependency_data)
        self.assertEqual("install", dependency.scope)

    def test_scanpipe_pipes_update_or_create_dependency_ignored_dependency_scopes(self):
        p1 = Project.objects.create(name="Analysis")
        make_resource_file(p1, "daglib-0.3.2.tar.gz-extract/daglib-0.3.2/PKG-INFO")
        pipes.update_or_create_package(p1, package_data1)

        p1.settings = {
            "ignored_dependency_scopes": [{"package_type": "pypi", "scope": "tests"}]
        }
        p1.save()

        dependency_data = dict(dependency_data1)
        self.assertFalse(pipes.ignore_dependency_scope(p1, dependency_data))
        dependency = pipes.update_or_create_dependency(p1, dependency_data)
        for field_name, value in dependency_data.items():
            self.assertEqual(value, getattr(dependency, field_name), msg=field_name)
        dependency.delete()

        # Matching the ignored setting
        dependency_data["package_type"] = "pypi"
        dependency_data["scope"] = "tests"
        self.assertTrue(pipes.ignore_dependency_scope(p1, dependency_data))
        dependency = pipes.update_or_create_dependency(p1, dependency_data)
        self.assertIsNone(dependency)

    def test_scanpipe_pipes_get_or_create_relation(self):
        p1 = Project.objects.create(name="Analysis")
        from1 = make_resource_file(p1, "from/a.txt")
        to1 = make_resource_file(p1, "to/a.txt")
        relation_data = {
            "from_resource": from1.path,
            "to_resource": to1.path,
            "map_type": "sha1",
        }
        relation_created = pipes.get_or_create_relation(p1, relation_data)
        self.assertEqual("sha1", relation_created.map_type)
        relation_from_get = pipes.get_or_create_relation(p1, relation_data)
        self.assertEqual(relation_created, relation_from_get)

    def test_scanpipe_pipes_make_relation(self):
        p1 = Project.objects.create(name="Analysis")
        from_resource = make_resource_file(p1, "Name.java")
        to_resource = make_resource_file(p1, "Name.class")

        relation = pipes.make_relation(
            from_resource=from_resource,
            to_resource=to_resource,
            map_type="java_to_class",
            extra_data={"extra": "data"},
        )

        self.assertEqual(from_resource, relation.from_resource)
        self.assertEqual(to_resource, relation.to_resource)
        self.assertEqual("java_to_class", relation.map_type)
        self.assertEqual({"extra": "data"}, relation.extra_data)


class ScanPipePipesTransactionTest(TransactionTestCase):
    """
    Since we are testing some Database errors, we need to use a
    TransactionTestCase to avoid any TransactionManagementError while running
    the tests.
    """

    data = Path(__file__).parent.parent / "data"

    def test_scanpipe_pipes_make_codebase_resource(self):
        p1 = Project.objects.create(name="Analysis")
        resource_location = str(self.data / "aboutcode" / "notice.NOTICE")

        with self.assertRaises(ValueError) as cm:
            pipes.make_codebase_resource(p1, resource_location)

        self.assertIn("not", str(cm.exception))
        self.assertIn(resource_location, str(cm.exception))
        self.assertIn("/codebase", str(cm.exception))

        copy_input(resource_location, p1.codebase_path)
        resource_location = str(p1.codebase_path / "notice.NOTICE")
        pipes.make_codebase_resource(p1, resource_location)

        resource = p1.codebaseresources.get()
        self.assertEqual(1178, resource.size)
        self.assertEqual("4bd631df28995c332bf69d9d4f0f74d7ee089598", resource.sha1)
        self.assertEqual("90cd416fd24df31f608249b77bae80f1", resource.md5)
        self.assertEqual("text/plain", resource.mime_type)
        self.assertEqual("ASCII text", resource.file_type)
        self.assertEqual("", resource.status)
        self.assertEqual(CodebaseResource.Type.FILE, resource.type)

        # Duplicated path: skip the creation and no project error added
        pipes.make_codebase_resource(p1, resource_location)
        self.assertEqual(1, p1.codebaseresources.count())
        self.assertEqual(0, p1.projectmessages.count())

    def test_scanpipe_add_resource_to_package(self):
        project1 = Project.objects.create(name="Analysis")
        resource1 = make_resource_file(project=project1, path="filename.ext")
        package1 = pipes.update_or_create_package(project1, package_data1)
        self.assertFalse(resource1.for_packages)

        self.assertIsNone(scancode.add_resource_to_package(None, resource1, project1))
        self.assertFalse(resource1.for_packages)

        scancode.add_resource_to_package("not_available", resource1, project1)
        self.assertFalse(resource1.for_packages)
        self.assertEqual(1, project1.projectmessages.count())
        error = project1.projectmessages.get()
        self.assertEqual("assemble_package", error.model)
        expected = {"resource_path": "filename.ext", "package_uid": "not_available"}
        self.assertEqual(expected, error.details)

        scancode.add_resource_to_package(package1.package_uid, resource1, project1)
        self.assertEqual(len(resource1.for_packages), 1)
        self.assertIn(package1.package_uid, resource1.for_packages)

        # Package will not be added twice since it is already associated with the
        # resource.
        scancode.add_resource_to_package(package1.package_uid, resource1, project1)
        self.assertEqual(len(resource1.for_packages), 1)

    def test_scanpipe_loop_progress_as_context_manager(self):
        total_iterations = 100
        progress_step = 10
        expected = (
            "Progress: 10% (10/100)"
            "Progress: 20% (20/100)"
            "Progress: 30% (30/100)"
            "Progress: 40% (40/100)"
            "Progress: 50% (50/100)"
            "Progress: 60% (60/100)"
            "Progress: 70% (70/100)"
            "Progress: 80% (80/100)"
            "Progress: 90% (90/100)"
            "Progress: 100% (100/100)"
        )

        buffer = io.StringIO()
        logger = buffer.write
        progress = LoopProgress(total_iterations, logger, progress_step=10)
        for _ in progress.iter(range(total_iterations)):
            pass
        self.assertEqual(expected, buffer.getvalue())

        buffer = io.StringIO()
        logger = buffer.write
        with LoopProgress(total_iterations, logger, progress_step) as progress:
            for _ in progress.iter(range(total_iterations)):
                pass
        self.assertEqual(expected, buffer.getvalue())

    def test_scanpipe_pipes_get_resource_diff_ratio(self):
        project1 = Project.objects.create(name="Analysis")

        resource_files = [
            self.data / "codebase" / "a.txt",
            self.data / "codebase" / "b.txt",
            self.data / "codebase" / "c.txt",
        ]
        copy_inputs(resource_files, project1.codebase_path)

        resource1 = make_resource_file(project1, "a.txt")
        resource2 = make_resource_file(project1, "b.txt")
        resource3 = make_resource_file(project1, "c.txt")

        self.assertEqual(0.5, get_resource_diff_ratio(resource1, resource2))
        self.assertEqual(0.0, get_resource_diff_ratio(resource1, resource3))
        self.assertEqual(1.0, get_resource_diff_ratio(resource2, resource2))

        resource4 = make_resource_file(project1, "d.txt")
        self.assertIsNone(get_resource_diff_ratio(resource1, resource4))
        self.assertIsNone(get_resource_diff_ratio(resource4, resource1))

    def test_scanpipe_pipes_get_text_str_diff_ratio(self):
        self.assertIsNone(get_text_str_diff_ratio(None, ""))
        self.assertIsNone(get_text_str_diff_ratio("", "a"))

        self.assertEqual(0.5, get_text_str_diff_ratio("a", "a\nb\nc"))

        with self.assertRaises(ValueError) as error:
            get_text_str_diff_ratio(1, 2)
        self.assertEqual("Values must be str", str(error.exception))

    def test_scanpipe_pipes_get_resource_codebase_root(self):
        p1 = Project.objects.create(name="Analysis")
        input_location = self.data / "codebase" / "a.txt"
        file_location = copy_input(input_location, p1.codebase_path)
        codebase_root = pipes.get_resource_codebase_root(p1, file_location)
        self.assertEqual("", codebase_root)

        to_dir = p1.codebase_path / "to"
        to_dir.mkdir()
        file_location = copy_input(input_location, to_dir)
        codebase_root = pipes.get_resource_codebase_root(p1, file_location)
        self.assertEqual("to", codebase_root)

        from_dir = p1.codebase_path / "from"
        from_dir.mkdir()
        file_location = copy_input(input_location, from_dir)
        codebase_root = pipes.get_resource_codebase_root(p1, file_location)
        self.assertEqual("from", codebase_root)

    def test_scanpipe_pipes_collect_and_create_codebase_resources(self):
        p1 = Project.objects.create(name="Analysis")
        input_location = self.data / "codebase" / "a.txt"
        to_dir = p1.codebase_path / "to"
        to_dir.mkdir()
        from_dir = p1.codebase_path / "from"
        from_dir.mkdir()
        copy_input(input_location, to_dir)
        copy_input(input_location, from_dir)
        pipes.collect_and_create_codebase_resources(p1)

        self.assertEqual(4, p1.codebaseresources.count())
        from_resource = p1.codebaseresources.get(path="from/a.txt")
        self.assertEqual("from", from_resource.tag)
        to_resource = p1.codebaseresources.get(path="to/a.txt")
        self.assertEqual("to", to_resource.tag)
