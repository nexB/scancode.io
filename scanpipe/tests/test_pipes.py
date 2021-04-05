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

import collections
import json
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.test import TestCase
from django.test import TransactionTestCase

from commoncode.resource import VirtualCodebase

from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredPackage
from scanpipe.models import Project
from scanpipe.pipes import codebase
from scanpipe.pipes import docker
from scanpipe.pipes import fetch
from scanpipe.pipes import filename_now
from scanpipe.pipes import make_codebase_resource
from scanpipe.pipes import output
from scanpipe.pipes import rootfs
from scanpipe.pipes import scancode
from scanpipe.pipes import strip_root
from scanpipe.pipes import tag_not_analyzed_codebase_resources
from scanpipe.pipes.input import copy_inputs
from scanpipe.tests import mocked_now
from scanpipe.tests import package_data1


class ScanPipePipesTest(TestCase):
    data_location = Path(__file__).parent / "data"

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
            self.assertEqual(expected, strip_root(path))
            self.assertEqual(expected, strip_root(Path(path)))

    def test_scanpipe_pipes_tag_not_analyzed_codebase_resources(self):
        p1 = Project.objects.create(name="Analysis")
        resource1 = CodebaseResource.objects.create(project=p1, path="filename.ext")
        resource2 = CodebaseResource.objects.create(
            project=p1,
            path="filename1.ext",
            status="scanned",
        )

        tag_not_analyzed_codebase_resources(p1)
        resource1.refresh_from_db()
        resource2.refresh_from_db()
        self.assertEqual("not-analyzed", resource1.status)
        self.assertEqual("scanned", resource2.status)

    @mock.patch("scanpipe.pipes.datetime", mocked_now)
    def test_scanpipe_pipes_filename_now(self):
        self.assertEqual("2010-10-10-10-10-10", filename_now())

    def test_scanpipe_pipes_outputs_queryset_to_csv_file(self):
        project1 = Project.objects.create(name="Analysis")
        codebase_resource = CodebaseResource.objects.create(
            project=project1,
            path="filename.ext",
        )
        codebase_resource.create_and_add_package(package_data1)

        queryset = project1.discoveredpackages.all()
        fieldnames = ["purl", "name", "version"]

        output_file_path = project1.get_output_file_path("packages", "csv")
        with output_file_path.open("w") as output_file:
            output.queryset_to_csv_file(queryset, fieldnames, output_file)

        expected = [
            "purl,name,version\n",
            "pkg:deb/debian/adduser@3.118?arch=all,adduser,3.118\n",
        ]
        with output_file_path.open() as f:
            self.assertEqual(expected, f.readlines())

        queryset = project1.codebaseresources.all()
        fieldnames = ["for_packages", "path"]
        output_file_path = project1.get_output_file_path("resources", "csv")
        with output_file_path.open("w") as output_file:
            output.queryset_to_csv_file(queryset, fieldnames, output_file)

        expected = [
            "for_packages,path\n",
            "['pkg:deb/debian/adduser@3.118?arch=all'],filename.ext\n",
        ]
        with output_file_path.open() as f:
            self.assertEqual(expected, f.readlines())

    def test_scanpipe_pipes_outputs_queryset_to_csv_stream(self):
        project1 = Project.objects.create(name="Analysis")
        codebase_resource = CodebaseResource.objects.create(
            project=project1,
            path="filename.ext",
        )
        codebase_resource.create_and_add_package(package_data1)

        queryset = project1.discoveredpackages.all()
        fieldnames = ["purl", "name", "version"]

        output_file = project1.get_output_file_path("packages", "csv")
        with output_file.open("w") as output_stream:
            generator = output.queryset_to_csv_stream(
                queryset, fieldnames, output_stream
            )
            collections.deque(generator, maxlen=0)  # Exhaust the generator

        expected = [
            "purl,name,version\n",
            "pkg:deb/debian/adduser@3.118?arch=all,adduser,3.118\n",
        ]
        with output_file.open() as f:
            self.assertEqual(expected, f.readlines())

        queryset = project1.codebaseresources.all()
        fieldnames = ["for_packages", "path"]
        output_file = project1.get_output_file_path("resources", "csv")
        with output_file.open("w") as output_stream:
            generator = output.queryset_to_csv_stream(
                queryset, fieldnames, output_stream
            )
            collections.deque(generator, maxlen=0)  # Exhaust the generator

        output.queryset_to_csv_stream(queryset, fieldnames, output_file)

        expected = [
            "for_packages,path\n",
            "['pkg:deb/debian/adduser@3.118?arch=all'],filename.ext\n",
        ]
        with output_file.open() as f:
            self.assertEqual(expected, f.readlines())

    @mock.patch("scanpipe.pipes.datetime", mocked_now)
    def test_scanpipe_pipes_outputs_to_csv(self):
        project1 = Project.objects.create(name="Analysis")
        output_files = output.to_csv(project=project1)
        expected = [
            "codebaseresource-2010-10-10-10-10-10.csv",
            "discoveredpackage-2010-10-10-10-10-10.csv",
        ]
        self.assertEqual(sorted(expected), sorted(project1.output_root))
        self.assertEqual(sorted(expected), sorted([f.name for f in output_files]))

    def test_scanpipe_pipes_outputs_to_json(self):
        project1 = Project.objects.create(name="Analysis")
        codebase_resource = CodebaseResource.objects.create(
            project=project1,
            path="filename.ext",
        )
        codebase_resource.create_and_add_package(package_data1)

        output_file = output.to_json(project=project1)
        self.assertEqual([output_file.name], project1.output_root)

        with output_file.open() as f:
            results = json.loads(f.read())

        expected = ["files", "headers", "packages"]
        self.assertEqual(expected, sorted(results.keys()))

        self.assertEqual(1, len(results["headers"]))
        self.assertEqual(1, len(results["files"]))
        self.assertEqual(1, len(results["packages"]))

    def test_scanpipe_pipes_outputs_to_xlsx(self):
        project1 = Project.objects.create(name="Analysis")
        codebase_resource = CodebaseResource.objects.create(
            project=project1,
            path="filename.ext",
        )
        codebase_resource.create_and_add_package(package_data1)

        output_file = output.to_xlsx(project=project1)
        self.assertEqual([output_file.name], project1.output_root)

    def test_scanpipe_pipes_scancode_get_resource_info(self):
        input_location = str(self.data_location / "notice.NOTICE")
        sha256 = "b323607418a36b5bd700fcf52ae9ca49f82ec6359bc4b89b1b2d73cf75321757"
        expected = {
            "type": CodebaseResource.Type.FILE,
            "name": "notice",
            "extension": ".NOTICE",
            "size": 1178,
            "sha1": "4bd631df28995c332bf69d9d4f0f74d7ee089598",
            "md5": "90cd416fd24df31f608249b77bae80f1",
            "sha256": sha256,
            "mime_type": "text/plain",
            "file_type": "ASCII text",
        }
        self.assertEqual(expected, scancode.get_resource_info(input_location))

    def test_scanpipe_pipes_scancode_scan_file(self):
        input_location = str(self.data_location / "notice.NOTICE")
        scan_results, scan_errors = scancode.scan_file(input_location)
        expected = [
            "copyrights",
            "holders",
            "authors",
            "licenses",
            "license_expressions",
            "spdx_license_expressions",
            "percentage_of_license_text",
            "emails",
            "urls",
        ]
        self.assertEqual(expected, list(scan_results.keys()))
        self.assertEqual([], scan_errors)

    def test_scanpipe_pipes_scancode_scan_file_and_save_results(self):
        project1 = Project.objects.create(name="Analysis")
        codebase_resource1 = CodebaseResource.objects.create(
            project=project1, path="not available"
        )

        scancode.scan_file_and_save_results(codebase_resource1)
        codebase_resource1.refresh_from_db()
        self.assertEqual("scanned-with-error", codebase_resource1.status)

        copy_inputs([self.data_location / "notice.NOTICE"], project1.codebase_path)
        codebase_resource2 = CodebaseResource.objects.create(
            project=project1, path="notice.NOTICE"
        )
        scancode.scan_file_and_save_results(codebase_resource2)
        codebase_resource2.refresh_from_db()
        self.assertEqual("scanned", codebase_resource2.status)
        expected = [
            "apache-2.0",
            "apache-2.0 AND scancode-acknowledgment",
            "apache-2.0",
            "apache-2.0",
        ]
        self.assertEqual(expected, codebase_resource2.license_expressions)

    @mock.patch("scanpipe.pipes.scancode.scan_file")
    def test_scanpipe_pipes_scancode_scan_for_files(self, mock_scan_file):
        scan_results = {"license_expressions": ["mit"]}
        scan_errors = []
        mock_scan_file.return_value = scan_results, scan_errors

        project1 = Project.objects.create(name="Analysis")
        sha1 = "51d28a27d919ce8690a40f4f335b9d591ceb16e9"
        resource1 = CodebaseResource.objects.create(
            project=project1,
            path="dir1/file.ext",
            sha1=sha1,
        )
        resource2 = CodebaseResource.objects.create(
            project=project1,
            path="dir2/file.ext",
            sha1=sha1,
        )

        scancode.scan_for_files(project1)
        # The scan_file is only called once as the cache is used for the second
        # duplicated resource.
        # WARNING: The cache is turned off for now in favor of multiprocessing
        # mock_scan_file.assert_called_once()

        for resource in [resource1, resource2]:
            resource.refresh_from_db()
            self.assertEqual("scanned", resource.status)
            self.assertEqual(["mit"], resource.license_expressions)

    def test_scanpipe_pipes_scancode_virtual_codebase(self):
        project = Project.objects.create(name="asgiref")
        input_location = self.data_location / "asgiref-3.3.0_scan.json"
        virtual_codebase = scancode.get_virtual_codebase(project, input_location)
        self.assertEqual(19, len(virtual_codebase.resources.keys()))

        scancode.create_codebase_resources(project, virtual_codebase)
        scancode.create_discovered_packages(project, virtual_codebase)

        self.assertEqual(19, CodebaseResource.objects.count())
        self.assertEqual(1, DiscoveredPackage.objects.count())

        # The functions can be called again and existing objects are skipped
        scancode.create_codebase_resources(project, virtual_codebase)
        scancode.create_discovered_packages(project, virtual_codebase)
        self.assertEqual(19, CodebaseResource.objects.count())
        self.assertEqual(1, DiscoveredPackage.objects.count())

    def test_scanpipe_pipes_scancode_run_extractcode(self):
        project = Project.objects.create(name="name with space")
        exitcode, output = scancode.run_extractcode(str(project.codebase_path))
        self.assertEqual(0, exitcode)
        self.assertIn("Extracting done.", output)

    def test_scanpipe_pipes_scancode_run_scancode(self):
        project = Project.objects.create(name="name with space")
        exitcode, output = scancode.run_scancode(
            location=str(project.codebase_path),
            output_file=str(project.get_output_file_path("scancode", "json")),
            options=["--info"],
        )
        self.assertEqual(0, exitcode)
        self.assertIn("Scanning done.", output)

    def test_scanpipe_pipes_codebase_get_tree(self):
        fixtures = self.data_location / "asgiref-3.3.0_fixtures.json"
        call_command("loaddata", fixtures, **{"verbosity": 0})
        project = Project.objects.get(name="asgiref")

        scan_results = self.data_location / "asgiref-3.3.0_scan.json"
        virtual_codebase = scancode.get_virtual_codebase(project, scan_results)
        project_codebase = codebase.ProjectCodebase(project)

        fields = ["name", "path"]
        virtual_tree = codebase.get_tree(
            virtual_codebase.root, fields, codebase=virtual_codebase
        )
        project_tree = codebase.get_tree(project_codebase.root, fields)

        with open(self.data_location / "asgiref-3.3.0_tree.json") as f:
            expected = json.loads(f.read())

        self.assertEqual(expected, project_tree)
        self.assertEqual(expected, virtual_tree)

    def test_scanpipe_pipes_codebase_project_codebase_class_no_resources(self):
        project = Project.objects.create(name="project")

        project_codebase = codebase.ProjectCodebase(project)
        with self.assertRaises(AttributeError):
            project_codebase.root

        self.assertEqual([], list(project_codebase.resources))
        with self.assertRaises(AttributeError):
            list(project_codebase.walk())
        with self.assertRaises(AttributeError):
            project_codebase.get_tree()

    def test_scanpipe_pipes_codebase_project_codebase_class_with_resources(self):
        fixtures = self.data_location / "asgiref-3.3.0_fixtures.json"
        call_command("loaddata", fixtures, **{"verbosity": 0})

        project = Project.objects.get(name="asgiref")
        project_codebase = codebase.ProjectCodebase(project)

        expected_root = project.codebaseresources.get(path="codebase")
        self.assertTrue(isinstance(project_codebase.root, CodebaseResource))
        self.assertEqual(expected_root, project_codebase.root)

        self.assertEqual(19, len(project_codebase.resources))
        self.assertEqual(expected_root, project_codebase.resources[0])

        walk_gen = project_codebase.walk()
        self.assertEqual(expected_root, next(walk_gen))
        expected = "codebase/asgiref-3.3.0-py3-none-any.whl"
        self.assertEqual(expected, next(walk_gen).path)

        tree = project_codebase.get_tree()
        with open(self.data_location / "asgiref-3.3.0_tree.json") as f:
            expected = json.loads(f.read())

        self.assertEqual(expected, tree)

    def test_scanpipe_pipes_codebase_project_codebase_class_walk(self):
        fixtures = self.data_location / "asgiref-3.3.0_fixtures.json"
        call_command("loaddata", fixtures, **{"verbosity": 0})

        project = Project.objects.get(name="asgiref")
        project_codebase = codebase.ProjectCodebase(project)
        asgiref_scan = self.data_location / "asgiref-3.3.0_scan.json"
        asgiref_vc = VirtualCodebase(location=asgiref_scan)

        topdown_paths = list(r.path for r in project_codebase.walk(topdown=True))
        expected_topdown_paths = list(r.path for r in asgiref_vc.walk(topdown=True))
        self.assertEqual(expected_topdown_paths, topdown_paths)

        bottom_up_paths = list(r.path for r in project_codebase.walk(topdown=False))
        expected_bottom_up_paths = list(r.path for r in asgiref_vc.walk(topdown=False))
        self.assertEqual(expected_bottom_up_paths, bottom_up_paths)

    @mock.patch("requests.get")
    def test_scanpipe_pipes_fetch_download(self, mock_get):
        url = "https://example.com/filename.zip"

        mock_get.return_value = mock.Mock(
            content=b"\x00", headers={}, status_code=200, url=url
        )
        downloaded_file = fetch.download(url)
        self.assertTrue(Path(downloaded_file.directory, "filename.zip").exists())

        redirect_url = "https://example.com/redirect.zip"
        mock_get.return_value = mock.Mock(
            content=b"\x00", headers={}, status_code=200, url=redirect_url
        )
        downloaded_file = fetch.download(url)
        self.assertTrue(Path(downloaded_file.directory, "redirect.zip").exists())

        headers = {
            "content-disposition": 'attachment; filename="another_name.zip"',
        }
        mock_get.return_value = mock.Mock(
            content=b"\x00", headers=headers, status_code=200, url=url
        )
        downloaded_file = fetch.download(url)
        self.assertTrue(Path(downloaded_file.directory, "another_name.zip").exists())

    @mock.patch("requests.get")
    def test_scanpipe_pipes_fetch_fetch_urls(self, mock_get):
        urls = [
            "https://example.com/filename.zip",
            "https://example.com/archive.tar.gz",
        ]

        mock_get.return_value = mock.Mock(
            content=b"\x00", headers={}, status_code=200, url="mocked_url"
        )
        downloads, errors = fetch.fetch_urls(urls)
        self.assertEqual(2, len(downloads))
        self.assertEqual(urls[0], downloads[0].uri)
        self.assertEqual(urls[1], downloads[1].uri)
        self.assertEqual(0, len(errors))

        mock_get.side_effect = Exception
        downloads, errors = fetch.fetch_urls(urls)
        self.assertEqual(0, len(downloads))
        self.assertEqual(2, len(errors))
        self.assertEqual(urls, errors)

    def test_scanpipe_pipes_docker_tag_whiteout_codebase_resources(self):
        p1 = Project.objects.create(name="Analysis")
        resource1 = CodebaseResource.objects.create(project=p1, path="filename.ext")
        resource2 = CodebaseResource.objects.create(project=p1, name=".wh.filename2")

        docker.tag_whiteout_codebase_resources(p1)
        resource1.refresh_from_db()
        resource2.refresh_from_db()
        self.assertEqual("", resource1.status)
        self.assertEqual("ignored-whiteout", resource2.status)

    def test_scanpipe_pipes_rootfs_tag_empty_codebase_resources(self):
        p1 = Project.objects.create(name="Analysis")
        resource1 = CodebaseResource.objects.create(project=p1, path="dir/")
        resource2 = CodebaseResource.objects.create(
            project=p1, path="filename.ext", type=CodebaseResource.Type.FILE
        )

        rootfs.tag_empty_codebase_resources(p1)
        resource1.refresh_from_db()
        resource2.refresh_from_db()
        self.assertEqual("", resource1.status)
        self.assertEqual("ignored-empty-file", resource2.status)

    def test_scanpipe_pipes_rootfs_tag_uninteresting_codebase_resources(self):
        p1 = Project.objects.create(name="Analysis")
        resource1 = CodebaseResource.objects.create(project=p1, path="filename.ext")
        resource2 = CodebaseResource.objects.create(project=p1, rootfs_path="/tmp/file")

        rootfs.tag_uninteresting_codebase_resources(p1)
        resource1.refresh_from_db()
        resource2.refresh_from_db()
        self.assertEqual("", resource1.status)
        self.assertEqual("ignored-not-interesting", resource2.status)


class ScanPipePipesTransactionTest(TransactionTestCase):
    """
    Since we are testing some Database errors, we need to use a
    TransactionTestCase to avoid any TransactionManagementError while running
    the tests.
    """

    data_location = Path(__file__).parent / "data"

    def test_scanpipe_pipes_make_codebase_resource(self):
        p1 = Project.objects.create(name="Analysis")
        resource_location = str(self.data_location / "notice.NOTICE")

        with self.assertRaises(AssertionError) as cm:
            make_codebase_resource(p1, resource_location)

        self.assertIn("is not under project/codebase/", str(cm.exception))

        copy_inputs([resource_location], p1.codebase_path)
        resource_location = str(p1.codebase_path / "notice.NOTICE")
        make_codebase_resource(p1, resource_location)

        resource = p1.codebaseresources.get()
        self.assertEqual(1178, resource.size)
        self.assertEqual("4bd631df28995c332bf69d9d4f0f74d7ee089598", resource.sha1)
        self.assertEqual("90cd416fd24df31f608249b77bae80f1", resource.md5)
        self.assertEqual("text/plain", resource.mime_type)
        self.assertEqual("ASCII text", resource.file_type)
        self.assertEqual("", resource.status)
        self.assertEqual(CodebaseResource.Type.FILE, resource.type)

        # Duplicated path: skip the creation and no project error added
        make_codebase_resource(p1, resource_location)
        self.assertEqual(1, p1.codebaseresources.count())
        self.assertEqual(0, p1.projecterrors.count())
