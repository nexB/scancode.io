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

import io
import shutil
import sys
import tempfile
import uuid
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest import mock
from unittest import skipIf

from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import DataError
from django.db import IntegrityError
from django.db import connection
from django.test import TestCase
from django.test import TransactionTestCase
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from packagedcode.models import PackageData
from requests.exceptions import RequestException
from rq.job import JobStatus

from scancodeio import __version__ as scancodeio_version
from scanpipe.models import CodebaseRelation
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredPackage
from scanpipe.models import Project
from scanpipe.models import ProjectMessage
from scanpipe.models import Run
from scanpipe.models import RunInProgressError
from scanpipe.models import RunNotAllowedToStart
from scanpipe.models import UUIDTaggedItem
from scanpipe.models import get_project_work_directory
from scanpipe.models import posix_regex_to_django_regex_lookup
from scanpipe.pipes.fetch import Download
from scanpipe.pipes.input import copy_input
from scanpipe.tests import dependency_data1
from scanpipe.tests import dependency_data2
from scanpipe.tests import license_policies_index
from scanpipe.tests import make_resource_file
from scanpipe.tests import mocked_now
from scanpipe.tests import package_data1
from scanpipe.tests import package_data2
from scanpipe.tests.pipelines.do_nothing import DoNothing

scanpipe_app = apps.get_app_config("scanpipe")
User = get_user_model()


class ScanPipeModelsTest(TestCase):
    data_location = Path(__file__).parent / "data"
    fixtures = [data_location / "asgiref-3.3.0_fixtures.json"]

    def setUp(self):
        self.project1 = Project.objects.create(name="Analysis")
        self.project_asgiref = Project.objects.get(name="asgiref")

    def create_run(self, pipeline="pipeline", **kwargs):
        return Run.objects.create(
            project=self.project1,
            pipeline_name=pipeline,
            **kwargs,
        )

    def test_scanpipe_project_model_extra_data(self):
        self.assertEqual({}, self.project1.extra_data)
        project1_from_db = Project.objects.get(name=self.project1.name)
        self.assertEqual({}, project1_from_db.extra_data)

    def test_scanpipe_project_model_work_directories(self):
        expected_work_directory = f"projects/analysis-{self.project1.short_uuid}"
        self.assertTrue(self.project1.work_directory.endswith(expected_work_directory))
        self.assertTrue(self.project1.work_path.exists())
        self.assertTrue(self.project1.input_path.exists())
        self.assertTrue(self.project1.output_path.exists())
        self.assertTrue(self.project1.codebase_path.exists())
        self.assertTrue(self.project1.tmp_path.exists())

    def test_scanpipe_get_project_work_directory(self):
        project = Project.objects.create(name="Name with spaces and @£$éæ")
        expected = f"/projects/name-with-spaces-and-e-{project.short_uuid}"
        self.assertTrue(get_project_work_directory(project).endswith(expected))
        self.assertTrue(project.work_directory.endswith(expected))

    def test_scanpipe_project_model_clear_tmp_directory(self):
        new_file_path = self.project1.tmp_path / "file.ext"
        new_file_path.touch()
        self.assertEqual([new_file_path], list(self.project1.tmp_path.glob("*")))

        self.project1.clear_tmp_directory()
        self.assertTrue(self.project1.tmp_path.exists())
        self.assertEqual([], list(self.project1.tmp_path.glob("*")))

        self.assertTrue(self.project1.tmp_path.exists())
        shutil.rmtree(self.project1.work_path, ignore_errors=True)
        self.assertFalse(self.project1.tmp_path.exists())
        self.project1.clear_tmp_directory()
        self.assertTrue(self.project1.tmp_path.exists())

    def test_scanpipe_project_model_archive(self):
        (self.project1.input_path / "input_file").touch()
        (self.project1.codebase_path / "codebase_file").touch()
        (self.project1.output_path / "output_file").touch()
        self.assertEqual(1, len(Project.get_root_content(self.project1.input_path)))
        self.assertEqual(1, len(Project.get_root_content(self.project1.codebase_path)))
        self.assertEqual(1, len(Project.get_root_content(self.project1.output_path)))

        self.project1.archive()
        self.project1.refresh_from_db()
        self.assertTrue(self.project1.is_archived)
        self.assertEqual(1, len(Project.get_root_content(self.project1.input_path)))
        self.assertEqual(1, len(Project.get_root_content(self.project1.codebase_path)))
        self.assertEqual(1, len(Project.get_root_content(self.project1.output_path)))

        self.project1.archive(remove_input=True, remove_codebase=True)
        self.assertEqual(0, len(Project.get_root_content(self.project1.input_path)))
        self.assertEqual(0, len(Project.get_root_content(self.project1.codebase_path)))
        self.assertEqual(1, len(Project.get_root_content(self.project1.output_path)))

    def test_scanpipe_project_model_delete_related_objects(self):
        work_path = self.project1.work_path
        self.assertTrue(work_path.exists())

        self.project1.add_pipeline("docker")
        self.project1.labels.add("label1", "label2")
        self.assertEqual(2, UUIDTaggedItem.objects.count())
        resource = CodebaseResource.objects.create(project=self.project1, path="path")
        package = DiscoveredPackage.objects.create(project=self.project1)
        resource.discovered_packages.add(package)

        delete_log = self.project1.delete_related_objects()
        expected = {
            "scanpipe.CodebaseRelation": 0,
            "scanpipe.CodebaseResource": 1,
            "scanpipe.DiscoveredDependency": 0,
            "scanpipe.DiscoveredPackage": 1,
            "scanpipe.DiscoveredPackage_codebase_resources": 1,
            "scanpipe.ProjectMessage": 0,
            "scanpipe.Run": 1,
        }
        self.assertEqual(expected, delete_log)
        # Make sure the labels were deleted too.
        self.assertEqual(0, UUIDTaggedItem.objects.count())

    def test_scanpipe_project_model_delete(self):
        work_path = self.project1.work_path
        self.assertTrue(work_path.exists())

        uploaded_file = SimpleUploadedFile("file.ext", content=b"content")
        self.project1.write_input_file(uploaded_file)
        self.project1.add_pipeline("docker")
        resource = CodebaseResource.objects.create(project=self.project1, path="path")
        package = DiscoveredPackage.objects.create(project=self.project1)
        resource.discovered_packages.add(package)

        delete_log = self.project1.delete()
        expected = {"scanpipe.Project": 1}
        self.assertEqual(expected, delete_log[1])

        self.assertFalse(Project.objects.filter(name=self.project1.name).exists())
        self.assertFalse(work_path.exists())

    def test_scanpipe_project_model_reset(self):
        work_path = self.project1.work_path
        self.assertTrue(work_path.exists())

        uploaded_file = SimpleUploadedFile("file.ext", content=b"content")
        self.project1.write_input_file(uploaded_file)
        self.project1.add_pipeline("docker")
        resource = CodebaseResource.objects.create(project=self.project1, path="path")
        package = DiscoveredPackage.objects.create(project=self.project1)
        resource.discovered_packages.add(package)

        self.project1.reset()

        self.assertTrue(Project.objects.filter(name=self.project1.name).exists())
        self.assertEqual(0, self.project1.projectmessages.count())
        self.assertEqual(0, self.project1.runs.count())
        self.assertEqual(0, self.project1.discoveredpackages.count())
        self.assertEqual(0, self.project1.codebaseresources.count())

        self.assertTrue(work_path.exists())
        self.assertTrue(self.project1.input_path.exists())
        self.assertEqual(["file.ext"], self.project1.input_root)
        self.assertTrue(self.project1.output_path.exists())
        self.assertTrue(self.project1.codebase_path.exists())
        self.assertTrue(self.project1.tmp_path.exists())

    def test_scanpipe_project_model_clone(self):
        self.project1.add_input_source(filename="file1", source="uploaded")
        self.project1.add_input_source(filename="file2", source="https://download.url")
        self.project1.update(settings={"extract_recursively": True})
        new_file_path1 = self.project1.input_path / "file.zip"
        new_file_path1.touch()
        run1 = self.project1.add_pipeline("docker")
        run2 = self.project1.add_pipeline("find_vulnerabilities")

        cloned_project = self.project1.clone("cloned project")
        self.assertIsInstance(cloned_project, Project)
        self.assertNotEqual(self.project1.pk, cloned_project.pk)
        self.assertNotEqual(self.project1.slug, cloned_project.slug)
        self.assertNotEqual(self.project1.work_directory, cloned_project.work_directory)

        self.assertEqual("cloned project", cloned_project.name)
        self.assertEqual({}, cloned_project.settings)
        self.assertEqual({}, cloned_project.input_sources)
        self.assertEqual([], list(cloned_project.inputs()))
        self.assertEqual([], list(cloned_project.runs.all()))

        cloned_project2 = self.project1.clone(
            "cloned project full",
            copy_inputs=True,
            copy_pipelines=True,
            copy_settings=True,
            execute_now=False,
        )
        self.assertEqual(self.project1.settings, cloned_project2.settings)
        self.assertEqual(self.project1.input_sources, cloned_project2.input_sources)
        self.assertEqual(1, len(list(cloned_project2.inputs())))
        runs = cloned_project2.runs.all()
        self.assertEqual(
            ["docker", "find_vulnerabilities"], [run.pipeline_name for run in runs]
        )
        self.assertNotEqual(run1.pk, runs[0].pk)
        self.assertNotEqual(run2.pk, runs[1].pk)

    def test_scanpipe_project_model_input_sources_list_property(self):
        self.project1.add_input_source(filename="file1", source="uploaded")
        self.project1.add_input_source(filename="file2", source="https://download.url")

        expected = [
            {"filename": "file1", "source": "uploaded"},
            {"filename": "file2", "source": "https://download.url"},
        ]
        self.assertEqual(expected, self.project1.input_sources_list)

    def test_scanpipe_project_model_inputs_and_input_files_and_input_root(self):
        self.assertEqual([], list(self.project1.inputs()))
        self.assertEqual([], self.project1.input_files)
        self.assertEqual([], self.project1.input_root)

        new_file_path1 = self.project1.input_path / "file.zip"
        new_file_path1.touch()

        new_dir1 = self.project1.input_path / "dir1"
        new_dir1.mkdir(parents=True, exist_ok=True)
        new_file_path2 = new_dir1 / "file2.tar"
        new_file_path2.touch()

        inputs = list(self.project1.inputs())
        expected = [new_dir1, new_file_path1, new_file_path2]
        self.assertEqual(sorted(expected), sorted(inputs))

        with self.assertRaises(TypeError) as error:
            self.project1.inputs(extensions="str")
        self.assertEqual("extensions should be a list or tuple", str(error.exception))

        inputs = list(self.project1.inputs(extensions=["zip"]))
        self.assertEqual([new_file_path1], inputs)

        inputs = list(self.project1.inputs(extensions=[".tar"]))
        self.assertEqual([new_file_path2], inputs)

        inputs = list(self.project1.inputs(extensions=[".zip", "tar"]))
        self.assertEqual(sorted([new_file_path1, new_file_path2]), sorted(inputs))

        expected = ["file.zip", "dir1/file2.tar"]
        self.assertEqual(sorted(expected), sorted(self.project1.input_files))

        expected = ["dir1", "file.zip"]
        self.assertEqual(sorted(expected), sorted(self.project1.input_root))

    @mock.patch("scanpipe.pipes.datetime", mocked_now)
    def test_scanpipe_project_model_get_output_file_path(self):
        filename = self.project1.get_output_file_path("file", "ext")
        self.assertTrue(str(filename).endswith("/output/file-2010-10-10-10-10-10.ext"))

        # get_output_file_path always ensure the work_directory is setup
        shutil.rmtree(self.project1.work_directory)
        self.assertFalse(self.project1.work_path.exists())
        self.project1.get_output_file_path("file", "ext")
        self.assertTrue(self.project1.work_path.exists())

    def test_scanpipe_project_model_get_latest_output(self):
        scan1 = self.project1.get_output_file_path("scancode", "json")
        scan1.write_text("")
        scan2 = self.project1.get_output_file_path("scancode", "json")
        scan2.write_text("")
        summary1 = self.project1.get_output_file_path("summary", "json")
        summary1.write_text("")
        scan3 = self.project1.get_output_file_path("scancode", "json")
        scan3.write_text("")
        summary2 = self.project1.get_output_file_path("summary", "json")
        summary2.write_text("")

        self.assertIsNone(self.project1.get_latest_output("none"))
        self.assertEqual(scan3, self.project1.get_latest_output("scancode"))
        self.assertEqual(summary2, self.project1.get_latest_output("summary"))

    def test_scanpipe_project_model_write_input_file(self):
        self.assertEqual([], self.project1.input_files)

        uploaded_file = SimpleUploadedFile("file.ext", content=b"content")
        self.project1.write_input_file(uploaded_file)

        self.assertEqual(["file.ext"], self.project1.input_files)

    def test_scanpipe_project_model_copy_input_from(self):
        self.assertEqual([], self.project1.input_files)

        _, input_location = tempfile.mkstemp()
        input_filename = Path(input_location).name

        self.project1.copy_input_from(input_location)
        self.assertEqual([input_filename], self.project1.input_files)
        self.assertTrue(Path(input_location).exists())

    def test_scanpipe_project_model_move_input_from(self):
        self.assertEqual([], self.project1.input_files)

        _, input_location = tempfile.mkstemp()
        input_filename = Path(input_location).name

        self.project1.move_input_from(input_location)
        self.assertEqual([input_filename], self.project1.input_files)
        self.assertFalse(Path(input_location).exists())

    def test_scanpipe_project_model_inputs_with_source(self):
        inputs, missing_inputs = self.project1.inputs_with_source
        self.assertEqual([], inputs)
        self.assertEqual({}, missing_inputs)

        uploaded_file = SimpleUploadedFile("file.ext", content=b"content")
        self.project1.add_uploads([uploaded_file])
        self.project1.copy_input_from(self.data_location / "notice.NOTICE")
        self.project1.add_input_source(filename="missing.zip", source="uploaded")

        inputs, missing_inputs = self.project1.inputs_with_source
        sha256_1 = "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73"
        sha256_2 = "b323607418a36b5bd700fcf52ae9ca49f82ec6359bc4b89b1b2d73cf75321757"
        expected = [
            {
                "is_file": True,
                "name": "file.ext",
                "sha256": sha256_1,
                "size": 7,
                "source": "uploaded",
            },
            {
                "is_file": True,
                "name": "notice.NOTICE",
                "sha256": sha256_2,
                "size": 1178,
                "source": "not_found",
            },
        ]

        def sort_by_name(x):
            return x.get("name")

        self.assertEqual(
            sorted(expected, key=sort_by_name), sorted(inputs, key=sort_by_name)
        )
        self.assertEqual({"missing.zip": "uploaded"}, missing_inputs)

    def test_scanpipe_project_model_can_change_inputs(self):
        self.assertTrue(self.project1.can_change_inputs)

        run = self.project1.add_pipeline("docker")
        self.project1 = Project.objects.get(uuid=self.project1.uuid)
        self.assertTrue(self.project1.can_change_inputs)

        run.task_start_date = timezone.now()
        run.save()
        self.project1 = Project.objects.get(uuid=self.project1.uuid)
        self.assertFalse(self.project1.can_change_inputs)

    def test_scanpipe_project_model_add_input_source(self):
        self.assertEqual({}, self.project1.input_sources)

        self.project1.add_input_source("filename", "source", save=True)
        self.project1.refresh_from_db()
        self.assertEqual({"filename": "source"}, self.project1.input_sources)

    def test_scanpipe_project_model_delete_input(self):
        self.assertEqual({}, self.project1.input_sources)
        self.assertEqual([], list(self.project1.inputs()))
        deleted = self.project1.delete_input(name="not_existing")
        self.assertFalse(deleted)

        file_location = self.data_location / "notice.NOTICE"
        copy_input(file_location, self.project1.input_path)
        self.project1.add_input_source(
            filename=file_location.name, source="uploaded", save=True
        )
        self.project1.refresh_from_db()
        self.assertEqual({file_location.name: "uploaded"}, self.project1.input_sources)
        self.assertEqual(
            [file_location.name], [path.name for path in self.project1.inputs()]
        )

        deleted = self.project1.delete_input(name=file_location.name)
        self.assertTrue(deleted)
        self.project1.refresh_from_db()
        self.assertEqual({}, self.project1.input_sources)
        self.assertEqual([], list(self.project1.inputs()))

    def test_scanpipe_project_model_add_downloads(self):
        file_location = self.data_location / "notice.NOTICE"
        copy_input(file_location, self.project1.tmp_path)

        download = Download(
            uri="https://example.com/filename.zip",
            directory="",
            filename="notice.NOTICE",
            path=self.project1.tmp_path / "notice.NOTICE",
            size="",
            sha1="",
            md5="",
        )

        self.project1.add_downloads([download])

        inputs, missing_inputs = self.project1.inputs_with_source
        sha256 = "b323607418a36b5bd700fcf52ae9ca49f82ec6359bc4b89b1b2d73cf75321757"
        expected = [
            {
                "is_file": True,
                "name": "notice.NOTICE",
                "sha256": sha256,
                "size": 1178,
                "source": "https://example.com/filename.zip",
            }
        ]
        self.assertEqual(expected, inputs)
        self.assertEqual({}, missing_inputs)

    def test_scanpipe_project_model_add_uploads(self):
        uploaded_file = SimpleUploadedFile("file.ext", content=b"content")
        self.project1.add_uploads([uploaded_file])

        inputs, missing_inputs = self.project1.inputs_with_source
        sha256 = "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73"
        expected = [
            {
                "name": "file.ext",
                "is_file": True,
                "sha256": sha256,
                "size": 7,
                "source": "uploaded",
            }
        ]
        self.assertEqual(expected, inputs)
        self.assertEqual({}, missing_inputs)

    def test_scanpipe_project_model_add_webhook_subscription(self):
        self.assertEqual(0, self.project1.webhooksubscriptions.count())
        self.project1.add_webhook_subscription("https://localhost")
        self.assertEqual(1, self.project1.webhooksubscriptions.count())

    def test_scanpipe_project_model_get_next_run(self):
        self.assertEqual(None, self.project1.get_next_run())

        run1 = self.create_run()
        run2 = self.create_run()
        self.assertEqual(run1, self.project1.get_next_run())

        run1.task_start_date = timezone.now()
        run1.save()
        self.assertEqual(run2, self.project1.get_next_run())

        run2.task_start_date = timezone.now()
        run2.save()
        self.assertEqual(None, self.project1.get_next_run())

    def test_scanpipe_project_model_raise_if_run_in_progress(self):
        run1 = self.create_run()
        self.assertIsNone(self.project1._raise_if_run_in_progress())

        run1.set_task_started(task_id=1)
        with self.assertRaises(RunInProgressError):
            self.project1._raise_if_run_in_progress()

        with self.assertRaises(RunInProgressError):
            self.project1.archive()

        with self.assertRaises(RunInProgressError):
            self.project1.delete()

        with self.assertRaises(RunInProgressError):
            self.project1.reset()

    def test_scanpipe_project_queryset_with_counts(self):
        self.project_asgiref.add_error("error 1", "model")
        self.project_asgiref.add_error("error 2", "model")

        project_qs = Project.objects.with_counts(
            "codebaseresources",
            "discoveredpackages",
            "projectmessages",
        )

        project = project_qs.get(pk=self.project_asgiref.pk)
        self.assertEqual(18, project.codebaseresources_count)
        self.assertEqual(18, project.codebaseresources.count())
        self.assertEqual(2, project.discoveredpackages_count)
        self.assertEqual(2, project.discoveredpackages.count())
        self.assertEqual(2, project.projectmessages_count)
        self.assertEqual(2, project.projectmessages.count())

    def test_scanpipe_project_related_queryset_get_or_none(self):
        self.assertIsNone(CodebaseResource.objects.get_or_none(path="path/"))
        self.assertIsNone(DiscoveredPackage.objects.get_or_none(name="name"))

    def test_scanpipe_project_get_codebase_config_directory(self):
        self.assertIsNone(self.project1.get_codebase_config_directory())
        (self.project1.codebase_path / settings.SCANCODEIO_CONFIG_DIR).mkdir()
        config_directory = str(self.project1.get_codebase_config_directory())
        self.assertTrue(config_directory.endswith("codebase/.scancode"))

    def test_scanpipe_project_get_input_config_file(self):
        self.assertIsNone(self.project1.get_input_config_file())
        config_file = self.project1.input_path / settings.SCANCODEIO_CONFIG_FILE
        config_file.touch()
        config_file_location = str(self.project1.get_input_config_file())
        self.assertTrue(config_file_location.endswith("input/scancode-config.yml"))

    def test_scanpipe_project_get_settings_as_yml(self):
        self.assertEqual("{}\n", self.project1.get_settings_as_yml())

        test_config_file = self.data_location / "settings" / "scancode-config.yml"
        config_file = copy_input(test_config_file, self.project1.input_path)
        env_from_test_config = self.project1.get_env().copy()
        self.project1.settings = env_from_test_config
        self.project1.save()

        config_file.write_text(self.project1.get_settings_as_yml())
        self.assertEqual(env_from_test_config, self.project1.get_env())

    def test_scanpipe_project_get_env(self):
        self.assertEqual({}, self.project1.get_env())

        test_config_file = self.data_location / "settings" / "scancode-config.yml"
        copy_input(test_config_file, self.project1.input_path)

        expected = {
            "ignored_patterns": ["*.img", "docs/*", "*/tests/*"],
            "extract_recursively": False,
        }
        self.assertEqual(expected, self.project1.get_env())

        config = {"extract_recursively": True}
        self.project1.settings = config
        self.project1.save()
        expected = {
            "ignored_patterns": ["*.img", "docs/*", "*/tests/*"],
            "extract_recursively": True,
        }
        self.assertEqual(expected, self.project1.get_env())

    def test_scanpipe_project_get_env_invalid_yml_content(self):
        config_file = self.project1.input_path / settings.SCANCODEIO_CONFIG_FILE
        config_file.write_text("{*this is not valid yml*}")

        config_file_location = str(self.project1.get_input_config_file())
        self.assertTrue(config_file_location.endswith("input/scancode-config.yml"))
        self.assertEqual({}, self.project1.get_env())

    def test_scanpipe_project_model_labels(self):
        self.project1.labels.add("label1", "label2")
        self.assertEqual(2, UUIDTaggedItem.objects.count())
        self.assertEqual(["label1", "label2"], sorted(self.project1.labels.names()))

        self.project1.labels.remove("label1")
        self.assertEqual(1, UUIDTaggedItem.objects.count())
        self.assertEqual(["label2"], sorted(self.project1.labels.names()))

        self.project1.labels.clear()
        self.assertEqual(0, UUIDTaggedItem.objects.count())

    def test_scanpipe_model_update_mixin(self):
        resource = CodebaseResource.objects.create(project=self.project1, path="file")
        self.assertEqual("", resource.status)

        with CaptureQueriesContext(connection) as queries_context:
            resource.update(status="updated")
        self.assertEqual(1, len(queries_context.captured_queries))
        sql = queries_context.captured_queries[0]["sql"]
        expected = """UPDATE "scanpipe_codebaseresource" SET "status" = 'updated'"""
        self.assertTrue(sql.startswith(expected))

        resource.refresh_from_db()
        self.assertEqual("updated", resource.status)

        package = DiscoveredPackage.objects.create(project=self.project1)
        purl_data = DiscoveredPackage.extract_purl_data(package_data1)

        with CaptureQueriesContext(connection) as queries_context:
            package.update(**purl_data)
        self.assertEqual(1, len(queries_context.captured_queries))
        sql = queries_context.captured_queries[0]["sql"]
        expected = (
            'UPDATE "scanpipe_discoveredpackage" SET "type" = "deb", '
            '"namespace" = "debian", "name" = "adduser", "version" = "3.118", '
            '"qualifiers" = "arch=all", "subpath" = ""'
        )
        self.assertTrue(sql.replace("'", '"').startswith(expected))

        package.refresh_from_db()
        self.assertEqual("pkg:deb/debian/adduser@3.118?arch=all", package.package_url)

    def test_scanpipe_model_posix_regex_to_django_regex_lookup(self):
        test_data = [
            ("", r"^$"),
            # Single segment
            ("example", r"^example$"),
            # Single segment with dot
            ("example.xml", r"^example\.xml$"),
            # Single segment with prefix dot
            (".example", r"^\.example$"),
            # Single segment wildcard with dot
            ("*.xml", r"^.*\.xml$"),
            ("*_map.xml", r"^.*_map\.xml$"),
            # Single segment wildcard with slash
            ("*/.example", r"^.*/\.example$"),
            ("*/readme.html", r"^.*/readme\.html$"),
            # Single segment with wildcards
            ("*README*", r"^.*README.*$"),
            # Multi segments
            ("path/to/file", r"^path/to/file$"),
            # Multi segments with wildcards
            ("path/*/file", r"^path/.*/file$"),
            ("*path/to/*", r"^.*path/to/.*$"),
            # Multiple segments and wildcards
            ("path/*/to/*/file.*", r"^path/.*/to/.*/file\..*$"),
            # Escaped character
            (r"path\*\.txt", r"^path\\.*\\\.txt$"),
            (r"path/*/foo$.class", r"^path/.*/foo\$\.class$"),
            # Question mark
            ("path/file?", r"^path/file.$"),
        ]

        for pattern, expected in test_data:
            self.assertEqual(expected, posix_regex_to_django_regex_lookup(pattern))

    def test_scanpipe_run_model_set_scancodeio_version(self):
        run1 = Run.objects.create(project=self.project1)
        self.assertEqual("", run1.scancodeio_version)

        run1.set_scancodeio_version()
        run1 = Run.objects.get(pk=run1.pk)
        self.assertEqual(scancodeio_version, run1.scancodeio_version)

        with self.assertRaises(ValueError) as cm:
            run1.set_scancodeio_version()
        self.assertIn("Field scancodeio_version already set to", str(cm.exception))

    def test_scanpipe_run_model_set_current_step(self):
        run1 = Run.objects.create(project=self.project1)
        self.assertEqual("", run1.current_step)

        run1.set_current_step("a" * 300)
        run1 = Run.objects.get(pk=run1.pk)
        self.assertEqual(256, len(run1.current_step))

        run1.set_current_step("")
        run1 = Run.objects.get(pk=run1.pk)
        self.assertEqual("", run1.current_step)

    def test_scanpipe_run_model_pipeline_class_property(self):
        run1 = Run.objects.create(project=self.project1, pipeline_name="do_nothing")
        self.assertEqual(DoNothing, run1.pipeline_class)

    def test_scanpipe_run_model_make_pipeline_instance(self):
        run1 = Run.objects.create(project=self.project1, pipeline_name="do_nothing")
        pipeline_instance = run1.make_pipeline_instance()
        self.assertTrue(isinstance(pipeline_instance, DoNothing))

    def test_scanpipe_run_model_task_execution_time_property(self):
        run1 = self.create_run()

        self.assertIsNone(run1.execution_time)

        run1.task_start_date = datetime(1984, 10, 10, 10, 10, 10, tzinfo=timezone.utc)
        run1.save()
        self.assertIsNone(run1.execution_time)

        run1.task_end_date = datetime(1984, 10, 10, 10, 10, 35, tzinfo=timezone.utc)
        run1.save()
        self.assertEqual(25.0, run1.execution_time)

        run1.set_task_staled()
        run1.refresh_from_db()
        self.assertIsNone(run1.execution_time)

    def test_scanpipe_run_model_execution_time_for_display_property(self):
        run1 = self.create_run()

        self.assertIsNone(run1.execution_time_for_display)

        run1.task_start_date = datetime(1984, 10, 10, 10, 10, 10, tzinfo=timezone.utc)
        run1.save()
        self.assertIsNone(run1.execution_time_for_display)

        run1.task_end_date = datetime(1984, 10, 10, 10, 10, 35, tzinfo=timezone.utc)
        run1.save()
        self.assertEqual("25 seconds", run1.execution_time_for_display)

        run1.task_end_date = datetime(1984, 10, 10, 10, 12, 35, tzinfo=timezone.utc)
        run1.save()
        self.assertEqual("145 seconds (2.4 minutes)", run1.execution_time_for_display)

        run1.task_end_date = datetime(1984, 10, 10, 11, 12, 35, tzinfo=timezone.utc)
        run1.save()
        self.assertEqual("3745 seconds (1.0 hours)", run1.execution_time_for_display)

    def test_scanpipe_run_model_reset_task_values_method(self):
        run1 = self.create_run(
            task_id=uuid.uuid4(),
            task_start_date=timezone.now(),
            task_end_date=timezone.now(),
            task_exitcode=0,
            task_output="Output",
        )

        run1.reset_task_values()
        self.assertIsNone(run1.task_id)
        self.assertIsNone(run1.task_start_date)
        self.assertIsNone(run1.task_end_date)
        self.assertIsNone(run1.task_exitcode)
        self.assertEqual("", run1.task_output)

    def test_scanpipe_run_model_set_task_started_method(self):
        run1 = self.create_run()

        task_id = uuid.uuid4()
        run1.set_task_started(task_id)

        run1 = Run.objects.get(pk=run1.pk)
        self.assertEqual(task_id, run1.task_id)
        self.assertTrue(run1.task_start_date)
        self.assertFalse(run1.task_end_date)

    def test_scanpipe_run_model_set_task_ended_method(self):
        run1 = self.create_run()

        # Set a value for `log` on the DB record without impacting the `run1` instance.
        Run.objects.get(pk=run1.pk).append_to_log("entry in log")
        self.assertEqual("", run1.log)

        with CaptureQueriesContext(connection) as queries_context:
            run1.set_task_ended(exitcode=0, output="output")

        # Ensure that the SQL UPDATE was limited to `update_fields`
        self.assertEqual(1, len(queries_context.captured_queries))
        sql = queries_context.captured_queries[0]["sql"]
        self.assertTrue(sql.startswith('UPDATE "scanpipe_run" SET "task_end_date"'))
        self.assertIn("task_exitcode", sql)
        self.assertIn("task_output", sql)
        self.assertNotIn("log", sql)

        run1 = Run.objects.get(pk=run1.pk)
        self.assertEqual(0, run1.task_exitcode)
        self.assertEqual("output", run1.task_output)
        self.assertTrue(run1.task_end_date)
        # Ensure the initial value for `log` was not overriden during the
        # `set_task_ended.save()`
        self.assertIn("entry in log", run1.log)

    def test_scanpipe_run_model_set_task_methods(self):
        run1 = self.create_run()
        self.assertIsNone(run1.task_id)
        self.assertEqual(Run.Status.NOT_STARTED, run1.status)

        run1.set_task_queued()
        run1.refresh_from_db()
        self.assertEqual(run1.pk, run1.task_id)
        self.assertEqual(Run.Status.QUEUED, run1.status)

        run1.set_task_started(run1.pk)
        self.assertTrue(run1.task_start_date)
        self.assertEqual(Run.Status.RUNNING, run1.status)

        run1.set_task_ended(exitcode=0)
        self.assertTrue(run1.task_end_date)
        self.assertEqual(Run.Status.SUCCESS, run1.status)
        self.assertTrue(run1.task_succeeded)

        run1.set_task_ended(exitcode=1)
        self.assertEqual(Run.Status.FAILURE, run1.status)
        self.assertTrue(run1.task_failed)

        run1.set_task_staled()
        self.assertEqual(Run.Status.STALE, run1.status)
        self.assertTrue(run1.task_staled)

        run1.set_task_stopped()
        self.assertEqual(Run.Status.STOPPED, run1.status)
        self.assertTrue(run1.task_stopped)

    @override_settings(SCANCODEIO_ASYNC=False)
    def test_scanpipe_run_model_stop_task_method(self):
        run1 = self.create_run()
        run1.stop_task()
        self.assertEqual(Run.Status.STOPPED, run1.status)
        self.assertTrue(run1.task_stopped)
        self.assertIn("Stop task requested", run1.log)

    @override_settings(SCANCODEIO_ASYNC=False)
    def test_scanpipe_run_model_delete_task_method(self):
        run1 = self.create_run()
        run1.delete_task()
        self.assertFalse(Run.objects.filter(pk=run1.pk).exists())
        self.assertFalse(self.project1.runs.exists())

    def test_scanpipe_run_model_queryset_methods(self):
        now = timezone.now()

        running = self.create_run(
            pipeline="running", task_start_date=now, task_id=uuid.uuid4()
        )
        not_started = self.create_run(pipeline="not_started")
        queued = self.create_run(pipeline="queued", task_id=uuid.uuid4())
        executed = self.create_run(
            pipeline="executed", task_start_date=now, task_end_date=now
        )
        succeed = self.create_run(
            pipeline="succeed", task_start_date=now, task_end_date=now, task_exitcode=0
        )
        failed = self.create_run(
            pipeline="failed", task_start_date=now, task_end_date=now, task_exitcode=1
        )

        qs = self.project1.runs.has_start_date()
        self.assertQuerySetEqual(qs, [running, executed, succeed, failed])

        qs = self.project1.runs.not_started()
        self.assertQuerySetEqual(qs, [not_started])

        qs = self.project1.runs.queued()
        self.assertQuerySetEqual(qs, [queued])

        qs = self.project1.runs.running()
        self.assertQuerySetEqual(qs, [running])

        qs = self.project1.runs.executed()
        self.assertQuerySetEqual(qs, [executed, succeed, failed])

        qs = self.project1.runs.not_executed()
        self.assertQuerySetEqual(qs, [running, not_started, queued])

        qs = self.project1.runs.succeed()
        self.assertQuerySetEqual(qs, [succeed])

        qs = self.project1.runs.failed()
        self.assertQuerySetEqual(qs, [failed])

        queued_or_running_qs = self.project1.runs.queued_or_running()
        self.assertQuerySetEqual(queued_or_running_qs, [running, queued])

    def test_scanpipe_run_model_status_property(self):
        now = timezone.now()

        running = self.create_run(task_start_date=now)
        not_started = self.create_run()
        queued = self.create_run(task_id=uuid.uuid4())
        succeed = self.create_run(
            task_start_date=now, task_end_date=now, task_exitcode=0
        )
        failed = self.create_run(
            task_start_date=now, task_end_date=now, task_exitcode=1
        )

        self.assertEqual(Run.Status.RUNNING, running.status)
        self.assertEqual(Run.Status.NOT_STARTED, not_started.status)
        self.assertEqual(Run.Status.QUEUED, queued.status)
        self.assertEqual(Run.Status.SUCCESS, succeed.status)
        self.assertEqual(Run.Status.FAILURE, failed.status)

    def test_scanpipe_run_model_get_previous_runs(self):
        run1 = self.create_run()
        run2 = self.create_run()
        run3 = self.create_run()
        self.assertQuerySetEqual([], run1.get_previous_runs())
        self.assertQuerySetEqual([run1], run2.get_previous_runs())
        self.assertQuerySetEqual([run1, run2], run3.get_previous_runs())

    def test_scanpipe_run_model_can_start(self):
        run1 = self.create_run()
        run2 = self.create_run()
        run3 = self.create_run()

        self.assertTrue(run1.can_start)
        self.assertFalse(run2.can_start)
        self.assertFalse(run3.can_start)

        run1.set_task_started(run1.pk)
        self.assertFalse(run1.can_start)
        self.assertFalse(run2.can_start)
        self.assertFalse(run3.can_start)

        run1.set_task_ended(exitcode=0)
        self.assertFalse(run1.can_start)
        self.assertTrue(run2.can_start)
        self.assertFalse(run3.can_start)

        run2.set_task_stopped()
        self.assertFalse(run1.can_start)
        self.assertFalse(run2.can_start)
        self.assertTrue(run3.can_start)

        run1.reset_task_values()
        run1.set_task_started(run1.pk)
        self.assertFalse(run1.can_start)
        self.assertFalse(run2.can_start)
        self.assertFalse(run3.can_start)

    @override_settings(SCANCODEIO_ASYNC=True)
    @mock.patch("scanpipe.models.Run.execute_task_async")
    @mock.patch("scanpipe.models.Run.job_status", new_callable=mock.PropertyMock)
    def test_scanpipe_run_model_sync_with_job_async_mode(
        self, mock_job_status, mock_execute_task
    ):
        queued = self.create_run(task_id=uuid.uuid4())
        self.assertEqual(Run.Status.QUEUED, queued.status)
        mock_job_status.return_value = None
        queued.sync_with_job()
        mock_execute_task.assert_called_once()

        running = self.create_run(task_id=uuid.uuid4(), task_start_date=timezone.now())
        self.assertEqual(Run.Status.RUNNING, running.status)
        mock_job_status.return_value = None
        running.sync_with_job()
        running.refresh_from_db()
        self.assertTrue(running.task_staled)

        running = self.create_run(task_id=uuid.uuid4(), task_start_date=timezone.now())
        mock_job_status.return_value = JobStatus.STOPPED
        running.sync_with_job()
        running.refresh_from_db()
        self.assertTrue(running.task_stopped)

        running = self.create_run(task_id=uuid.uuid4(), task_start_date=timezone.now())
        mock_job_status.return_value = JobStatus.FAILED
        running.sync_with_job()
        running.refresh_from_db()
        self.assertTrue(running.task_failed)
        expected = "Job was moved to the FailedJobRegistry during cleanup"
        self.assertEqual(expected, running.task_output)

        running = self.create_run(task_id=uuid.uuid4(), task_start_date=timezone.now())
        mock_job_status.return_value = "Something else"
        running.sync_with_job()
        running.refresh_from_db()
        self.assertTrue(running.task_staled)

    @override_settings(SCANCODEIO_ASYNC=False)
    @mock.patch("scanpipe.models.Run.execute_task_async")
    def test_scanpipe_run_model_sync_with_job_sync_mode(self, mock_execute_task):
        queued = self.create_run(task_id=uuid.uuid4())
        self.assertEqual(Run.Status.QUEUED, queued.status)
        queued.sync_with_job()
        mock_execute_task.assert_called_once()

        running = self.create_run(task_id=uuid.uuid4(), task_start_date=timezone.now())
        self.assertEqual(Run.Status.RUNNING, running.status)
        running.sync_with_job()
        running.refresh_from_db()
        self.assertTrue(running.task_staled)

    def test_scanpipe_run_model_append_to_log(self):
        run1 = self.create_run()

        with self.assertRaises(ValueError):
            run1.append_to_log("multiline\nmessage")

        run1.append_to_log("line1")
        run1.append_to_log("line2")

        run1.refresh_from_db()
        self.assertEqual("line1\nline2\n", run1.log)

    @mock.patch("scanpipe.models.WebhookSubscription.deliver")
    def test_scanpipe_run_model_deliver_project_subscriptions(self, mock_deliver):
        self.project1.add_webhook_subscription("https://localhost")
        run1 = self.create_run()
        run1.deliver_project_subscriptions()
        mock_deliver.assert_called_once_with(pipeline_run=run1)

    def test_scanpipe_run_model_profile_method(self):
        run1 = self.create_run()
        self.assertIsNone(run1.profile())

        run1.log = (
            "2021-02-05 12:46:47.63 Pipeline [ScanCodebase] starting\n"
            "2021-02-05 12:46:47.63 Step [copy_inputs_to_codebase_directory] starting\n"
            "2021-02-05 12:46:47.63 Step [copy_inputs_to_codebase_directory]"
            " completed in 0.00 seconds\n"
            "2021-02-05 12:46:47.63 Step [extract_archives] starting\n"
            "2021-02-05 12:46:48.13 Step [extract_archives] completed in 0.50 seconds\n"
            "2021-02-05 12:46:48.14 Step [run_scancode] starting\n"
            "2021-02-05 12:46:52.59 Step [run_scancode] completed in 4.45 seconds\n"
            "2021-02-05 12:46:52.59 Step [build_inventory_from_scan] starting\n"
            "2021-02-05 12:46:52.75 Step [build_inventory_from_scan]"
            " completed in 0.16 seconds\n"
            "2021-02-05 12:46:52.75 Step [csv_output] starting\n"
            "2021-02-05 12:46:52.82 Step [csv_output] completed in 0.06 seconds\n"
            "2021-02-05 12:46:52.82 Pipeline completed\n"
        )
        run1.save()
        self.assertIsNone(run1.profile())

        run1.task_exitcode = 0
        run1.save()

        expected = {
            "build_inventory_from_scan": 0.16,
            "copy_inputs_to_codebase_directory": 0.0,
            "csv_output": 0.06,
            "extract_archives": 0.5,
            "run_scancode": 4.45,
        }
        self.assertEqual(expected, run1.profile())

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertIsNone(run1.profile(print_results=True))

        expected = (
            "copy_inputs_to_codebase_directory  0.0 seconds 0.0%\n"
            "extract_archives                   0.5 seconds 9.7%\n"
            "\x1b[41;37mrun_scancode                       4.45 seconds 86.1%\x1b[m\n"
            "build_inventory_from_scan          0.16 seconds 3.1%\n"
            "csv_output                         0.06 seconds 1.2%\n"
        )
        self.assertEqual(expected, output.getvalue())

    def test_scanpipe_codebase_resource_model_methods(self):
        resource = CodebaseResource.objects.create(
            project=self.project1, path="filename.ext"
        )

        self.assertEqual(
            self.project1.codebase_path / resource.path, resource.location_path
        )
        self.assertEqual(
            f"{self.project1.codebase_path}/{resource.path}", resource.location
        )

        with open(resource.location, "w") as f:
            f.write("content")
        self.assertEqual("content\n", resource.file_content)

        package = DiscoveredPackage.objects.create(project=self.project1)
        resource.discovered_packages.add(package)
        self.assertEqual([str(package.uuid)], resource.for_packages)

    def test_scanpipe_codebase_resource_model_file_content(self):
        resource = self.project1.codebaseresources.create(path="filename.ext")

        with open(resource.location, "w") as f:
            f.write("content")
        self.assertEqual("content\n", resource.file_content)

        file_with_long_lines = self.data_location / "decompose_l_u_8hpp_source.html"
        copy_input(file_with_long_lines, self.project1.codebase_path)

        resource.update(path="decompose_l_u_8hpp_source.html")
        line_count = len(resource.file_content.split("\n"))
        self.assertEqual(101, line_count)

    def test_scanpipe_codebase_resource_model_compliance_alert(self):
        scanpipe_app.license_policies_index = license_policies_index
        resource = CodebaseResource.objects.create(project=self.project1, path="file")
        self.assertEqual("", resource.compliance_alert)

        license_expression = "bsd-new"
        self.assertNotIn(license_expression, scanpipe_app.license_policies_index)
        resource.update(detected_license_expression=license_expression)
        self.assertEqual("missing", resource.compliance_alert)

        license_expression = "apache-2.0"
        self.assertIn(license_expression, scanpipe_app.license_policies_index)
        resource.update(detected_license_expression=license_expression)
        self.assertEqual("ok", resource.compliance_alert)

        license_expression = "mpl-2.0"
        self.assertIn(license_expression, scanpipe_app.license_policies_index)
        resource.update(detected_license_expression=license_expression)
        self.assertEqual("warning", resource.compliance_alert)

        license_expression = "gpl-3.0"
        self.assertIn(license_expression, scanpipe_app.license_policies_index)
        resource.update(detected_license_expression=license_expression)
        self.assertEqual("error", resource.compliance_alert)

        license_expression = "apache-2.0 AND mpl-2.0 OR gpl-3.0"
        resource.update(detected_license_expression=license_expression)
        self.assertEqual("error", resource.compliance_alert)

        # Reset the index value
        scanpipe_app.license_policies_index = None

    def test_scanpipe_codebase_resource_model_compliance_alert_update_fields(self):
        scanpipe_app.license_policies_index = license_policies_index
        resource = CodebaseResource.objects.create(project=self.project1, path="file")
        self.assertEqual("", resource.compliance_alert)

        # Ensure the "compliance_alert" field is appended to `update_fields`
        resource.detected_license_expression = "apache-2.0"
        resource.save(update_fields=["detected_license_expression"])
        resource.refresh_from_db()
        self.assertEqual("ok", resource.compliance_alert)

        # Reset the index value
        scanpipe_app.license_policies_index = None

    def test_scanpipe_scan_fields_model_mixin_methods(self):
        expected = [
            "detected_license_expression",
            "detected_license_expression_spdx",
            "license_detections",
            "license_clues",
            "percentage_of_license_text",
            "copyrights",
            "holders",
            "authors",
            "emails",
            "urls",
        ]
        self.assertEqual(expected, CodebaseResource.scan_fields())

        resource = CodebaseResource.objects.create(
            project=self.project1, path="filename.ext"
        )

        scan_results = {
            "detected_license_expression": "mit",
            "name": "name",
            "non_resource_field": "value",
        }
        resource.set_scan_results(scan_results, status="scanned")
        resource.refresh_from_db()
        self.assertEqual("", resource.name)
        self.assertEqual("mit", resource.detected_license_expression)
        self.assertEqual("scanned", resource.status)

        resource2 = CodebaseResource.objects.create(project=self.project1, path="file2")
        resource2.copy_scan_results(from_instance=resource)
        resource.refresh_from_db()
        self.assertEqual("mit", resource2.detected_license_expression)

    def test_scanpipe_codebase_resource_queryset_methods(self):
        CodebaseResource.objects.all().delete()

        file = CodebaseResource.objects.create(
            project=self.project1, type=CodebaseResource.Type.FILE, path="file"
        )
        directory = CodebaseResource.objects.create(
            project=self.project1,
            type=CodebaseResource.Type.DIRECTORY,
            path="directory",
        )
        symlink = CodebaseResource.objects.create(
            project=self.project1, type=CodebaseResource.Type.SYMLINK, path="symlink"
        )

        self.assertTrue(file.is_file)
        self.assertFalse(file.is_dir)
        self.assertFalse(file.is_symlink)

        self.assertFalse(directory.is_file)
        self.assertTrue(directory.is_dir)
        self.assertFalse(directory.is_symlink)

        self.assertFalse(symlink.is_file)
        self.assertFalse(symlink.is_dir)
        self.assertTrue(symlink.is_symlink)

        qs = CodebaseResource.objects.files()
        self.assertEqual(1, len(qs))
        self.assertIn(file, qs)

        qs = CodebaseResource.objects.empty()
        self.assertEqual(3, len(qs))
        qs = CodebaseResource.objects.not_empty()
        self.assertEqual(0, len(qs))
        file.update(size=1)
        qs = CodebaseResource.objects.empty()
        self.assertEqual(2, len(qs))
        self.assertNotIn(file, qs)
        qs = CodebaseResource.objects.not_empty()
        self.assertEqual(1, len(qs))
        file.update(size=0)
        qs = CodebaseResource.objects.empty()
        self.assertEqual(3, len(qs))

        qs = CodebaseResource.objects.directories()
        self.assertEqual(1, len(qs))
        self.assertIn(directory, qs)

        qs = CodebaseResource.objects.symlinks()
        self.assertEqual(1, len(qs))
        self.assertIn(symlink, qs)

        qs = CodebaseResource.objects.without_symlinks()
        self.assertEqual(2, len(qs))
        self.assertIn(file, qs)
        self.assertIn(directory, qs)
        self.assertNotIn(symlink, qs)

        file.update(license_detections=[{"license_expression": "bsd-new"}])
        qs = CodebaseResource.objects.has_license_detections()
        self.assertEqual(1, len(qs))
        self.assertIn(file, qs)
        self.assertNotIn(directory, qs)
        self.assertNotIn(symlink, qs)

        qs = CodebaseResource.objects.has_no_license_detections()
        self.assertEqual(2, len(qs))
        self.assertNotIn(file, qs)
        self.assertIn(directory, qs)
        self.assertIn(symlink, qs)

        qs = CodebaseResource.objects.unknown_license()
        self.assertEqual(0, len(qs))

        file.update(detected_license_expression="gpl-3.0 AND unknown")
        qs = CodebaseResource.objects.unknown_license()
        self.assertEqual(1, len(qs))
        self.assertIn(file, qs)

        qs = CodebaseResource.objects.has_value("mime_type")
        self.assertEqual(0, qs.count())
        qs = CodebaseResource.objects.has_value("type")
        self.assertEqual(3, qs.count())
        qs = CodebaseResource.objects.has_value("detected_license_expression")
        self.assertEqual(1, qs.count())
        qs = CodebaseResource.objects.has_value("copyrights")
        self.assertEqual(0, qs.count())

        self.assertEqual(0, CodebaseResource.objects.in_package().count())
        self.assertEqual(3, CodebaseResource.objects.not_in_package().count())

        file.create_and_add_package(package_data1)
        file.create_and_add_package(package_data2)
        self.assertEqual(1, CodebaseResource.objects.in_package().count())
        self.assertEqual(2, CodebaseResource.objects.not_in_package().count())

        self.assertEqual(0, CodebaseResource.objects.has_relation().count())
        self.assertEqual(3, CodebaseResource.objects.has_no_relation().count())
        self.assertEqual(0, CodebaseResource.objects.has_many_relation().count())
        CodebaseRelation.objects.create(
            project=self.project1,
            from_resource=file,
            to_resource=directory,
        )
        self.assertEqual(2, CodebaseResource.objects.has_relation().count())
        self.assertEqual(1, CodebaseResource.objects.has_no_relation().count())
        self.assertEqual(0, CodebaseResource.objects.has_many_relation().count())

        CodebaseRelation.objects.create(
            project=self.project1,
            from_resource=file,
            to_resource=symlink,
        )
        self.assertEqual(1, CodebaseResource.objects.has_many_relation().count())

        self.assertEqual(0, CodebaseResource.objects.from_codebase().count())
        self.assertEqual(0, CodebaseResource.objects.to_codebase().count())
        file.update(tag="to")
        symlink.update(tag="to")
        directory.update(tag="from")
        self.assertEqual(1, CodebaseResource.objects.from_codebase().count())
        self.assertEqual(2, CodebaseResource.objects.to_codebase().count())

    def _create_resources_for_queryset_methods(self):
        resource1 = CodebaseResource.objects.create(project=self.project1, path="1")
        resource1.holders = [
            {"holder": "H1", "end_line": 51, "start_line": 50},
            {"holder": "H2", "end_line": 61, "start_line": 60},
        ]
        resource1.mime_type = "application/zip"
        resource1.save()

        resource2 = CodebaseResource.objects.create(project=self.project1, path="2")
        resource2.holders = [{"holder": "H3", "end_line": 558, "start_line": 556}]
        resource2.mime_type = "application/zip"
        resource2.save()

        resource3 = CodebaseResource.objects.create(project=self.project1, path="3")
        resource3.mime_type = "text/plain"
        resource3.save()

        return resource1, resource2, resource3

    def test_scanpipe_codebase_resource_queryset_json_field_contains(self):
        resource1, resource2, resource3 = self._create_resources_for_queryset_methods()

        qs = CodebaseResource.objects
        self.assertQuerySetEqual([resource2], qs.json_field_contains("holders", "H3"))
        self.assertQuerySetEqual([resource1], qs.json_field_contains("holders", "H1"))
        expected = [resource1, resource2]
        self.assertQuerySetEqual(expected, qs.json_field_contains("holders", "H"))

    def test_scanpipe_codebase_resource_queryset_json_list_contains(self):
        resource1, resource2, resource3 = self._create_resources_for_queryset_methods()
        qs = CodebaseResource.objects

        results = qs.json_list_contains("holders", "holder", ["H3"])
        self.assertQuerySetEqual([resource2], results)

        results = qs.json_list_contains("holders", "holder", ["H1"])
        self.assertQuerySetEqual([resource1], results)
        results = qs.json_list_contains("holders", "holder", ["H2"])
        self.assertQuerySetEqual([resource1], results)
        results = qs.json_list_contains("holders", "holder", ["H1", "H2"])
        self.assertQuerySetEqual([resource1], results)

        results = qs.json_list_contains("holders", "holder", ["H1", "H2", "H3"])
        self.assertQuerySetEqual([resource1, resource2], results)

        results = qs.json_list_contains("holders", "holder", ["H"])
        self.assertQuerySetEqual([], results)

    def test_scanpipe_codebase_resource_queryset_values_from_json_field(self):
        CodebaseResource.objects.all().delete()
        self._create_resources_for_queryset_methods()
        qs = CodebaseResource.objects

        results = qs.values_from_json_field("holders", "nothing")
        self.assertEqual(["", "", "", ""], results)

        results = qs.values_from_json_field("holders", "holder")
        self.assertEqual(["H1", "H2", "H3", ""], results)

    def test_scanpipe_codebase_resource_queryset_group_by(self):
        CodebaseResource.objects.all().delete()
        self._create_resources_for_queryset_methods()
        expected = [
            {"mime_type": "application/zip", "count": 2},
            {"mime_type": "text/plain", "count": 1},
        ]
        self.assertEqual(expected, list(CodebaseResource.objects.group_by("mime_type")))

    def test_scanpipe_codebase_resource_queryset_most_common_values(self):
        CodebaseResource.objects.all().delete()
        self._create_resources_for_queryset_methods()
        results = CodebaseResource.objects.most_common_values("mime_type", limit=1)
        self.assertQuerySetEqual(["application/zip"], results)

    def test_scanpipe_codebase_resource_queryset_less_common_values(self):
        CodebaseResource.objects.all().delete()
        self._create_resources_for_queryset_methods()
        CodebaseResource.objects.create(
            project=self.project1, path="4", mime_type="text/x-script.python"
        )

        results = CodebaseResource.objects.less_common_values("mime_type", limit=1)
        expected = ["text/plain", "text/x-script.python"]
        self.assertQuerySetEqual(expected, results, ordered=False)

    def test_scanpipe_codebase_resource_queryset_less_common(self):
        CodebaseResource.objects.all().delete()
        resource1, resource2, resource3 = self._create_resources_for_queryset_methods()
        resource4 = CodebaseResource.objects.create(
            project=self.project1, path="4", mime_type="text/x-script.python"
        )
        resource4.holders = [
            {"holder": "H1", "end_line": 51, "start_line": 50},
            {"holder": "H1", "end_line": 51, "start_line": 50},
            {"holder": "H2", "end_line": 51, "start_line": 50},
            {"holder": "H2", "end_line": 51, "start_line": 50},
        ]
        resource4.save()

        qs = CodebaseResource.objects
        results = qs.less_common("mime_type", limit=1)
        self.assertQuerySetEqual([resource3, resource4], results)

        results = qs.less_common("holders", limit=2)
        self.assertQuerySetEqual([resource2], results)

    def test_scanpipe_codebase_resource_queryset_path_pattern(self):
        make_resource_file(self.project1, path="example")
        make_resource_file(self.project1, path="example.xml")
        make_resource_file(self.project1, path=".example")
        make_resource_file(self.project1, path="example_map.js")
        make_resource_file(self.project1, path="dir/.example")
        make_resource_file(self.project1, path="dir/subdir/readme.html")
        make_resource_file(self.project1, path="foo$.class")

        patterns = [
            "example",
            "example.xml",
            ".example",
            "*.xml",
            "*_map.js",
            "*/.example",
            "*/readme.html",
            "*readme*",
            "dir/subdir/readme.html",
            "dir/*/readme.html",
            "*dir/subdir/*",
            "dir/*/readme.*",
            r"*$.class",
            "*readme.htm?",
        ]

        for pattern in patterns:
            qs = CodebaseResource.objects.path_pattern(pattern)
            self.assertEqual(1, qs.count(), pattern)

    def test_scanpipe_codebase_resource_descendants(self):
        path = "asgiref-3.3.0-py3-none-any.whl-extract/asgiref"
        resource = self.project_asgiref.codebaseresources.get(path=path)
        descendants = list(resource.descendants())
        self.assertEqual(9, len(descendants))
        self.assertNotIn(resource.path, descendants)
        expected = [
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref/__init__.py",
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref/compatibility.py",
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref/"
            "current_thread_executor.py",
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref/local.py",
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref/server.py",
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref/sync.py",
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref/testing.py",
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref/timeout.py",
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref/wsgi.py",
        ]
        self.assertEqual(expected, sorted([resource.path for resource in descendants]))

    def test_scanpipe_codebase_resource_children(self):
        path = "asgiref-3.3.0-py3-none-any.whl-extract"
        resource = self.project_asgiref.codebaseresources.get(path=path)
        children = list(resource.children())
        self.assertEqual(2, len(children))
        self.assertNotIn(resource.path, children)
        expected = [
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref",
            "asgiref-3.3.0-py3-none-any.whl-extract/asgiref-3.3.0.dist-info",
        ]
        self.assertEqual(expected, [resource.path for resource in children])

    def test_scanpipe_codebase_resource_add_package(self):
        resource = CodebaseResource.objects.create(project=self.project1, path="file")
        package = DiscoveredPackage.create_from_data(self.project1, package_data1)
        resource.add_package(package)
        self.assertEqual(1, resource.discovered_packages.count())
        self.assertEqual(package, resource.discovered_packages.get())

    def test_scanpipe_codebase_resource_create_and_add_package(self):
        resource = CodebaseResource.objects.create(project=self.project1, path="file")
        package = resource.create_and_add_package(package_data1)
        self.assertEqual(self.project1, package.project)
        self.assertEqual("pkg:deb/debian/adduser@3.118?arch=all", str(package))
        self.assertEqual(1, resource.discovered_packages.count())
        self.assertEqual(package, resource.discovered_packages.get())

    def test_scanpipe_codebase_resource_get_path_segments_with_subpath(self):
        resource = make_resource_file(self.project1, path="")
        self.assertEqual([], resource.get_path_segments_with_subpath())

        resource = make_resource_file(self.project1, path="root/subpath/file.txt")
        expected = [
            ("root", "root"),
            ("subpath", "root/subpath"),
            ("file.txt", "root/subpath/file.txt"),
        ]
        self.assertEqual(expected, resource.get_path_segments_with_subpath())

    def test_scanpipe_discovered_package_queryset_for_package_url(self):
        DiscoveredPackage.create_from_data(self.project1, package_data1)
        inputs = [
            ("pkg:deb/debian/adduser@3.118?arch=all", 1),
            ("pkg:deb/debian/adduser@3.118", 1),
            ("pkg:deb/debian/adduser", 1),
            ("pkg:deb/debian", 0),
            ("pkg:deb/debian/adduser@4", 0),
        ]

        for purl, expected_count in inputs:
            qs = DiscoveredPackage.objects.for_package_url(purl)
            self.assertEqual(expected_count, qs.count(), msg=purl)

    def test_scanpipe_discovered_package_queryset_vulnerable(self):
        p1 = DiscoveredPackage.create_from_data(self.project1, package_data1)
        p2 = DiscoveredPackage.create_from_data(self.project1, package_data2)
        p2.update(
            affected_by_vulnerabilities=[{"vulnerability_id": "VCID-cah8-awtr-aaad"}]
        )
        self.assertNotIn(p1, DiscoveredPackage.objects.vulnerable())
        self.assertIn(p2, DiscoveredPackage.objects.vulnerable())

    @skipIf(sys.platform != "linux", "Ordering differs on macOS.")
    def test_scanpipe_codebase_resource_model_walk_method(self):
        fixtures = self.data_location / "asgiref-3.3.0_walk_test_fixtures.json"
        call_command("loaddata", fixtures, **{"verbosity": 0})
        asgiref_root = self.project_asgiref.codebaseresources.get(
            path="asgiref-3.3.0.whl-extract"
        )

        topdown_paths = list(r.path for r in asgiref_root.walk(topdown=True))
        expected_topdown_paths = [
            "asgiref-3.3.0.whl-extract/asgiref",
            "asgiref-3.3.0.whl-extract/asgiref/compatibility.py",
            "asgiref-3.3.0.whl-extract/asgiref/current_thread_executor.py",
            "asgiref-3.3.0.whl-extract/asgiref/__init__.py",
            "asgiref-3.3.0.whl-extract/asgiref/local.py",
            "asgiref-3.3.0.whl-extract/asgiref/server.py",
            "asgiref-3.3.0.whl-extract/asgiref/sync.py",
            "asgiref-3.3.0.whl-extract/asgiref/testing.py",
            "asgiref-3.3.0.whl-extract/asgiref/timeout.py",
            "asgiref-3.3.0.whl-extract/asgiref/wsgi.py",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/LICENSE",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/METADATA",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/RECORD",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/top_level.txt",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/WHEEL",
        ]
        self.assertEqual(expected_topdown_paths, topdown_paths)

        bottom_up_paths = list(r.path for r in asgiref_root.walk(topdown=False))
        expected_bottom_up_paths = [
            "asgiref-3.3.0.whl-extract/asgiref/compatibility.py",
            "asgiref-3.3.0.whl-extract/asgiref/current_thread_executor.py",
            "asgiref-3.3.0.whl-extract/asgiref/__init__.py",
            "asgiref-3.3.0.whl-extract/asgiref/local.py",
            "asgiref-3.3.0.whl-extract/asgiref/server.py",
            "asgiref-3.3.0.whl-extract/asgiref/sync.py",
            "asgiref-3.3.0.whl-extract/asgiref/testing.py",
            "asgiref-3.3.0.whl-extract/asgiref/timeout.py",
            "asgiref-3.3.0.whl-extract/asgiref/wsgi.py",
            "asgiref-3.3.0.whl-extract/asgiref",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/LICENSE",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/METADATA",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/RECORD",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/top_level.txt",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info/WHEEL",
            "asgiref-3.3.0.whl-extract/asgiref-3.3.0.dist-info",
        ]
        self.assertEqual(expected_bottom_up_paths, bottom_up_paths)

        # Test parent-related methods
        asgiref_resource = self.project_asgiref.codebaseresources.get(
            path="asgiref-3.3.0.whl-extract/asgiref/compatibility.py"
        )
        expected_parent_path = "asgiref-3.3.0.whl-extract/asgiref"
        self.assertEqual(expected_parent_path, asgiref_resource.parent_path())
        self.assertTrue(asgiref_resource.has_parent())
        expected_parent = self.project_asgiref.codebaseresources.get(
            path="asgiref-3.3.0.whl-extract/asgiref"
        )
        self.assertEqual(expected_parent, asgiref_resource.parent())

        # Test sibling-related methods
        expected_siblings = [
            "asgiref-3.3.0.whl-extract/asgiref/__init__.py",
            "asgiref-3.3.0.whl-extract/asgiref/compatibility.py",
            "asgiref-3.3.0.whl-extract/asgiref/current_thread_executor.py",
            "asgiref-3.3.0.whl-extract/asgiref/local.py",
            "asgiref-3.3.0.whl-extract/asgiref/server.py",
            "asgiref-3.3.0.whl-extract/asgiref/sync.py",
            "asgiref-3.3.0.whl-extract/asgiref/testing.py",
            "asgiref-3.3.0.whl-extract/asgiref/timeout.py",
            "asgiref-3.3.0.whl-extract/asgiref/wsgi.py",
        ]
        asgiref_resource_siblings = [r.path for r in asgiref_resource.siblings()]
        self.assertEqual(sorted(expected_siblings), sorted(asgiref_resource_siblings))

    def test_scanpipe_codebase_resource_model_walk_method_problematic_filenames(self):
        project = Project.objects.create(name="walk_test_problematic_filenames")
        resource1 = CodebaseResource.objects.create(
            project=project, path="qt-everywhere-opensource-src-5.3.2/gnuwin32/bin"
        )
        CodebaseResource.objects.create(
            project=project,
            path="qt-everywhere-opensource-src-5.3.2/gnuwin32/bin/flex++.exe",
        )
        expected_paths = [
            "qt-everywhere-opensource-src-5.3.2/gnuwin32/bin/flex++.exe",
        ]
        result = [r.path for r in resource1.walk()]
        self.assertEqual(expected_paths, result)

    @mock.patch("requests.post")
    def test_scanpipe_webhook_subscription_deliver_method(self, mock_post):
        webhook = self.project1.add_webhook_subscription("https://localhost")
        self.assertFalse(webhook.delivered)
        run1 = self.create_run()

        mock_post.side_effect = RequestException("Error from exception")
        self.assertFalse(webhook.deliver(pipeline_run=run1))
        webhook.refresh_from_db()
        self.assertEqual("Error from exception", webhook.delivery_error)
        self.assertFalse(webhook.delivered)
        self.assertFalse(webhook.success)

        mock_post.side_effect = None
        mock_post.return_value = mock.Mock(status_code=404, text="text")
        self.assertTrue(webhook.deliver(pipeline_run=run1))
        webhook.refresh_from_db()
        self.assertTrue(webhook.delivered)
        self.assertFalse(webhook.success)
        self.assertEqual("text", webhook.response_text)

        mock_post.return_value = mock.Mock(status_code=200, text="text")
        self.assertTrue(webhook.deliver(pipeline_run=run1))
        webhook.refresh_from_db()
        self.assertTrue(webhook.delivered)
        self.assertTrue(webhook.success)
        self.assertEqual("text", webhook.response_text)

    def test_scanpipe_discovered_package_model_extract_purl_data(self):
        package_data = {}
        expected = {
            "type": "",
            "namespace": "",
            "name": "",
            "version": "",
            "qualifiers": "",
            "subpath": "",
        }
        purl_data = DiscoveredPackage.extract_purl_data(package_data)
        self.assertEqual(expected, purl_data)

        expected = {
            "name": "adduser",
            "namespace": "debian",
            "qualifiers": "arch=all",
            "subpath": "",
            "type": "deb",
            "version": "3.118",
        }
        purl_data = DiscoveredPackage.extract_purl_data(package_data1)
        self.assertEqual(expected, purl_data)

    def test_scanpipe_discovered_package_model_update_from_data(self):
        package = DiscoveredPackage.create_from_data(self.project1, package_data1)
        new_data = {
            "name": "new name",
            "notice_text": "NOTICE",
            "description": "new description",
            "unknown_field": "value",
            "sha1": "sha1",
        }
        updated_fields = package.update_from_data(new_data)
        self.assertEqual(["sha1"], updated_fields)

        package.refresh_from_db()
        # PURL field, not updated
        self.assertEqual(package_data1["name"], package.name)
        # Empty field, updated
        self.assertEqual(new_data["sha1"], package.sha1)
        # Already a value, not updated
        self.assertEqual(package_data1["description"], package.description)

        updated_fields = package.update_from_data(new_data, override=True)
        self.assertEqual(["notice_text", "description"], updated_fields)
        self.assertEqual(new_data["description"], package.description)

    def test_scanpipe_discovered_package_get_declared_license_expression_spdx(self):
        package = DiscoveredPackage.create_from_data(self.project1, package_data1)
        expression = "gpl-2.0 AND gpl-2.0-plus"
        spdx = "GPL-2.0-only AND GPL-2.0-or-later"

        self.assertEqual(expression, package.declared_license_expression)
        self.assertEqual(spdx, package.declared_license_expression_spdx)
        self.assertEqual(spdx, package.get_declared_license_expression_spdx())

        package.update(declared_license_expression_spdx="")
        self.assertEqual(expression, package.declared_license_expression)
        self.assertEqual("", package.declared_license_expression_spdx)
        self.assertEqual(spdx, package.get_declared_license_expression_spdx())

        package.update(declared_license_expression="")
        self.assertEqual("", package.declared_license_expression)
        self.assertEqual("", package.declared_license_expression_spdx)
        self.assertEqual("", package.get_declared_license_expression_spdx())

    def test_scanpipe_discovered_package_get_declared_license_expression(self):
        package = DiscoveredPackage.create_from_data(self.project1, package_data1)
        expression = "gpl-2.0 AND gpl-2.0-plus"
        spdx = "GPL-2.0-only AND GPL-2.0-or-later"

        self.assertEqual(expression, package.declared_license_expression)
        self.assertEqual(spdx, package.declared_license_expression_spdx)
        self.assertEqual(expression, package.get_declared_license_expression())

        package.update(declared_license_expression="")
        self.assertEqual("", package.declared_license_expression)
        self.assertEqual(spdx, package.declared_license_expression_spdx)
        self.assertEqual(expression, package.get_declared_license_expression())

        package.update(declared_license_expression_spdx="")
        self.assertEqual("", package.declared_license_expression)
        self.assertEqual("", package.declared_license_expression_spdx)
        self.assertEqual("", package.get_declared_license_expression_spdx())

    def test_scanpipe_discovered_package_model_add_resources(self):
        package = DiscoveredPackage.create_from_data(self.project1, package_data1)
        resource1 = CodebaseResource.objects.create(project=self.project1, path="file1")
        resource2 = CodebaseResource.objects.create(project=self.project1, path="file2")

        package.add_resources([resource1])
        self.assertEqual(1, package.codebase_resources.count())
        self.assertIn(resource1, package.codebase_resources.all())
        package.add_resources([resource2])
        self.assertEqual(2, package.codebase_resources.count())
        self.assertIn(resource2, package.codebase_resources.all())

        package.codebase_resources.remove(resource1)
        package.codebase_resources.remove(resource2)
        self.assertEqual(0, package.codebase_resources.count())
        package.add_resources([resource1, resource2])
        self.assertEqual(2, package.codebase_resources.count())
        self.assertIn(resource1, package.codebase_resources.all())
        self.assertIn(resource2, package.codebase_resources.all())

    def test_scanpipe_discovered_package_model_as_cyclonedx(self):
        package = DiscoveredPackage.create_from_data(self.project1, package_data1)
        cyclonedx_component = package.as_cyclonedx()

        self.assertEqual("library", cyclonedx_component.type)
        self.assertEqual(package_data1["name"], cyclonedx_component.name)
        self.assertEqual(package_data1["version"], cyclonedx_component.version)
        purl = "pkg:deb/debian/adduser@3.118?arch=all"
        self.assertEqual(purl, str(cyclonedx_component.bom_ref))
        self.assertEqual(purl, cyclonedx_component.purl)
        self.assertEqual(1, len(cyclonedx_component.licenses))
        expected = "GPL-2.0-only AND GPL-2.0-or-later"
        self.assertEqual(expected, cyclonedx_component.licenses[0].expression)
        self.assertEqual(package_data1["copyright"], cyclonedx_component.copyright)
        self.assertEqual(package_data1["description"], cyclonedx_component.description)
        self.assertEqual(1, len(cyclonedx_component.hashes))
        self.assertEqual(package_data1["md5"], cyclonedx_component.hashes[0].content)

        properties = {prop.name: prop.value for prop in cyclonedx_component.properties}
        expected_properties = {
            "aboutcode:download_url": "https://download.url/package.zip",
            "aboutcode:filename": "package.zip",
            "aboutcode:homepage_url": "https://packages.debian.org",
            "aboutcode:primary_language": "bash",
            "aboutcode:notice_text": "Notice\nText",
        }
        self.assertEqual(expected_properties, properties)

        external_references = cyclonedx_component.external_references
        self.assertEqual(1, len(external_references))
        self.assertEqual("vcs", external_references[0].type)
        self.assertEqual("https://packages.vcs.url", external_references[0].url)

    def test_scanpipe_discovered_package_model_compliance_alert(self):
        scanpipe_app.license_policies_index = license_policies_index
        package_data = package_data1.copy()
        package_data["declared_license_expression"] = ""
        package = DiscoveredPackage.create_from_data(self.project1, package_data)
        self.assertEqual("", package.compliance_alert)

        license_expression = "bsd-new"
        self.assertNotIn(license_expression, scanpipe_app.license_policies_index)
        package.update(declared_license_expression=license_expression)
        self.assertEqual("missing", package.compliance_alert)

        license_expression = "apache-2.0"
        self.assertIn(license_expression, scanpipe_app.license_policies_index)
        package.update(declared_license_expression=license_expression)
        self.assertEqual("ok", package.compliance_alert)

        license_expression = "apache-2.0 AND mpl-2.0 OR gpl-3.0"
        package.update(declared_license_expression=license_expression)
        self.assertEqual("error", package.compliance_alert)

        # Reset the index value
        scanpipe_app.license_policies_index = None

    def test_scanpipe_model_create_user_creates_auth_token(self):
        basic_user = User.objects.create_user(username="basic_user")
        self.assertTrue(basic_user.auth_token.key)
        self.assertEqual(40, len(basic_user.auth_token.key))

    def test_scanpipe_discovered_dependency_model_update_from_data(self):
        DiscoveredPackage.create_from_data(self.project1, package_data1)
        CodebaseResource.objects.create(
            project=self.project1, path="data.tar.gz-extract/Gemfile.lock"
        )
        dependency = DiscoveredDependency.create_from_data(
            self.project1, dependency_data2
        )

        new_data = {
            "name": "new name",
            "extracted_requirement": "new requirement",
            "scope": "new scope",
            "unknown_field": "value",
        }
        updated_fields = dependency.update_from_data(new_data)
        self.assertEqual(["extracted_requirement"], updated_fields)

        dependency.refresh_from_db()
        # PURL field, not updated
        self.assertEqual("appraisal", dependency.name)
        # Empty field, updated
        self.assertEqual(
            new_data["extracted_requirement"], dependency.extracted_requirement
        )
        # Already a value, not updated
        self.assertEqual(dependency_data2["scope"], dependency.scope)

        updated_fields = dependency.update_from_data(new_data, override=True)
        self.assertEqual(["scope"], updated_fields)
        self.assertEqual(new_data["scope"], dependency.scope)

    def test_scanpipe_discovered_dependency_model_is_vulnerable_property(self):
        package = DiscoveredPackage.create_from_data(self.project1, package_data1)
        self.assertFalse(package.is_vulnerable)
        package.update(
            affected_by_vulnerabilities=[{"vulnerability_id": "VCID-cah8-awtr-aaad"}]
        )
        self.assertTrue(package.is_vulnerable)

    def test_scanpipe_package_model_integrity_with_toolkit_package_model(self):
        scanpipe_only_fields = [
            "id",
            "uuid",
            "project",
            "missing_resources",
            "modified_resources",
            "codebase_resources",
            "package_uid",
            "filename",
            "affected_by_vulnerabilities",
            "compliance_alert",
        ]

        discovered_package_fields = [
            field.name
            for field in DiscoveredPackage._meta.get_fields()
            if field.name not in scanpipe_only_fields
        ]
        toolkit_package_fields = [field.name for field in PackageData.__attrs_attrs__]

        for toolkit_field in toolkit_package_fields:
            self.assertIn(toolkit_field, discovered_package_fields)

        for scanpipe_field in discovered_package_fields:
            self.assertIn(scanpipe_field, toolkit_package_fields)


class ScanPipeModelsTransactionTest(TransactionTestCase):
    """
    Since we are testing some Database errors, we need to use a
    TransactionTestCase to avoid any TransactionManagementError while running
    the tests.
    """

    @mock.patch("scanpipe.models.Run.execute_task_async")
    def test_scanpipe_project_model_add_pipeline(self, mock_execute_task):
        project1 = Project.objects.create(name="Analysis")

        self.assertEqual(0, project1.runs.count())

        pipeline_name = "not_available"
        with self.assertRaises(ValueError) as error:
            project1.add_pipeline(pipeline_name)
        self.assertEqual("Unknown pipeline: not_available", str(error.exception))

        pipeline_name = "inspect_manifest"
        project1.add_pipeline(pipeline_name)
        pipeline_class = scanpipe_app.pipelines.get(pipeline_name)

        self.assertEqual(1, project1.runs.count())
        run = project1.runs.get()
        self.assertEqual(pipeline_name, run.pipeline_name)
        self.assertEqual(pipeline_class.get_summary(), run.description)
        mock_execute_task.assert_not_called()

        project1.add_pipeline(pipeline_name, execute_now=True)
        mock_execute_task.assert_called_once()

    @mock.patch("scanpipe.models.Run.execute_task_async")
    def test_scanpipe_project_model_add_pipeline_run_can_start(self, mock_execute_task):
        project1 = Project.objects.create(name="Analysis")
        pipeline_name = "inspect_manifest"
        run1 = project1.add_pipeline(pipeline_name, execute_now=False)
        run2 = project1.add_pipeline(pipeline_name, execute_now=True)
        self.assertEqual(Run.Status.NOT_STARTED, run1.status)
        self.assertTrue(run1.can_start)
        self.assertEqual(Run.Status.NOT_STARTED, run1.status)
        self.assertFalse(run2.can_start)
        mock_execute_task.assert_not_called()

    @mock.patch("scanpipe.models.Run.execute_task_async")
    def test_scanpipe_project_model_add_pipeline_start_method(self, mock_execute_task):
        project1 = Project.objects.create(name="Analysis")
        pipeline_name = "inspect_manifest"
        run1 = project1.add_pipeline(pipeline_name, execute_now=False)
        run2 = project1.add_pipeline(pipeline_name, execute_now=False)
        self.assertEqual(Run.Status.NOT_STARTED, run1.status)
        self.assertEqual(Run.Status.NOT_STARTED, run1.status)

        self.assertFalse(run2.can_start)
        with self.assertRaises(RunNotAllowedToStart):
            run2.start()
        mock_execute_task.assert_not_called()

        self.assertTrue(run1.can_start)
        run1.start()
        mock_execute_task.assert_called_once()

    def test_scanpipe_project_model_add_info(self):
        project1 = Project.objects.create(name="Analysis")
        message = project1.add_info(description="This is an info")
        self.assertEqual(message, ProjectMessage.objects.get())
        self.assertEqual("", message.model)
        self.assertEqual(ProjectMessage.Severity.INFO, message.severity)
        self.assertEqual({}, message.details)
        self.assertEqual("This is an info", message.description)
        self.assertEqual("", message.traceback)

    def test_scanpipe_project_model_add_warning(self):
        project1 = Project.objects.create(name="Analysis")
        message = project1.add_warning(description="This is a warning")
        self.assertEqual(message, ProjectMessage.objects.get())
        self.assertEqual("", message.model)
        self.assertEqual(ProjectMessage.Severity.WARNING, message.severity)
        self.assertEqual({}, message.details)
        self.assertEqual("This is a warning", message.description)
        self.assertEqual("", message.traceback)

    def test_scanpipe_project_model_add_error(self):
        project1 = Project.objects.create(name="Analysis")
        details = {
            "name": "value",
            "release_date": datetime.fromisoformat("2008-02-01"),
        }
        message = project1.add_error(
            model="Package",
            details=details,
            exception=Exception("Error message"),
        )
        self.assertEqual(message, ProjectMessage.objects.get())
        self.assertEqual("Package", message.model)
        self.assertEqual(ProjectMessage.Severity.ERROR, message.severity)
        self.assertEqual(details, message.details)
        self.assertEqual("Error message", message.description)
        self.assertEqual("", message.traceback)

    def test_scanpipe_project_model_update_extra_data(self):
        project1 = Project.objects.create(name="Analysis")
        self.assertEqual({}, project1.extra_data)

        with self.assertRaises(ValueError):
            project1.update_extra_data("not_a_dict")

        data = {"key": "value"}
        with CaptureQueriesContext(connection) as queries_context:
            project1.update_extra_data(data)

        self.assertEqual(1, len(queries_context.captured_queries))
        sql = queries_context.captured_queries[0]["sql"]
        expected = (
            'UPDATE "scanpipe_project" SET "extra_data" = \'{"key": "value"}\'::jsonb'
        )
        self.assertTrue(sql.startswith(expected))

        self.assertEqual(data, project1.extra_data)
        project1.refresh_from_db()
        self.assertEqual(data, project1.extra_data)

        more_data = {"more": "data"}
        project1.update_extra_data(more_data)
        expected = {"key": "value", "more": "data"}
        self.assertEqual(expected, project1.extra_data)
        project1.refresh_from_db()
        self.assertEqual(expected, project1.extra_data)

    def test_scanpipe_codebase_resource_model_add_error(self):
        project1 = Project.objects.create(name="Analysis")
        codebase_resource = CodebaseResource.objects.create(project=project1)
        error = codebase_resource.add_error(Exception("Error message"))

        self.assertEqual(error, ProjectMessage.objects.get())
        self.assertEqual("CodebaseResource", error.model)
        self.assertTrue(error.details)
        self.assertEqual("Error message", error.description)
        self.assertEqual("", error.traceback)

    def test_scanpipe_codebase_resource_model_add_errors(self):
        project1 = Project.objects.create(name="Analysis")
        codebase_resource = CodebaseResource.objects.create(project=project1)
        codebase_resource.add_error(Exception("Error1"))
        codebase_resource.add_error(Exception("Error2"))
        self.assertEqual(2, ProjectMessage.objects.count())

    @skipIf(connection.vendor == "sqlite", "No max_length constraints on SQLite.")
    def test_scanpipe_project_error_model_save_non_valid_related_object(self):
        project1 = Project.objects.create(name="Analysis")
        long_value = "value" * 1000

        package = DiscoveredPackage.objects.create(
            project=project1, filename=long_value
        )
        # The DiscoveredPackage was not created
        self.assertIsNone(package.id)
        self.assertEqual(0, DiscoveredPackage.objects.count())
        # A ProjectMessage was saved instead
        self.assertEqual(1, project1.projectmessages.count())

        error = project1.projectmessages.get()
        self.assertEqual("DiscoveredPackage", error.model)
        self.assertEqual(long_value, error.details["filename"])
        self.assertEqual(
            "value too long for type character varying(255)", error.description
        )

        codebase_resource = CodebaseResource.objects.create(
            project=project1, type=long_value
        )
        self.assertIsNone(codebase_resource.id)
        self.assertEqual(0, CodebaseResource.objects.count())
        self.assertEqual(2, project1.projectmessages.count())

    @skipIf(connection.vendor == "sqlite", "No max_length constraints on SQLite.")
    def test_scanpipe_discovered_package_model_create_from_data(self):
        project1 = Project.objects.create(name="Analysis")

        package = DiscoveredPackage.create_from_data(project1, package_data1)
        self.assertEqual(project1, package.project)
        self.assertEqual("pkg:deb/debian/adduser@3.118?arch=all", str(package))
        self.assertEqual("deb", package.type)
        self.assertEqual("debian", package.namespace)
        self.assertEqual("adduser", package.name)
        self.assertEqual("3.118", package.version)
        self.assertEqual("arch=all", package.qualifiers)
        self.assertEqual("add and remove users and groups", package.description)
        self.assertEqual("849", package.size)
        expected = "gpl-2.0 AND gpl-2.0-plus"
        self.assertEqual(expected, package.declared_license_expression)

        package_count = DiscoveredPackage.objects.count()
        incomplete_data = dict(package_data1)
        incomplete_data["name"] = ""
        self.assertIsNone(DiscoveredPackage.create_from_data(project1, incomplete_data))
        self.assertEqual(package_count, DiscoveredPackage.objects.count())
        error = project1.projectmessages.latest("created_date")
        self.assertEqual("DiscoveredPackage", error.model)
        expected_message = "No values for the following required fields: name"
        self.assertEqual(expected_message, error.description)
        self.assertEqual(package_data1["purl"], error.details["purl"])
        self.assertEqual("", error.details["name"])
        self.assertEqual("", error.traceback)

        package_count = DiscoveredPackage.objects.count()
        project_message_count = ProjectMessage.objects.count()
        bad_data = dict(package_data1)
        bad_data["version"] = "a" * 200
        # The exception are not capture at the DiscoveredPackage.create_from_data but
        # rather in the CodebaseResource.create_and_add_package method so resource data
        # can be injected in the ProjectMessage record.
        with self.assertRaises(DataError):
            DiscoveredPackage.create_from_data(project1, bad_data)

        self.assertEqual(package_count, DiscoveredPackage.objects.count())
        self.assertEqual(project_message_count, ProjectMessage.objects.count())

    @skipIf(connection.vendor == "sqlite", "No max_length constraints on SQLite.")
    def test_scanpipe_discovered_dependency_model_create_from_data(self):
        project1 = Project.objects.create(name="Analysis")

        DiscoveredPackage.create_from_data(project1, package_data1)
        CodebaseResource.objects.create(
            project=project1, path="daglib-0.3.2.tar.gz-extract/daglib-0.3.2/PKG-INFO"
        )
        dependency = DiscoveredDependency.create_from_data(
            project1, dependency_data1, strip_datafile_path_root=False
        )
        self.assertEqual(project1, dependency.project)
        self.assertEqual("pkg:pypi/dask", dependency.purl)
        self.assertEqual("dask<2023.0.0,>=2022.6.0", dependency.extracted_requirement)
        self.assertEqual("install", dependency.scope)
        self.assertTrue(dependency.is_runtime)
        self.assertFalse(dependency.is_optional)
        self.assertFalse(dependency.is_resolved)
        self.assertEqual(
            "pkg:pypi/dask?uuid=e656b571-7d3f-46d1-b95b-8f037aef9692",
            dependency.dependency_uid,
        )
        self.assertEqual(
            "pkg:deb/debian/adduser@3.118?uuid=610bed29-ce39-40e7-92d6-fd8b",
            dependency.for_package_uid,
        )
        self.assertEqual(
            "daglib-0.3.2.tar.gz-extract/daglib-0.3.2/PKG-INFO",
            dependency.datafile_path,
        )
        self.assertEqual("pypi_sdist_pkginfo", dependency.datasource_id)

        # Test field validation when using create_from_data
        dependency_count = DiscoveredDependency.objects.count()
        incomplete_data = dict(dependency_data1)
        incomplete_data["dependency_uid"] = ""
        self.assertIsNone(
            DiscoveredDependency.create_from_data(project1, incomplete_data)
        )
        self.assertEqual(dependency_count, DiscoveredDependency.objects.count())
        message = project1.projectmessages.latest("created_date")
        self.assertEqual("DiscoveredDependency", message.model)
        self.assertEqual(ProjectMessage.Severity.WARNING, message.severity)
        expected_message = "No values for the following required fields: dependency_uid"
        self.assertEqual(expected_message, message.description)
        self.assertEqual(dependency_data1["purl"], message.details["purl"])
        self.assertEqual("", message.details["dependency_uid"])
        self.assertEqual("", message.traceback)

    def test_scanpipe_discovered_package_model_unique_package_uid_in_project(self):
        project1 = Project.objects.create(name="Analysis")

        self.assertTrue(package_data1["package_uid"])
        package = DiscoveredPackage.create_from_data(project1, package_data1)
        self.assertTrue(package.package_uid)

        with self.assertRaises(IntegrityError):
            DiscoveredPackage.create_from_data(project1, package_data1)

        package_data_no_uid = package_data1.copy()
        package_data_no_uid.pop("package_uid")
        package2 = DiscoveredPackage.create_from_data(project1, package_data_no_uid)
        self.assertFalse(package2.package_uid)
        package3 = DiscoveredPackage.create_from_data(project1, package_data_no_uid)
        self.assertFalse(package3.package_uid)

    @skipIf(connection.vendor == "sqlite", "No max_length constraints on SQLite.")
    def test_scanpipe_codebase_resource_create_and_add_package_warnings(self):
        project1 = Project.objects.create(name="Analysis")
        resource = CodebaseResource.objects.create(project=project1, path="p")

        package_count = DiscoveredPackage.objects.count()
        bad_data = dict(package_data1)
        bad_data["version"] = "a" * 200

        package = resource.create_and_add_package(bad_data)
        self.assertIsNone(package)
        self.assertEqual(package_count, DiscoveredPackage.objects.count())
        message = project1.projectmessages.latest("created_date")
        self.assertEqual("DiscoveredPackage", message.model)
        self.assertEqual(ProjectMessage.Severity.WARNING, message.severity)
        expected_message = "value too long for type character varying(100)"
        self.assertEqual(expected_message, message.description)
        self.assertEqual(bad_data["version"], message.details["version"])
        self.assertTrue(message.details["codebase_resource_pk"])
        self.assertEqual(resource.path, message.details["codebase_resource_path"])
        self.assertIn("in save", message.traceback)
