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
import json
import shutil
import sys
import tempfile
import uuid
from contextlib import redirect_stdout
from datetime import datetime
from datetime import timezone as tz
from pathlib import Path
from unittest import mock
from unittest import skipIf

from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import DataError
from django.db import IntegrityError
from django.db import connection
from django.test import TestCase
from django.test import TransactionTestCase
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from packagedcode.models import PackageData
from packageurl import PackageURL
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
from scanpipe.models import WebhookSubscription
from scanpipe.models import convert_glob_to_django_regex
from scanpipe.models import get_project_work_directory
from scanpipe.models import normalize_package_url_data
from scanpipe.pipes.fetch import Download
from scanpipe.pipes.input import copy_input
from scanpipe.tests import dependency_data1
from scanpipe.tests import dependency_data2
from scanpipe.tests import license_policies_index
from scanpipe.tests import make_dependency
from scanpipe.tests import make_package
from scanpipe.tests import make_resource_directory
from scanpipe.tests import make_resource_file
from scanpipe.tests import mocked_now
from scanpipe.tests import package_data1
from scanpipe.tests import package_data2
from scanpipe.tests.pipelines.do_nothing import DoNothing

scanpipe_app = apps.get_app_config("scanpipe")
User = get_user_model()


class ScanPipeModelsTest(TestCase):
    data = Path(__file__).parent / "data"
    fixtures = [data / "asgiref" / "asgiref-3.3.0_fixtures.json"]

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

        self.project1.add_pipeline("analyze_docker_image")
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
            "scanpipe.InputSource": 0,
            "scanpipe.ProjectMessage": 0,
            "scanpipe.Run": 1,
            "scanpipe.WebhookDelivery": 0,
            "scanpipe.WebhookSubscription": 0,
        }
        self.assertEqual(expected, delete_log)
        # Make sure the labels were deleted too.
        self.assertEqual(0, UUIDTaggedItem.objects.count())

    def test_scanpipe_project_model_delete(self):
        work_path = self.project1.work_path
        self.assertTrue(work_path.exists())

        uploaded_file = SimpleUploadedFile("file.ext", content=b"content")
        self.project1.write_input_file(uploaded_file)
        self.project1.add_pipeline("analyze_docker_image")
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
        self.project1.add_pipeline("analyze_docker_image")
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
        self.project1.add_input_source(filename="file1", is_uploaded=True)
        self.project1.add_input_source(
            filename="file2", download_url="https://download.url"
        )
        self.project1.update(settings={"product_name": "My Product"})
        new_file_path1 = self.project1.input_path / "file.zip"
        new_file_path1.touch()
        run1 = self.project1.add_pipeline("analyze_docker_image", selected_groups=["g"])
        run2 = self.project1.add_pipeline("find_vulnerabilities")
        subscription1 = self.project1.add_webhook_subscription(
            target_url="http://domain.url"
        )

        cloned_project = self.project1.clone("cloned project")
        self.assertIsInstance(cloned_project, Project)
        self.assertNotEqual(self.project1.pk, cloned_project.pk)
        self.assertNotEqual(self.project1.slug, cloned_project.slug)
        self.assertNotEqual(self.project1.work_directory, cloned_project.work_directory)

        self.assertEqual("cloned project", cloned_project.name)
        self.assertEqual({}, cloned_project.settings)
        self.assertEqual([], cloned_project.input_sources)
        self.assertEqual([], list(cloned_project.inputs()))
        self.assertEqual([], list(cloned_project.runs.all()))
        self.assertEqual([], list(cloned_project.webhooksubscriptions.all()))

        cloned_project2 = self.project1.clone(
            "cloned project full",
            copy_inputs=True,
            copy_pipelines=True,
            copy_settings=True,
            copy_subscriptions=True,
            execute_now=False,
        )
        self.assertEqual(self.project1.settings, cloned_project2.settings)
        self.assertEqual(
            len(self.project1.input_sources), len(cloned_project2.input_sources)
        )
        self.assertEqual(1, len(list(cloned_project2.inputs())))
        runs = cloned_project2.runs.all()
        self.assertEqual(
            ["analyze_docker_image", "find_vulnerabilities"],
            [run.pipeline_name for run in runs],
        )
        self.assertNotEqual(run1.pk, runs[0].pk)
        self.assertEqual(run1.selected_groups, runs[0].selected_groups)
        self.assertNotEqual(run2.pk, runs[1].pk)
        self.assertEqual(1, len(cloned_project2.webhooksubscriptions.all()))
        cloned_subscription = cloned_project2.webhooksubscriptions.get()
        self.assertNotEqual(subscription1.uuid, cloned_subscription.uuid)

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

    @mock.patch("scanpipe.pipes.datetime", mocked_now)
    def test_scanpipe_project_model_get_output_files_info(self):
        self.assertEqual([], self.project1.get_output_files_info())
        self.project1.get_output_file_path("file", "ext").write_text("Some content")
        expected = [{"name": "file-2010-10-10-10-10-10.ext", "size": 12}]
        self.assertEqual(expected, self.project1.get_output_files_info())

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

    def test_scanpipe_project_model_get_inputs_with_source(self):
        self.assertEqual([], self.project1.get_inputs_with_source())

        uploaded_file = SimpleUploadedFile("file.ext", content=b"content")
        self.project1.add_upload(uploaded_file)
        self.project1.copy_input_from(self.data / "aboutcode" / "notice.NOTICE")
        self.project1.add_input_source(filename="missing.zip", is_uploaded=True)

        uuid1, uuid2 = (
            str(input_source.uuid) for input_source in self.project1.inputsources.all()
        )

        expected = [
            {
                "uuid": uuid1,
                "filename": "file.ext",
                "download_url": "",
                "is_uploaded": True,
                "tag": "",
                "size": 7,
                "is_file": True,
                "exists": True,
            },
            {
                "uuid": uuid2,
                "filename": "missing.zip",
                "download_url": "",
                "is_uploaded": True,
                "tag": "",
                "size": None,
                "is_file": True,
                "exists": False,
            },
            {
                "filename": "notice.NOTICE",
                "is_uploaded": False,
                "is_file": True,
                "size": 1178,
                "exists": True,
            },
        ]

        self.assertEqual(expected, self.project1.get_inputs_with_source())
        self.assertEqual(expected, self.project1.input_sources)

    def test_scanpipe_project_model_can_start_pipelines(self):
        self.assertFalse(self.project1.can_start_pipelines)

        # Not started
        run = self.project1.add_pipeline("analyze_docker_image")
        self.project1 = Project.objects.get(uuid=self.project1.uuid)
        self.assertTrue(self.project1.can_start_pipelines)

        # Queued
        run.task_start_date = timezone.now()
        run.save()
        self.project1 = Project.objects.get(uuid=self.project1.uuid)
        self.assertFalse(self.project1.can_start_pipelines)

        # Success
        run.task_end_date = timezone.now()
        run.task_exitcode = 0
        run.save()
        self.project1 = Project.objects.get(uuid=self.project1.uuid)
        self.assertFalse(self.project1.can_start_pipelines)

        # Another "Not started"
        self.project1.add_pipeline("analyze_docker_image")
        self.project1 = Project.objects.get(uuid=self.project1.uuid)
        self.assertTrue(self.project1.can_start_pipelines)

    def test_scanpipe_project_model_can_change_inputs(self):
        self.assertTrue(self.project1.can_change_inputs)

        run = self.project1.add_pipeline("analyze_docker_image")
        self.project1 = Project.objects.get(uuid=self.project1.uuid)
        self.assertTrue(self.project1.can_change_inputs)

        run.task_start_date = timezone.now()
        run.save()
        self.project1 = Project.objects.get(uuid=self.project1.uuid)
        self.assertFalse(self.project1.can_change_inputs)

    def test_scanpipe_project_model_add_input_source(self):
        self.assertEqual(0, self.project1.inputsources.count())

        with self.assertRaises(Exception) as cm:
            self.project1.add_input_source()
        expected = "Provide at least a value for download_url or filename."
        self.assertEqual(expected, str(cm.exception))

        source = self.project1.add_input_source(
            download_url="https://download.url", tag="tag"
        )
        self.assertFalse(source.is_uploaded)
        self.assertEqual("", source.filename)
        self.assertEqual("tag", source.tag)

        source = self.project1.add_input_source(filename="file.tar", is_uploaded=True)
        self.assertTrue(source.is_uploaded)
        self.assertEqual("", source.download_url)
        self.assertEqual("", source.tag)

        input_sources = self.project1.inputsources.all()
        self.assertEqual(2, len(input_sources))

        url_with_fragment = "https://download.url#tag_value"
        input_source = self.project1.add_input_source(download_url=url_with_fragment)
        self.assertEqual("tag_value", input_source.tag)

    def test_scanpipe_project_model_add_downloads(self):
        file_location = self.data / "aboutcode" / "notice.NOTICE"
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

        inputs_with_source = self.project1.get_inputs_with_source()
        expected = [
            {
                "uuid": str(self.project1.inputsources.get().uuid),
                "filename": "notice.NOTICE",
                "download_url": "https://example.com/filename.zip",
                "is_uploaded": False,
                "tag": "",
                "size": 1178,
                "is_file": True,
                "exists": True,
            }
        ]
        self.assertEqual(expected, inputs_with_source)

    def test_scanpipe_project_model_add_uploads(self):
        uploaded_file = SimpleUploadedFile("file.ext", content=b"content")
        self.project1.add_uploads([uploaded_file])

        inputs_with_source = self.project1.get_inputs_with_source()
        expected = [
            {
                "uuid": str(self.project1.inputsources.get().uuid),
                "filename": "file.ext",
                "download_url": "",
                "is_uploaded": True,
                "tag": "",
                "size": 7,
                "is_file": True,
                "exists": True,
            }
        ]
        self.assertEqual(expected, inputs_with_source)

    def test_scanpipe_project_model_add_webhook_subscription(self):
        self.assertEqual(0, self.project1.webhooksubscriptions.count())
        self.project1.add_webhook_subscription(target_url="https://localhost")
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

    def test_scanpipe_project_related_model_clone(self):
        subscription1 = self.project1.add_webhook_subscription(
            target_url="http://domain.url"
        )

        new_project = Project.objects.create(name="New Project")
        subscription1.clone(to_project=new_project)

        cloned_subscription = new_project.webhooksubscriptions.get()
        subscription1 = self.project1.webhooksubscriptions.get()
        self.assertEqual(new_project, cloned_subscription.project)
        self.assertNotEqual(cloned_subscription.pk, subscription1.pk)

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

        dir1_path = self.project1.codebase_path / "dir1"
        dir1_path.mkdir(parents=True, exist_ok=True)
        dir1_config_file = dir1_path / settings.SCANCODEIO_CONFIG_FILE
        dir1_config_file.touch()
        # If a config file exists directly in the input directory, return it.
        config_file_location = str(self.project1.get_input_config_file())
        self.assertTrue(config_file_location.endswith("input/scancode-config.yml"))

        config_file.unlink()
        config_file_location = str(self.project1.get_input_config_file())
        self.assertTrue(
            config_file_location.endswith("codebase/dir1/scancode-config.yml")
        )

        dir2_path = self.project1.codebase_path / "dir2"
        dir2_path.mkdir(parents=True, exist_ok=True)
        dir2_config_file = dir2_path / settings.SCANCODEIO_CONFIG_FILE
        dir2_config_file.touch()
        # If multiple config files are found, report an error.
        self.assertIsNone(self.project1.get_input_config_file())
        error = self.project1.projectmessages.get()
        self.assertIn("More than one scancode-config.yml found", error.description)

        dir1_config_file.unlink()
        dir2_config_file.unlink()
        sub_dir1_path = self.project1.codebase_path / "dir1" / "subdir1"
        sub_dir1_path.mkdir(parents=True, exist_ok=True)
        sub_dir1_config_file = sub_dir1_path / settings.SCANCODEIO_CONFIG_FILE
        sub_dir1_config_file.touch()
        # Search for config files *ONLY* in immediate codebase/ subdirectories.
        self.assertIsNone(self.project1.get_input_config_file())

    def test_scanpipe_project_get_settings_as_yml(self):
        self.assertEqual("{}\n", self.project1.get_settings_as_yml())

        test_config_file = self.data / "settings" / "scancode-config.yml"
        config_file = copy_input(test_config_file, self.project1.input_path)
        env_from_test_config = self.project1.get_env().copy()
        self.project1.settings = env_from_test_config
        self.project1.save()

        config_file.write_text(self.project1.get_settings_as_yml())
        self.assertEqual(env_from_test_config, self.project1.get_env())

    def test_get_enabled_settings(self):
        self.assertEqual({}, self.project1.settings)
        self.assertEqual({}, self.project1.get_enabled_settings())

        self.project1.update(
            settings={"ignored_patterns": None, "attribution_template": ""}
        )
        self.assertEqual({}, self.project1.get_enabled_settings())

        self.project1.update(
            settings={"ignored_patterns": "ignore_me", "attribution_template": ""}
        )
        self.assertEqual(
            {"ignored_patterns": "ignore_me"}, self.project1.get_enabled_settings()
        )

    def test_scanpipe_project_get_env(self):
        self.assertEqual({}, self.project1.get_env())

        test_config_file = self.data / "settings" / "scancode-config.yml"
        copy_input(test_config_file, self.project1.input_path)

        expected = {
            "product_name": "My Product Name",
            "product_version": "1.0",
            "ignored_patterns": ["*.tmp", "tests/*"],
            "ignored_dependency_scopes": [
                {"package_type": "npm", "scope": "devDependencies"},
                {"package_type": "pypi", "scope": "tests"},
            ],
            "ignored_vulnerabilities": [
                "VCID-q4q6-yfng-aaag",
                "CVE-2024-27351",
                "GHSA-vm8q-m57g-pff3",
            ],
        }
        self.assertEqual(expected, self.project1.get_env())

        config = {"ignored_patterns": None}
        self.project1.settings = config
        self.project1.save()
        self.assertEqual(expected, self.project1.get_env())

        config = {"ignored_patterns": ["*.txt"], "product_name": "Product1"}
        self.project1.settings = config
        self.project1.save()
        expected["product_name"] = "Product1"
        expected["ignored_patterns"] = ["*.txt"]
        self.assertEqual(expected, self.project1.get_env())

    def test_scanpipe_project_get_env_invalid_yml_content(self):
        config_file = self.project1.input_path / settings.SCANCODEIO_CONFIG_FILE
        config_file.write_text("{*this is not valid yml*}")

        config_file_location = str(self.project1.get_input_config_file())
        self.assertTrue(config_file_location.endswith("input/scancode-config.yml"))
        self.assertEqual({}, self.project1.get_env())

        error = self.project1.projectmessages.get()
        self.assertIn("Failed to load configuration from", error.description)
        self.assertIn("The file format is invalid.", error.description)

    def test_scanpipe_project_get_ignored_dependency_scopes_index(self):
        self.project1.settings = {
            "ignored_dependency_scopes": [{"package_type": "pypi", "scope": "tests"}]
        }
        expected = {"pypi": ["tests"]}
        self.assertEqual(expected, self.project1.ignored_dependency_scopes_index)
        self.assertEqual(expected, self.project1.get_ignored_dependency_scopes_index())

        self.project1.settings = {
            "ignored_dependency_scopes": [
                {"package_type": "pypi", "scope": "tests"},
                {"package_type": "pypi", "scope": "build"},
                {"package_type": "npm", "scope": "devDependencies"},
            ]
        }
        # Since this is a cache property, it still returns the previous value
        self.assertEqual(expected, self.project1.ignored_dependency_scopes_index)
        # The following function call always build and return the index
        expected = {"npm": ["devDependencies"], "pypi": ["tests", "build"]}
        self.assertEqual(expected, self.project1.get_ignored_dependency_scopes_index())

    def test_scanpipe_normalize_package_url_data(self):
        purl = PackageURL.from_string("pkg:npm/athena-express@6.0.4")
        purl_data = normalize_package_url_data(purl_mapping=purl.to_dict())
        self.assertEqual(purl_data.get("namespace"), "")

        purl_data = normalize_package_url_data(
            purl_mapping=purl.to_dict(),
            ignore_nulls=True,
        )
        self.assertEqual(purl_data.get("namespace"), None)

    def test_scanpipe_project_get_ignored_vulnerabilities_set(self):
        self.project1.settings = {
            "ignored_vulnerabilities": [
                "VCID-q4q6-yfng-aaag",
                "CVE-2024-27351",
                "GHSA-vm8q-m57g-pff3",
            ],
        }
        expected = {"VCID-q4q6-yfng-aaag", "CVE-2024-27351", "GHSA-vm8q-m57g-pff3"}
        self.assertEqual(expected, self.project1.ignored_vulnerabilities_set)
        self.assertEqual(expected, self.project1.get_ignored_vulnerabilities_set())

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

    def test_scanpipe_model_convert_glob_to_django_regex(self):
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
            self.assertEqual(expected, convert_glob_to_django_regex(pattern))

    def test_scanpipe_run_model_set_scancodeio_version(self):
        run1 = Run.objects.create(project=self.project1)
        self.assertEqual("", run1.scancodeio_version)

        run1.set_scancodeio_version()
        run1 = Run.objects.get(pk=run1.pk)
        self.assertEqual(scancodeio_version, run1.scancodeio_version)

        with self.assertRaises(ValueError) as cm:
            run1.set_scancodeio_version()
        self.assertIn("Field scancodeio_version already set to", str(cm.exception))

    def test_scanpipe_run_model_get_diff_url(self):
        run1 = Run.objects.create(project=self.project1)
        self.assertEqual("", run1.scancodeio_version)
        self.assertIsNone(run1.get_diff_url())

        with mock.patch("scancodeio.__version__", "v32.3.0-28-g0000000"):
            run1.set_scancodeio_version()
        self.assertEqual("v32.3.0-28-g0000000", run1.scancodeio_version)

        expected = (
            "https://github.com/aboutcode-org/scancode.io/compare/0000000..ffffffff"
        )
        with mock.patch("scancodeio.__version__", "v31.0.0-1-gffffffff"):
            self.assertEqual(expected, run1.get_diff_url())

    def test_scanpipe_run_model_set_current_step(self):
        run1 = Run.objects.create(project=self.project1)
        self.assertEqual("", run1.current_step)

        run1.set_current_step("a" * 300)
        run1 = Run.objects.get(pk=run1.pk)
        self.assertEqual(256, len(run1.current_step))

        run1.set_current_step("")
        run1 = Run.objects.get(pk=run1.pk)
        self.assertEqual("", run1.current_step)

    def test_scanpipe_run_model_selected_groups(self):
        run1 = Run.objects.create(project=self.project1)
        self.assertEqual(None, run1.selected_groups)

        # Empty list has not the same behavior as None
        run1.update(selected_groups=[])
        self.assertEqual([], run1.selected_groups)

        run1.update(selected_groups=["foo"])
        self.assertEqual(["foo"], run1.selected_groups)

        run1.update(selected_groups=["foo", "bar"])
        self.assertEqual(["foo", "bar"], run1.selected_groups)

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

        run1.task_start_date = datetime(1984, 10, 10, 10, 10, 10, tzinfo=tz.utc)
        run1.save()
        self.assertIsNone(run1.execution_time)

        run1.task_end_date = datetime(1984, 10, 10, 10, 10, 35, tzinfo=tz.utc)
        run1.save()
        self.assertEqual(25.0, run1.execution_time)

        run1.set_task_staled()
        run1.refresh_from_db()
        self.assertIsNone(run1.execution_time)

    def test_scanpipe_run_model_execution_time_for_display_property(self):
        run1 = self.create_run()

        self.assertIsNone(run1.execution_time_for_display)

        run1.task_start_date = datetime(1984, 10, 10, 10, 10, 10, tzinfo=tz.utc)
        run1.save()
        self.assertIsNone(run1.execution_time_for_display)

        run1.task_end_date = datetime(1984, 10, 10, 10, 10, 35, tzinfo=tz.utc)
        run1.save()
        self.assertEqual("25 seconds", run1.execution_time_for_display)

        run1.task_end_date = datetime(1984, 10, 10, 10, 12, 35, tzinfo=tz.utc)
        run1.save()
        self.assertEqual("145 seconds (2.4 minutes)", run1.execution_time_for_display)

        run1.task_end_date = datetime(1984, 10, 10, 11, 12, 35, tzinfo=tz.utc)
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
        self.project1.add_webhook_subscription(target_url="https://localhost")
        run1 = self.create_run()

        run1.deliver_project_subscriptions(has_next_run=True)
        mock_deliver.assert_not_called()

        run1.deliver_project_subscriptions()
        mock_deliver.assert_called_once_with(pipeline_run=run1)

    def test_scanpipe_run_model_results_url(self):
        run1 = self.create_run(pipeline="scan_codebase")
        self.assertEqual("", run1.pipeline_class.results_url)
        self.assertIsNone(run1.results_url)

        run2 = self.create_run(pipeline="find_vulnerabilities")
        self.assertEqual(
            "/project/{slug}/packages/?is_vulnerable=yes",
            run2.pipeline_class.results_url,
        )
        packages_url = reverse("project_packages", args=[self.project1.slug])
        self.assertEqual(f"{packages_url}?is_vulnerable=yes", run2.results_url)

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

    def test_scanpipe_input_source_model_str(self):
        file_location = self.data / "aboutcode" / "notice.NOTICE"
        input_source = self.project1.add_input_source(
            filename=file_location.name, is_uploaded=True
        )
        self.assertEqual("filename=notice.NOTICE [uploaded]", str(input_source))

    def test_scanpipe_input_source_model_path(self):
        file_location = self.data / "aboutcode" / "notice.NOTICE"
        input_source = self.project1.add_input_source(
            filename=file_location.name, is_uploaded=True
        )
        self.assertTrue(str(input_source.path).endswith("input/notice.NOTICE"))

    def test_scanpipe_input_source_model_exists(self):
        file_location = self.data / "aboutcode" / "notice.NOTICE"
        input_source = self.project1.add_input_source(
            filename=file_location.name, is_uploaded=True
        )
        self.assertFalse(input_source.exists())

        copy_input(file_location, self.project1.input_path)
        self.assertTrue(input_source.exists())

    def test_scanpipe_input_source_model_delete_input(self):
        self.assertEqual([], self.project1.input_sources)
        self.assertEqual([], list(self.project1.inputs()))

        file_location = self.data / "aboutcode" / "notice.NOTICE"
        copy_input(file_location, self.project1.input_path)
        input_source = self.project1.add_input_source(
            filename=file_location.name, is_uploaded=True
        )
        self.assertEqual(1, self.project1.inputsources.count())
        self.assertEqual(
            [file_location.name], [path.name for path in self.project1.inputs()]
        )

        deleted = input_source.delete()
        self.assertTrue(deleted)
        self.assertEqual([], self.project1.input_sources)
        self.assertEqual([], list(self.project1.inputs()))

    def test_scanpipe_input_source_model_delete_file(self):
        file_location = self.data / "aboutcode" / "notice.NOTICE"
        input_source = self.project1.add_input_source(
            filename=file_location.name, is_uploaded=True
        )
        copy_input(file_location, self.project1.input_path)
        self.assertTrue(input_source.exists())
        input_source.delete_file()
        self.assertFalse(input_source.exists())

    @mock.patch("requests.sessions.Session.get")
    def test_scanpipe_input_source_model_fetch(self, mock_get):
        download_url = "https://download.url/file.zip"
        mock_get.return_value = mock.Mock(
            content=b"\x00", headers={}, status_code=200, url=download_url
        )

        input_source = self.project1.add_input_source(download_url=download_url)
        destination = input_source.fetch()
        self.assertTrue(str(destination).endswith("input/file.zip"))

        self.assertEqual("file.zip", input_source.filename)
        self.assertFalse(input_source.is_uploaded)
        self.assertTrue(input_source.exists())
        mock_get.assert_called_once()

        self.assertIsNone(input_source.fetch())
        mock_get.assert_called_once()

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

        file_with_long_lines = self.data / "misc" / "decompose_l_u_8hpp_source.html"
        copy_input(file_with_long_lines, self.project1.codebase_path)

        resource.update(path="decompose_l_u_8hpp_source.html")
        line_count = len(resource.file_content.split("\n"))
        self.assertEqual(101, line_count)

    def test_scanpipe_codebase_resource_model_file_content_for_map(self):
        map_file_path = self.data / "d2d-javascript/to/main.js.map"
        copy_input(map_file_path, self.project1.codebase_path)
        resource = self.project1.codebaseresources.create(path="main.js.map")

        with open(map_file_path) as file:
            expected = json.load(file)

        result = json.loads(resource.file_content)

        self.assertEqual(expected, result)

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
        qs = CodebaseResource.objects.has_license_expression()
        self.assertEqual(0, len(qs))

        file.update(detected_license_expression="gpl-3.0 AND unknown")
        qs = CodebaseResource.objects.unknown_license()
        self.assertEqual(1, len(qs))
        self.assertIn(file, qs)
        qs = CodebaseResource.objects.has_license_expression()
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
        make_resource_file(self.project1, path="example-1.0.jar")

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
            "example-*.jar",
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

        path = "root/subpath/archive.zip-extract/file.txt"
        resource = make_resource_file(self.project1, path=path)
        expected = [
            ("root", "root", False),
            ("subpath", "root/subpath", False),
            ("archive.zip", "root/subpath/archive.zip", True),
            ("file.txt", "root/subpath/archive.zip-extract/file.txt", False),
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
            qs2 = DiscoveredPackage.objects.filter(package_url=purl)
            self.assertEqual(expected_count, qs2.count(), msg=purl)

    def test_scanpipe_discovered_package_queryset_vulnerable(self):
        p1 = DiscoveredPackage.create_from_data(self.project1, package_data1)
        p2 = DiscoveredPackage.create_from_data(self.project1, package_data2)
        p2.update(
            affected_by_vulnerabilities=[{"vulnerability_id": "VCID-cah8-awtr-aaad"}]
        )
        self.assertNotIn(p1, DiscoveredPackage.objects.vulnerable())
        self.assertIn(p2, DiscoveredPackage.objects.vulnerable())

    def test_scanpipe_discovered_package_queryset_dependency_methods(self):
        project = Project.objects.create(name="project")
        a = make_package(project, "pkg:type/a")
        b = make_package(project, "pkg:type/b")
        c = make_package(project, "pkg:type/c")
        z = make_package(project, "pkg:type/z")
        # Project -> A -> B -> C
        # Project -> Z
        a_to_b = make_dependency(
            project, for_package=a, resolved_to_package=b, dependency_uid="a_to_b"
        )
        b_to_c = make_dependency(
            project, for_package=b, resolved_to_package=c, dependency_uid="b_to_c"
        )
        unresolved_dependency = make_dependency(project, dependency_uid="unresolved")

        self.assertFalse(a_to_b.is_project_dependency)
        self.assertTrue(a_to_b.is_for_package)
        self.assertTrue(a_to_b.is_resolved_to_package)
        self.assertTrue(unresolved_dependency.is_project_dependency)
        self.assertFalse(unresolved_dependency.is_for_package)
        self.assertFalse(unresolved_dependency.is_resolved_to_package)

        project_packages_qs = project.discoveredpackages.order_by("name")
        root_packages = project_packages_qs.root_packages()
        self.assertEqual([a, z], list(root_packages))
        non_root_packages = project_packages_qs.non_root_packages()
        self.assertEqual([b, c], list(non_root_packages))

        dependency_qs = project.discovereddependencies
        self.assertEqual(
            [unresolved_dependency], list(dependency_qs.project_dependencies())
        )
        self.assertEqual([a_to_b, b_to_c], list(dependency_qs.package_dependencies()))
        self.assertEqual([a_to_b, b_to_c], list(dependency_qs.resolved()))
        self.assertEqual([unresolved_dependency], list(dependency_qs.unresolved()))

    @skipIf(sys.platform != "linux", "Ordering differs on macOS.")
    def test_scanpipe_codebase_resource_model_walk_method(self):
        fixtures = self.data / "asgiref" / "asgiref-3.3.0_walk_test_fixtures.json"
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

    def test_scanpipe_webhook_subscription_model_create(self):
        webhook = WebhookSubscription.objects.create(
            project=self.project1,
            target_url="https://url",
        )
        self.assertEqual("https://url", webhook.target_url)
        self.assertFalse(webhook.trigger_on_each_run)
        self.assertFalse(webhook.include_summary)
        self.assertFalse(webhook.include_results)
        self.assertTrue(webhook.is_active)

    @mock.patch("requests.post")
    def test_scanpipe_webhook_subscription_model_deliver_method(self, mock_post):
        webhook = self.project1.add_webhook_subscription(target_url="https://url")
        run1 = self.create_run()

        mock_post.side_effect = RequestException("Error from exception")
        webhook_delivery = webhook.deliver(pipeline_run=run1)
        self.assertEqual(run1, webhook_delivery.run)
        self.assertEqual("", webhook_delivery.response_text)
        self.assertIsNone(webhook_delivery.response_status_code)
        self.assertEqual("Error from exception", webhook_delivery.delivery_error)
        self.assertFalse(webhook_delivery.delivered)
        self.assertFalse(webhook_delivery.success)

        mock_post.side_effect = None
        mock_post.return_value = mock.Mock(status_code=404, text="text")
        webhook_delivery = webhook.deliver(pipeline_run=run1)
        self.assertEqual(run1, webhook_delivery.run)
        self.assertEqual("text", webhook_delivery.response_text)
        self.assertEqual(404, webhook_delivery.response_status_code)
        self.assertEqual("", webhook_delivery.delivery_error)
        self.assertTrue(webhook_delivery.delivered)
        self.assertFalse(webhook_delivery.success)

        mock_post.return_value = mock.Mock(status_code=200, text="text")
        webhook_delivery = webhook.deliver(pipeline_run=run1)
        self.assertEqual(run1, webhook_delivery.run)
        self.assertEqual("text", webhook_delivery.response_text)
        self.assertEqual(200, webhook_delivery.response_status_code)
        self.assertEqual("", webhook_delivery.delivery_error)
        self.assertTrue(webhook_delivery.delivered)
        self.assertTrue(webhook_delivery.success)

        self.assertEqual(3, webhook.deliveries.count())

    def test_scanpipe_webhook_subscription_model_get_payload(self):
        webhook = self.project1.add_webhook_subscription(target_url="https://localhost")
        run1 = self.create_run()
        payload = webhook.get_payload(run1)

        expected = {
            "project": {
                "name": "Analysis",
                "uuid": str(self.project1.uuid),
                "is_archived": False,
                "notes": "",
                "labels": [],
                "settings": {},
                "input_sources": [],
                "input_root": [],
                "output_root": [],
                "next_run": "pipeline",
                "extra_data": {},
                "message_count": 0,
                "resource_count": 0,
                "package_count": 0,
                "dependency_count": 0,
                "relation_count": 0,
                "codebase_resources_summary": {},
                "discovered_packages_summary": {
                    "total": 0,
                    "with_missing_resources": 0,
                    "with_modified_resources": 0,
                },
                "discovered_dependencies_summary": {
                    "total": 0,
                    "is_runtime": 0,
                    "is_optional": 0,
                    "is_resolved": 0,
                },
                "codebase_relations_summary": {},
                "results_url": f"/api/projects/{self.project1.uuid}/results/",
                "summary_url": f"/api/projects/{self.project1.uuid}/summary/",
            },
            "run": {
                "pipeline_name": "pipeline",
                "status": run1.status,
                "description": "",
                "selected_groups": None,
                "selected_steps": None,
                "uuid": str(run1.uuid),
                "scancodeio_version": "",
                "task_id": None,
                "task_start_date": None,
                "task_end_date": None,
                "task_exitcode": None,
                "task_output": "",
                "log": "",
                "execution_time": None,
            },
        }

        del payload["project"]["created_date"]
        del payload["run"]["created_date"]
        self.assertDictEqual(expected, payload)

        webhook.include_summary = True
        webhook.include_results = True
        webhook.save()
        payload = webhook.get_payload(run1)
        self.assertIn("summary", payload)
        self.assertIn("results", payload)

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
        bom_ref = package.package_uid
        self.assertEqual(bom_ref, str(cyclonedx_component.bom_ref))
        self.assertEqual(package.package_url, str(cyclonedx_component.purl))
        self.assertEqual(1, len(cyclonedx_component.licenses))
        self.assertEqual(
            package_data1["declared_license_expression_spdx"],
            cyclonedx_component.licenses[0].value,
        )
        self.assertEqual(
            package_data1["other_license_expression_spdx"],
            cyclonedx_component.evidence.licenses[0].value,
        )
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
            "aboutcode:package_uid": package_data1["package_uid"],
        }
        self.assertEqual(expected_properties, properties)

        external_references = cyclonedx_component.external_references
        self.assertEqual(1, len(external_references))
        self.assertEqual(
            "<ExternalReference SCM, https://packages.vcs.url>",
            str(external_references[0]),
        )
        self.assertEqual("vcs", external_references[0].type)
        self.assertEqual("https://packages.vcs.url", external_references[0].url)

        # LicenseRef are not supported by the license_factory.make_with_expression
        license_ref_expression = "LicenseRef-scancode-bash-exception-gpl-2.0"
        package.declared_license_expression_spdx = license_ref_expression
        package.other_license_expression_spdx = license_ref_expression
        package.save()
        cyclonedx_component = package.as_cyclonedx()
        self.assertEqual(license_ref_expression, cyclonedx_component.licenses[0].value)
        self.assertEqual(
            license_ref_expression,
            cyclonedx_component.evidence.licenses[0].value,
        )

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

    def test_scanpipe_discovered_dependency_model_many_to_many(self):
        project = Project.objects.create(name="project")

        a = make_package(project, "pkg:type/a")
        b = make_package(project, "pkg:type/b")
        c = make_package(project, "pkg:type/c")
        # A -> B -> C
        a_b = make_dependency(project, for_package=a, resolved_to_package=b)
        b_c = make_dependency(project, for_package=b, resolved_to_package=c)

        # *_packages fields return DiscoveredPackage QuerySet
        self.assertEqual([b], list(a.children_packages.all()))
        self.assertEqual([], list(a.parent_packages.all()))
        self.assertEqual([c], list(b.children_packages.all()))
        self.assertEqual([a], list(b.parent_packages.all()))
        self.assertEqual([], list(c.children_packages.all()))
        self.assertEqual([b], list(c.parent_packages.all()))

        # *_dependencies fields return DiscoveredDependency QuerySet
        self.assertEqual([a_b], list(a.declared_dependencies.all()))
        self.assertEqual([], list(a.resolved_from_dependencies.all()))
        self.assertEqual([b_c], list(b.declared_dependencies.all()))
        self.assertEqual([a_b], list(b.resolved_from_dependencies.all()))
        self.assertEqual([], list(c.declared_dependencies.all()))
        self.assertEqual([b_c], list(c.resolved_from_dependencies.all()))

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
            "datasource_ids",
            "datafile_paths",
            "filename",
            "affected_by_vulnerabilities",
            "compliance_alert",
            "tag",
            "declared_dependencies",
            "resolved_from_dependencies",
            "parent_packages",
            "children_packages",
            "notes",
        ]

        package_data_only_field = ["datasource_id", "dependencies"]

        discovered_package_fields = [
            field.name
            for field in DiscoveredPackage._meta.get_fields()
            if field.name not in scanpipe_only_fields
        ]
        toolkit_package_fields = [
            field.name
            for field in PackageData.__attrs_attrs__
            if field.name not in package_data_only_field
        ]

        for toolkit_field in toolkit_package_fields:
            self.assertIn(toolkit_field, discovered_package_fields)

        for scanpipe_field in discovered_package_fields:
            self.assertIn(scanpipe_field, toolkit_package_fields)

    def test_scanpipe_codebase_resource_queryset_has_directory_content_fingerprint(
        self,
    ):
        # This should be returned
        directory1 = make_resource_directory(self.project1, path="directory1")
        directory1.extra_data = {
            "directory_content": "00000003238f6ed2c218090d4da80b3b42160e69"
        }
        directory1.save()

        # This should not be returned because the fingerprint should be ignored
        directory2 = make_resource_directory(self.project1, path="directory2")
        directory2.extra_data = {
            "directory_content": "0000000000000000000000000000000000000000"
        }
        directory2.save()

        # This should not be returned because it does not contain a directory
        # fingerprint
        make_resource_directory(self.project1, path="directory3")

        self.assertEqual(3, self.project1.codebaseresources.count())
        expected = self.project1.codebaseresources.filter(path="directory1")
        results = self.project1.codebaseresources.has_directory_content_fingerprint()
        self.assertQuerySetEqual(expected, results, ordered=False)

    def test_scanpipe_codebase_resource_queryset_elfs(self):
        project = Project.objects.create(name="Test")
        resource_starting_with_elf_and_executable_in_file_type = CodebaseResource(
            file_type="""ELF 32-bit LSB executable, ARM, version 1 (ARM), statically
             linked, with debug_info, not stripped""",
            project=project,
            path="a",
            type=CodebaseResource.Type.FILE,
        )
        resource_starting_with_elf_and_executable_in_file_type.save()
        resource_with_executable_in_file_type = CodebaseResource(
            file_type="""32-bit LSB executable, ARM, version 1 (ARM), statically
              linked, with debug_info, not stripped""",
            project=project,
            path="b",
            type=CodebaseResource.Type.FILE,
        )
        resource_with_executable_in_file_type.save()
        resource_starting_with_elf_in_file_type = CodebaseResource(
            file_type="""ELF 32-bit LSB resourcable, ARM, version 1 (ARM), statically
             linked, with debug_info, not stripped""",
            project=project,
            path="c",
            type=CodebaseResource.Type.FILE,
        )
        resource_starting_with_elf_in_file_type.save()
        resource = CodebaseResource(
            file_type="""32-bit LSB relocatable, ARM, version 1 (ARM), statically
              linked, with debug_info, not stripped""",
            project=project,
            path="d",
            type=CodebaseResource.Type.FILE,
        )
        resource.save()
        resource_starting_with_elf_and_relocatable_in_file_type = CodebaseResource(
            file_type="""ELF 32-bit LSB relocatable, ARM, version 1 (ARM), statically
              linked, with debug_info, not stripped""",
            project=project,
            path="e",
            type=CodebaseResource.Type.FILE,
        )
        resource_starting_with_elf_and_relocatable_in_file_type.save()
        paths = [str(resource.path) for resource in project.codebaseresources.elfs()]
        self.assertTrue("e" in paths)
        self.assertTrue("a" in paths)

    def test_scanpipe_model_codebase_resource_compliance_alert_queryset_mixin(self):
        severities = CodebaseResource.Compliance
        make_resource_file(self.project1, path="none")
        make_resource_file(self.project1, path="ok", compliance_alert=severities.OK)
        warning = make_resource_file(
            self.project1, path="warning", compliance_alert=severities.WARNING
        )
        error = make_resource_file(
            self.project1, path="error", compliance_alert=severities.ERROR
        )
        missing = make_resource_file(
            self.project1, path="missing", compliance_alert=severities.MISSING
        )

        qs = CodebaseResource.objects.order_by("path")
        self.assertQuerySetEqual(qs.compliance_issues(severities.ERROR), [error])
        self.assertQuerySetEqual(
            qs.compliance_issues(severities.WARNING), [error, warning]
        )
        self.assertQuerySetEqual(
            qs.compliance_issues(severities.MISSING), [error, missing, warning]
        )


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

        pipeline_name = "inspect_packages"
        project1.add_pipeline(pipeline_name)
        pipeline_class = scanpipe_app.pipelines.get(pipeline_name)

        self.assertEqual(1, project1.runs.count())
        run = project1.runs.get()
        self.assertEqual(pipeline_name, run.pipeline_name)
        self.assertEqual(pipeline_class.get_summary(), run.description)
        mock_execute_task.assert_not_called()

        project2 = Project.objects.create(name="Analysis 2")
        project2.add_pipeline(pipeline_name, execute_now=True)
        mock_execute_task.assert_called_once()

    @mock.patch("scanpipe.models.Run.execute_task_async")
    def test_scanpipe_project_model_add_pipeline_run_can_start(self, mock_execute_task):
        project1 = Project.objects.create(name="Analysis")
        pipeline_name = "inspect_packages"
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
        pipeline_name = "inspect_packages"
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

    def test_scanpipe_project_model_add_pipeline_selected_groups(self):
        project1 = Project.objects.create(name="Analysis")
        pipeline_name = "scan_codebase"

        run1 = project1.add_pipeline(pipeline_name, selected_groups=[])
        self.assertEqual([], run1.selected_groups)

        run2 = project1.add_pipeline(pipeline_name, selected_groups=["foo"])
        self.assertEqual(["foo"], run2.selected_groups)

        run3 = project1.add_pipeline(pipeline_name, selected_groups=["foo", "bar"])
        self.assertEqual(["foo", "bar"], run3.selected_groups)

        with self.assertRaises(ValidationError):
            project1.add_pipeline(pipeline_name, selected_groups={})

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
        codebase_resource = CodebaseResource.objects.create(project=project1, path="a")
        error = codebase_resource.add_error(Exception("Error message"))

        self.assertEqual(error, ProjectMessage.objects.get())
        self.assertEqual("CodebaseResource", error.model)
        self.assertTrue(error.details)
        self.assertEqual("Error message", error.description)
        self.assertEqual("", error.traceback)
        self.assertEqual(codebase_resource.path, error.details["resource_path"])

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
        expected_message = 'No values provided for the required "name" field.'
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

    def test_scanpipe_discovered_package_model_create_from_data_missing_type(self):
        project1 = Project.objects.create(name="Analysis")

        incomplete_data = dict(package_data1)
        incomplete_data["type"] = ""

        package = DiscoveredPackage.create_from_data(project1, incomplete_data)
        self.assertEqual(project1, package.project)
        self.assertEqual("pkg:unknown/debian/adduser@3.118?arch=all", str(package))
        self.assertEqual("unknown", package.type)

    @skipIf(connection.vendor == "sqlite", "No max_length constraints on SQLite.")
    def test_scanpipe_discovered_dependency_model_create_from_data(self):
        project1 = Project.objects.create(name="Analysis")

        package1 = DiscoveredPackage.create_from_data(project1, package_data1)
        CodebaseResource.objects.create(
            project=project1, path="daglib-0.3.2.tar.gz-extract/daglib-0.3.2/PKG-INFO"
        )
        # Unresolved dependency
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
        self.assertFalse(dependency.is_project_dependency)
        self.assertTrue(dependency.is_for_package)
        self.assertFalse(dependency.is_resolved_to_package)

        # Resolved project dependency, resolved_to_package provided as arg
        dependency2 = DiscoveredDependency.create_from_data(
            project1, dependency_data={}, resolved_to_package=package1
        )
        self.assertTrue(dependency2.is_project_dependency)
        self.assertFalse(dependency2.is_for_package)
        self.assertTrue(dependency2.is_resolved_to_package)

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
        self.assertTrue(package2.package_uid)
        self.assertNotEqual(package.package_uid, package2.package_uid)
        package3 = DiscoveredPackage.create_from_data(project1, package_data_no_uid)
        self.assertTrue(package3.package_uid)
        self.assertNotEqual(package.package_uid, package3.package_uid)

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
        self.assertEqual(resource.path, message.details["resource_path"])
        self.assertIn("in save", message.traceback)
