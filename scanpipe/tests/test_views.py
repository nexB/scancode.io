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

import json
import shutil
import uuid
from pathlib import Path
from unittest import mock

from django.apps import apps
from django.core.exceptions import SuspiciousFileOperation
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch

import requests

from scanpipe.models import CodebaseRelation
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredPackage
from scanpipe.models import Project
from scanpipe.pipes import make_relation
from scanpipe.pipes import update_or_create_dependency
from scanpipe.pipes.input import copy_input
from scanpipe.pipes.input import copy_inputs
from scanpipe.tests import dependency_data1
from scanpipe.tests import dependency_data2
from scanpipe.tests import make_resource_file
from scanpipe.tests import package_data1
from scanpipe.tests import package_data2
from scanpipe.views import ProjectCodebaseView
from scanpipe.views import ProjectDetailView

scanpipe_app = apps.get_app_config("scanpipe")


@override_settings(SCANCODEIO_REQUIRE_AUTHENTICATION=False)
class ScanPipeViewsTest(TestCase):
    data = Path(__file__).parent / "data"

    def setUp(self):
        self.project1 = Project.objects.create(name="Analysis")

    def test_scanpipe_views_project_list_is_archived(self):
        project2 = Project.objects.create(name="project2", is_archived=True)
        url = reverse("project_list")
        is_archive_filter = "?is_archived=true"

        response = self.client.get(url)
        self.assertContains(response, self.project1.name)
        self.assertNotContains(response, project2.name)
        self.assertContains(response, url)
        self.assertContains(response, is_archive_filter)

        response = self.client.get(url + is_archive_filter)
        self.assertNotContains(response, self.project1.name)
        self.assertContains(response, project2.name)

    def test_scanpipe_views_project_list_filters(self):
        url = reverse("project_list")
        response = self.client.get(url)

        is_archived_filters = """
        <li>
          <a href="?is_archived=" class=" is-active">
            <i class="fa-solid fa-seedling"></i> 1 Active
          </a>
        </li>
        <li>
          <a href="?is_archived=true" class="">
            <i class="fa-solid fa-dice-d6"></i> 0 Archived
          </a>
        </li>
        """
        self.assertContains(response, is_archived_filters, html=True)

        pipeline_filters = [
            "?pipeline=analyze_docker_image",
            "?pipeline=analyze_windows_docker_image",
            "?pipeline=load_inventory",
            "?pipeline=analyze_root_filesystem_or_vm_image",
            "?pipeline=scan_codebase",
            "?pipeline=scan_single_package",
        ]
        for pipeline_filter in pipeline_filters:
            self.assertContains(response, pipeline_filter)

        status_filters = """
        <li><a href="?status=" class="dropdown-item is-active">All</a></li>
        <li><a href="?status=not_started" class="dropdown-item">Not started</a></li>
        <li><a href="?status=queued" class="dropdown-item">Queued</a></li>
        <li><a href="?status=running" class="dropdown-item">Running</a></li>
        <li><a href="?status=succeed" class="dropdown-item">Success</a></li>
        <li><a href="?status=failed" class="dropdown-item">Failure</a></li>
        """
        self.assertContains(response, status_filters, html=True)

        sort_filters = """
        <li><a href="?sort=" class="dropdown-item is-active">Newest</a></li>
        <li><a href="?sort=created_date" class="dropdown-item">Oldest</a></li>
        <li><a href="?sort=name" class="dropdown-item">Name (A-z)</a></li>
        <li><a href="?sort=-name" class="dropdown-item">Name (z-A)</a></li>
        """
        self.assertContains(response, sort_filters, html=True)

    def test_scanpipe_views_project_list_state_of_filters_in_search_form(self):
        url = reverse("project_list")
        data = {
            "status": "failed",
            "search": "query",
        }
        response = self.client.get(url, data=data)

        expected = (
            '<input class="input " type="search" placeholder="Search projects" '
            'name="search" value="query">'
        )
        self.assertContains(response, expected, html=True)

        expected = '<input type="hidden" name="status" value="failed">'
        self.assertContains(response, expected, html=True)

    @mock.patch("scanpipe.views.ProjectListView.get_paginate_by")
    def test_scanpipe_views_project_list_filters_exclude_page(self, mock_paginate_by):
        url = reverse("project_list")
        # Create another project to enable pagination
        Project.objects.create(name="project2")
        mock_paginate_by.return_value = 1

        data = {"page": "2"}
        response = self.client.get(url, data=data)

        expected = '<a href="?page=2&amp;sort=name" class="is-black-link">Name</a>'
        self.assertContains(response, expected, html=True)
        expected = '<li><a href="?status=" class="dropdown-item is-active">All</a></li>'
        self.assertContains(response, expected)
        expected = '<a href="?pipeline=" class="dropdown-item is-active">All</a>'
        self.assertContains(response, expected)
        expected = '<a href="?sort=" class="dropdown-item is-active">Newest</a>'
        self.assertContains(response, expected)

    def test_scanpipe_views_project_actions_view(self):
        url = reverse("project_action")
        response = self.client.get(url)
        self.assertEqual(405, response.status_code)

        response = self.client.post(url)
        self.assertEqual(404, response.status_code)

        data = {"action": "does_not_exists"}
        response = self.client.post(url, data=data)
        self.assertEqual(404, response.status_code)

        data = {"action": "delete"}
        response = self.client.post(url, data=data)
        self.assertEqual(404, response.status_code)

        random_uuid = uuid.uuid4()
        data = {
            "action": "delete",
            "selected_ids": f"{self.project1.uuid},{random_uuid}",
        }
        response = self.client.post(url, data=data, follow=True)
        self.assertRedirects(response, reverse("project_list"))
        expected = '<div class="message-body">1 projects have been delete.</div>'
        self.assertContains(response, expected, html=True)
        expected = (
            f'<div class="message-body">Project {random_uuid} does not exist.</div>'
        )
        self.assertContains(response, expected, html=True)

    def test_scanpipe_views_project_details_is_archived(self):
        url = self.project1.get_absolute_url()
        expected1 = "WARNING: This project is archived and read-only."

        response = self.client.get(url)
        self.assertNotContains(response, expected1)

        self.project1.archive()
        response = self.client.get(url)
        self.assertContains(response, expected1)

    @mock.patch("requests.sessions.Session.head")
    def test_scanpipe_views_project_details_add_inputs(self, mock_head):
        url = self.project1.get_absolute_url()

        data = {
            "input_urls": "https://example.com/archive.zip",
            "add-inputs-submit": "",
        }

        mock_head.side_effect = requests.exceptions.RequestException
        response = self.client.post(url, data, follow=True)
        self.assertContains(response, "Input file addition error.")

        mock_head.side_effect = None
        mock_head.return_value = mock.Mock(headers={}, status_code=200)
        response = self.client.post(url, data, follow=True)
        self.assertContains(response, "Input file(s) added.")

        inputs_with_source = self.project1.get_inputs_with_source()
        expected = [
            {
                "uuid": str(self.project1.inputsources.get().uuid),
                "filename": "",
                "download_url": "https://example.com/archive.zip",
                "is_uploaded": False,
                "tag": "",
                "size": None,
                "is_file": True,
                "exists": False,
            }
        ]
        self.assertEqual(expected, inputs_with_source)

    def test_scanpipe_views_project_details_download_input_view(self):
        url = reverse("project_download_input", args=[self.project1.slug, "file.zip"])
        response = self.client.get(url)
        self.assertEqual(404, response.status_code)

        file_location = self.data / "aboutcode" / "notice.NOTICE"
        copy_input(file_location, self.project1.input_path)
        filename = file_location.name
        url = reverse("project_download_input", args=[self.project1.slug, filename])
        response = self.client.get(url)
        self.assertTrue(response.getvalue().startswith(b"# SPDX-License-Identifier"))
        self.assertEqual("application/octet-stream", response.headers["Content-Type"])
        self.assertEqual(
            'attachment; filename="notice.NOTICE"',
            response.headers["Content-Disposition"],
        )

    def test_scanpipe_views_project_details_download_output_view(self):
        url = reverse("project_download_output", args=[self.project1.slug, "file.zip"])
        response = self.client.get(url)
        self.assertEqual(404, response.status_code)

        file_location = self.data / "aboutcode" / "notice.NOTICE"
        copy_input(file_location, self.project1.output_path)
        filename = file_location.name
        url = reverse("project_download_output", args=[self.project1.slug, filename])
        response = self.client.get(url)
        self.assertTrue(response.getvalue().startswith(b"# SPDX-License-Identifier"))
        self.assertEqual("application/octet-stream", response.headers["Content-Type"])
        self.assertEqual(
            'attachment; filename="notice.NOTICE"',
            response.headers["Content-Disposition"],
        )

    def test_scanpipe_views_project_details_delete_input_view(self):
        random_uuid = str(uuid.uuid4())
        url = reverse("project_delete_input", args=[self.project1.slug, random_uuid])
        response = self.client.get(url)
        self.assertEqual(405, response.status_code)
        response = self.client.post(url, follow=True)
        self.assertEqual(404, response.status_code)

        file_location = self.data / "aboutcode" / "notice.NOTICE"
        copy_input(file_location, self.project1.input_path)
        filename = file_location.name
        input1 = self.project1.add_input_source(filename=filename, is_uploaded=True)

        self.project1.update(is_archived=True)
        self.assertFalse(self.project1.can_change_inputs)
        url = reverse("project_delete_input", args=[self.project1.slug, input1.uuid])
        response = self.client.post(url)
        self.assertEqual(404, response.status_code)

        self.project1.update(is_archived=False)
        self.project1 = Project.objects.get(pk=self.project1.pk)
        self.assertTrue(self.project1.can_change_inputs)
        response = self.client.post(url, follow=True)
        self.assertRedirects(response, self.project1.get_absolute_url())
        expected = f'<div class="message-body">Input {filename} deleted.</div>'
        self.assertContains(response, expected, html=True)

        self.assertEqual([], self.project1.input_sources)
        self.assertEqual([], list(self.project1.inputs()))

    def test_scanpipe_views_project_details_missing_inputs(self):
        self.project1.add_input_source(filename="missing.zip", is_uploaded=True)
        url = self.project1.get_absolute_url()
        response = self.client.get(url)
        expected = (
            '<div class="message-body">'
            "    The following input files are not available on disk anymore:<br>"
            "    - missing.zip"
            "</div>"
        )
        self.assertContains(response, expected, html=True)

    def test_scanpipe_views_project_details_add_pipelines(self):
        url = self.project1.get_absolute_url()
        data = {
            "pipeline": "analyze_docker_image",
        }
        response = self.client.post(url, data, follow=True)
        self.assertEqual(404, response.status_code)

        data["add-pipeline-submit"] = ""
        response = self.client.post(url, data, follow=True)
        self.assertContains(response, "Pipeline added.")
        run = self.project1.runs.get()
        self.assertEqual("analyze_docker_image", run.pipeline_name)
        self.assertIsNone(run.task_start_date)

    def test_scanpipe_views_project_details_get_pipeline_choices(self):
        main_pipeline1 = "scan_codebase"
        main_pipeline2 = "scan_single_package"
        addon_pipeline = "find_vulnerabilities"

        choices = ProjectDetailView.get_pipeline_choices(pipeline_runs=[])
        pipeline_choices = [choice[0] for choice in choices]
        self.assertIn(main_pipeline1, pipeline_choices)
        self.assertIn(main_pipeline2, pipeline_choices)
        self.assertNotIn(addon_pipeline, pipeline_choices)

        self.project1.add_pipeline(pipeline_name=main_pipeline1)
        choices = ProjectDetailView.get_pipeline_choices(
            pipeline_runs=self.project1.runs.all()
        )
        pipeline_choices = [choice[0] for choice in choices]
        self.assertIn(main_pipeline1, pipeline_choices)
        self.assertNotIn(main_pipeline2, pipeline_choices)
        self.assertIn(addon_pipeline, pipeline_choices)

    def test_scanpipe_views_project_details_add_labels(self):
        url = self.project1.get_absolute_url()
        data = {
            "labels": "label1, label2",
        }
        response = self.client.post(url, data, follow=True)
        self.assertEqual(404, response.status_code)

        data["add-labels-submit"] = ""
        response = self.client.post(url, data, follow=True)
        self.assertContains(response, "Label(s) added.")
        self.assertEqual(["label1", "label2"], sorted(self.project1.labels.names()))

    def test_scanpipe_views_project_delete_label(self):
        self.project1.labels.add("label1")
        url = reverse("project_delete_label", args=[self.project1.slug, "label1"])
        response = self.client.get(url)
        self.assertEqual(405, response.status_code)

        response = self.client.post(url)
        self.assertEqual(200, response.status_code)
        self.assertEqual({}, response.json())
        self.assertEqual([], list(self.project1.labels.names()))

    def test_scanpipe_views_project_details_edit_input_source_tag(self):
        url = self.project1.get_absolute_url()
        input_source = self.project1.add_input_source(
            filename="filename.zip",
            is_uploaded=True,
            tag="base value",
        )
        data = {
            "input_source_uuid": input_source.uuid,
            "tag": "new value",
            "edit-input-tag-submit": "",
        }
        response = self.client.post(url, data, follow=True)
        self.assertContains(response, "Tag updated.")
        input_source.refresh_from_db()
        self.assertEqual(data["tag"], input_source.tag)

    def test_scanpipe_views_project_details_charts_view(self):
        url = reverse("project_charts", args=[self.project1.slug])

        with self.assertNumQueries(9):
            response = self.client.get(url)

        self.assertNotContains(response, 'id="package-charts"')
        self.assertNotContains(response, 'id="dependency-charts"')
        self.assertNotContains(response, 'id="resource-charts-charts"')

        CodebaseResource.objects.create(
            project=self.project1,
            programming_language="Python",
            type=CodebaseResource.Type.FILE,
        )

        with self.assertNumQueries(12):
            response = self.client.get(url)
        self.assertContains(response, '{"Python": 1}')

    def test_scanpipe_views_project_details_charts_compliance_alert(self):
        url = reverse("project_charts", args=[self.project1.slug])
        expected = 'id="compliance_alert_chart"'

        response = self.client.get(url)
        self.assertNotContains(response, expected)

        response = self.client.get(url)
        self.assertNotContains(response, expected)

        resource = CodebaseResource.objects.create(
            project=self.project1,
            type=CodebaseResource.Type.FILE,
        )
        CodebaseResource.objects.filter(id=resource.id).update(
            compliance_alert=CodebaseResource.Compliance.ERROR
        )

        response = self.client.get(url)
        self.assertContains(response, expected)
        self.assertContains(response, '{"error": 1}')

    def test_scanpipe_views_project_details_scan_summary_panels(self):
        url = self.project1.get_absolute_url()

        expected1 = 'id="license-clarity-panel"'
        expected2 = 'id="scan-summary-panel"'

        response = self.client.get(url)
        self.assertNotContains(response, expected1)
        self.assertNotContains(response, expected2)

        summary_file = self.project1.get_output_file_path("summary", "json")
        with summary_file.open("wb") as opened_file:
            opened_file.write(b"\x21")

        response = self.client.get(url)
        self.assertNotContains(response, expected1)
        self.assertNotContains(response, expected2)

        scan_summary = self.data / "scancode" / "is-npm-1.0.0_scan_package_summary.json"
        with summary_file.open("w") as opened_file:
            opened_file.write(scan_summary.read_text())

        response = self.client.get(url)
        self.assertContains(response, expected1)
        self.assertContains(response, expected2)

    def test_scanpipe_views_project_details_get_license_clarity_data(self):
        get_license_clarity_data = ProjectDetailView.get_license_clarity_data

        scan_summary = self.data / "scancode" / "is-npm-1.0.0_scan_package_summary.json"
        scan_summary_json = json.loads(scan_summary.read_text())
        license_clarity_data = get_license_clarity_data(scan_summary_json)

        self.assertEqual(7, len(license_clarity_data))
        expected = ["label", "value", "help_text", "weight"]
        self.assertEqual(expected, list(license_clarity_data[0].keys()))

        score_entry = license_clarity_data[-1]
        self.assertEqual("Score", score_entry.get("label"))
        self.assertEqual(90, score_entry.get("value"))
        self.assertIsNone(score_entry.get("weight"))

    def test_scanpipe_views_project_details_get_scan_summary_data(self):
        get_scan_summary_data = ProjectDetailView.get_scan_summary_data

        scan_summary = self.data / "scancode" / "is-npm-1.0.0_scan_package_summary.json"
        scan_summary_json = json.loads(scan_summary.read_text())
        scan_summary_data = get_scan_summary_data(self.project1, scan_summary_json)

        self.assertEqual(7, len(scan_summary_data))
        expected = [
            "declared_license_expression",
            "declared_holder",
            "primary_language",
            "other_license_expressions",
            "other_holders",
            "other_languages",
            "key_file_licenses",
        ]
        self.assertEqual(expected, list(scan_summary_data.keys()))

    def test_scanpipe_views_project_details_codebase_root(self):
        (self.project1.codebase_path / "z.txt").touch()
        (self.project1.codebase_path / "a.txt").touch()
        (self.project1.codebase_path / "z").mkdir()
        (self.project1.codebase_path / "a").mkdir()
        (self.project1.codebase_path / "Zdir").mkdir()
        (self.project1.codebase_path / "Dir").mkdir()

        url = self.project1.get_absolute_url()
        response = self.client.get(url)
        codebase_root = response.context_data["codebase_root"]
        expected = ["Dir", "Zdir", "a", "z", "a.txt", "z.txt"]
        self.assertEqual(expected, [path.name for path in codebase_root])

    def test_scanpipe_views_project_create_view(self):
        url = reverse("project_add")
        response = self.client.get(url)
        self.assertContains(response, "scan_codebase")
        self.assertNotContains(response, "find_vulnerabilities")

    def test_scanpipe_views_project_codebase_view(self):
        url = reverse("project_codebase", args=[self.project1.slug])

        (self.project1.codebase_path / "dir1").mkdir()
        (self.project1.codebase_path / "dir1/dir2").mkdir()
        (self.project1.codebase_path / "file.txt").touch()

        response = self.client.get(url)
        self.assertContains(response, "/codebase/?current_dir=./dir1")
        self.assertContains(response, "/resources/./file.txt/")

        data = {"current_dir": "dir1"}
        response = self.client.get(url, data=data)
        self.assertContains(response, "..")
        self.assertContains(response, "/codebase/?current_dir=.")
        self.assertContains(response, "/codebase/?current_dir=dir1/dir2")

        data = {"current_dir": "not_existing"}
        response = self.client.get(url, data=data)
        self.assertEqual(404, response.status_code)

        data = {"current_dir": "../"}
        response = self.client.get(url, data=data)
        self.assertEqual(404, response.status_code)

    def test_scanpipe_views_project_codebase_view_ordering(self):
        url = reverse("project_codebase", args=[self.project1.slug])
        (self.project1.codebase_path / "z.txt").touch()
        (self.project1.codebase_path / "a.txt").touch()
        (self.project1.codebase_path / "z").mkdir()
        (self.project1.codebase_path / "a").mkdir()
        (self.project1.codebase_path / "Zdir").mkdir()
        (self.project1.codebase_path / "Dir").mkdir()

        response = self.client.get(url)
        codebase_tree = response.context_data["codebase_tree"]
        expected = ["Dir", "Zdir", "a", "z", "a.txt", "z.txt"]
        self.assertEqual(expected, [path.get("name") for path in codebase_tree])

    def test_scanpipe_views_project_codebase_view_get_tree(self):
        get_tree = ProjectCodebaseView.get_tree

        (self.project1.codebase_path / "dir1").mkdir()
        (self.project1.codebase_path / "dir1/dir2").mkdir()
        (self.project1.codebase_path / "file.txt").touch()

        with mock.patch.object(scanpipe_app, "workspace_path", ""):
            self.assertEqual("", scanpipe_app.workspace_path)
            with self.assertRaises(ValueError) as e:
                get_tree(self.project1, current_dir="")

        with self.assertRaises(FileNotFoundError):
            get_tree(self.project1, current_dir="not_existing")

        with self.assertRaises(SuspiciousFileOperation) as e:
            get_tree(self.project1, current_dir="../../")
        self.assertIn("is located outside of the base path component", str(e.exception))

        codebase_tree = get_tree(self.project1, current_dir="")
        expected = [
            {"name": "dir1", "is_dir": True, "location": "/dir1"},
            {"name": "file.txt", "is_dir": False, "location": "/file.txt"},
        ]
        self.assertEqual(expected, codebase_tree)

        codebase_tree = get_tree(self.project1, current_dir="dir1")
        expected = [
            {"name": "..", "is_dir": True, "location": "."},
            {"name": "dir2", "is_dir": True, "location": "dir1/dir2"},
        ]
        self.assertEqual(expected, codebase_tree)

        shutil.rmtree(self.project1.work_directory, ignore_errors=True)
        self.assertFalse(self.project1.codebase_path.exists())
        with self.assertRaises(Exception):
            get_tree(self.project1, current_dir="")

    def test_scanpipe_views_project_archive_view(self):
        url = reverse("project_archive", args=[self.project1.slug])
        run = self.project1.add_pipeline("analyze_docker_image")
        run.set_task_started(run.pk)

        response = self.client.post(url, follow=True)
        expected = (
            "Cannot execute this action until all associated pipeline runs "
            "are completed."
        )
        self.assertContains(response, expected)

        run.set_task_ended(exitcode=0)
        response = self.client.post(url, follow=True)
        expected = "has been archived."
        self.assertContains(response, expected)
        self.project1.refresh_from_db()
        self.assertTrue(self.project1.is_archived)

    def test_scanpipe_views_project_delete_view(self):
        url = reverse("project_delete", args=[self.project1.slug])
        run = self.project1.add_pipeline("analyze_docker_image")
        run.set_task_started(run.pk)

        response = self.client.post(url, follow=True)
        expected = (
            "Cannot execute this action until all associated pipeline runs "
            "are completed."
        )
        self.assertContains(response, expected)

        run.set_task_ended(exitcode=0)
        response = self.client.post(url, follow=True)
        expected = "all its related data have been removed."
        self.assertContains(response, expected)
        self.assertFalse(Project.objects.filter(name=self.project1.name).exists())

    def test_scanpipe_views_project_reset_view(self):
        url = reverse("project_reset", args=[self.project1.slug])
        run = self.project1.add_pipeline("analyze_docker_image")
        run.set_task_started(run.pk)

        response = self.client.post(url, follow=True)
        expected = (
            "Cannot execute this action until all associated pipeline runs "
            "are completed."
        )
        self.assertContains(response, expected)

        run.set_task_ended(exitcode=0)
        response = self.client.post(url, follow=True)
        expected = "have been removed."
        self.assertContains(response, expected)
        self.assertTrue(Project.objects.filter(name=self.project1.name).exists())

    def test_scanpipe_views_project_settings_view(self):
        url = reverse("project_settings", args=[self.project1.slug])
        response = self.client.get(url)
        expected_ids = [
            "id_name",
            "id_notes",
            "id_uuid",
            "id_work_directory",
            "id_ignored_patterns",
            "id_attribution_template",
            'id="modal-archive"',
            'id="modal-reset"',
            'id="modal-delete"',
        ]
        for expected in expected_ids:
            self.assertContains(response, expected)

        # Forcing a validation error
        project2 = Project.objects.create(name="p2")
        data = {"name": project2.name}
        response = self.client.post(url, data)
        expected_error = "<li>Project with this Name already exists.</li>"
        self.assertContains(response, expected_error)

    def test_scanpipe_views_project_settings_view_download_config_file(self):
        url = reverse("project_settings", args=[self.project1.slug])
        self.project1.settings = {"product_name": "Product"}
        self.project1.save()

        response = self.client.get(url, data={"download": 1})
        self.assertEqual(b"product_name: Product\n", response.getvalue())
        self.assertEqual("application/x-yaml", response.headers["Content-Type"])

    def test_scanpipe_views_project_views(self):
        self.project1.labels.add("label1", "label2")
        project2 = Project.objects.create(name="Analysis2")
        project2.labels.add("label3", "label4")

        url = reverse("project_list")
        with self.assertNumQueries(8):
            self.client.get(url)

        with self.assertNumQueries(13):
            self.client.get(self.project1.get_absolute_url())

    @mock.patch("scanpipe.models.Run.execute_task_async")
    def test_scanpipe_views_execute_pipelines_view(self, mock_execute_task):
        run = self.project1.add_pipeline("analyze_docker_image")
        url = reverse("project_execute_pipelines", args=[self.project1.slug])

        response = self.client.get(url, follow=True)
        expected = "Pipelines run started."
        self.assertContains(response, expected)
        mock_execute_task.assert_called_once()
        self.assertRedirects(response, self.project1.get_absolute_url())

        run.set_task_queued()
        response = self.client.get(url)
        self.assertEqual(404, response.status_code)

        run.set_task_started(run.pk)
        response = self.client.get(url)
        self.assertEqual(404, response.status_code)

        run.set_task_stopped()
        response = self.client.get(url)
        self.assertEqual(404, response.status_code)

    @mock.patch("scanpipe.models.Run.stop_task")
    def test_scanpipe_views_stop_pipeline_view(self, mock_stop_task):
        run = self.project1.add_pipeline("analyze_docker_image")
        url = reverse("project_stop_pipeline", args=[self.project1.slug, run.uuid])

        response = self.client.get(url)
        self.assertEqual(404, response.status_code)

        run.set_task_started(run.pk)
        response = self.client.get(url, follow=True)
        expected = f"Pipeline {run.pipeline_name} stopped."
        self.assertContains(response, expected)
        mock_stop_task.assert_called_once()

    @mock.patch("scanpipe.models.Run.delete_task")
    def test_scanpipe_views_delete_pipeline_view(self, mock_delete_task):
        run = self.project1.add_pipeline("analyze_docker_image")
        url = reverse("project_delete_pipeline", args=[self.project1.slug, run.uuid])

        response = self.client.get(url, follow=True)
        expected = f"Pipeline {run.pipeline_name} deleted."
        self.assertContains(response, expected)
        mock_delete_task.assert_called_once()

        run.set_task_stopped()
        response = self.client.get(url)
        self.assertEqual(404, response.status_code)

    def test_scanpipe_views_run_status_view(self):
        run = self.project1.add_pipeline("analyze_docker_image")
        url = reverse("run_status", args=[run.uuid])

        response = self.client.get(url)
        expected = '<span class="tag is-light">Not started</span>'
        self.assertContains(response, expected)

        run.set_task_queued()
        run.refresh_from_db()
        response = self.client.get(url)
        expected = '<i class="fa-solid fa-clock mr-1"></i>Queued'
        self.assertContains(response, expected)
        self.assertContains(response, f'hx-get="{url}?current_status={run.status}"')

        run.current_step = "1/2 Step A"
        run.save()
        run.set_task_started(run.pk)
        run.refresh_from_db()
        response = self.client.get(url)
        expected = (
            '<i class="fa-solid fa-spinner fa-pulse mr-1" aria-hidden="true"></i>'
            "Running"
        )
        self.assertContains(response, expected)
        self.assertContains(response, f'hx-get="{url}?current_status={run.status}"')

        response = self.client.get(url, data={"display_current_step": True})
        expected = (
            f'hx-get="{url}?current_status={run.status}&display_current_step=True"'
        )
        self.assertContains(response, expected)
        self.assertContains(response, "1/2 Step A")

        run.set_task_ended(exitcode=1)
        response = self.client.get(url)
        expected = '<span class="tag is-danger">Failure</span>'
        self.assertContains(response, expected)

        run.set_task_ended(exitcode=0)
        response = self.client.get(url)
        expected = '<span class="tag is-success">Success</span>'
        self.assertContains(response, expected)

        run.set_task_staled()
        response = self.client.get(url)
        expected = '<span class="tag is-dark">Stale</span>'
        self.assertContains(response, expected)

        run.set_task_stopped()
        response = self.client.get(url)
        expected = '<span class="tag is-danger">Stopped</span>'
        self.assertContains(response, expected)

    def test_scanpipe_views_project_run_step_selection_view(self):
        run = self.project1.add_pipeline("do_nothing")
        url = reverse("project_run_step_selection", args=[run.uuid])

        response = self.client.get(url)
        expected_input1 = (
            '<input type="checkbox" name="selected_steps" value="step1" '
            'id="id_selected_steps_0" checked>'
        )
        self.assertContains(response, expected_input1)
        expected_input2 = (
            '<input type="checkbox" name="selected_steps" value="step2" '
            'id="id_selected_steps_1" checked>'
        )
        self.assertContains(response, expected_input2)

        response = self.client.post(url, data={"selected_steps": ["invalid"]})
        expected = "Select a valid choice. invalid is not one of the available choices."
        self.assertContains(response, expected, html=True)

        response = self.client.post(url, data={"selected_steps": ["step1"]})
        expected = (
            '<div id="run-step-selection-box" class="box has-background-success-light">'
            "Steps updated successfully."
            "</div>"
        )
        self.assertContains(response, expected, html=True)
        run.refresh_from_db()
        self.assertEqual(["step1"], run.selected_steps)
        response = self.client.get(url)
        self.assertContains(response, expected_input1)
        # Not checked anymore in the initial data
        expected_input2 = (
            '<input type="checkbox" name="selected_steps" value="step2" '
            'id="id_selected_steps_1">'
        )
        self.assertContains(response, expected_input2)

    def test_scanpipe_views_pipeline_help_view(self):
        url = reverse("pipeline_help", args=["not_existing_pipeline"])
        response = self.client.get(url)
        self.assertEqual(404, response.status_code)

        url = reverse("pipeline_help", args=["map_deploy_to_develop"])
        response = self.client.get(url)
        expected = "<strong>map_deploy_to_develop</strong>"
        self.assertContains(response, expected, html=True)
        expected = (
            "<div>Locate the <code>from</code> and <code>to</code> input files.</div>"
        )
        self.assertContains(response, expected, html=True)

    def test_scanpipe_views_codebase_resource_list_view_bad_search_query(self):
        url = reverse("project_resources", args=[self.project1.slug])
        data = {"search": "'"}  # No closing quotation
        response = self.client.get(url, data=data)
        expected_error = "The provided search value is invalid: No closing quotation"
        self.assertContains(response, expected_error)

    def test_scanpipe_views_codebase_resource_details_view_tab_image(self):
        resource1 = make_resource_file(self.project1, "file1.ext")
        response = self.client.get(resource1.get_absolute_url())
        self.assertNotContains(response, "tab-image")
        self.assertNotContains(response, resource1.get_raw_url())

        resource2 = make_resource_file(self.project1, "img.jpg", mime_type="image/jpeg")
        response = self.client.get(resource2.get_absolute_url())
        self.assertContains(response, "tab-image")
        self.assertContains(response, "This resource is not available on disk.")

    def test_scanpipe_views_codebase_resource_details_view_tabset(self):
        resource1 = make_resource_file(self.project1, "file1.ext")
        response = self.client.get(resource1.get_absolute_url())
        self.assertContains(response, 'data-target="tab-essentials"')
        self.assertContains(response, 'id="tab-essentials"')
        self.assertContains(response, 'data-target="tab-others"')
        self.assertContains(response, 'id="tab-others"')
        self.assertContains(response, 'data-target="tab-viewer"')
        self.assertContains(response, 'id="tab-viewer"')
        self.assertNotContains(response, 'data-target="tab-terms"')
        self.assertNotContains(response, 'id="tab-terms"')
        self.assertNotContains(response, 'data-target="tab-resource-detection"')
        self.assertNotContains(response, 'id="tab-resource-detection"')
        self.assertNotContains(response, 'data-target="tab-packages"')
        self.assertNotContains(response, 'id="tab-packages"')
        self.assertNotContains(response, 'data-target="tab-relations"')
        self.assertNotContains(response, 'id="tab-relations"')
        self.assertNotContains(response, 'data-target="tab-extra_data"')
        self.assertNotContains(response, 'id="tab-extra_data"')

        resource1.detected_license_expression = "mit"
        resource1.extra_data = {"extra": "data"}
        resource1.save()
        resource1.create_and_add_package(package_data1)
        make_relation(
            from_resource=resource1,
            to_resource=make_resource_file(self.project1, "from/file2.ext"),
            map_type="path",
        )
        response = self.client.get(resource1.get_absolute_url())
        self.assertContains(response, 'data-target="tab-terms"')
        self.assertContains(response, 'id="tab-terms"')
        self.assertContains(response, 'data-target="tab-relations"')
        self.assertContains(response, 'id="tab-relations"')
        self.assertContains(response, 'data-target="tab-extra_data"')
        self.assertContains(response, 'id="tab-extra_data"')

    def test_scanpipe_views_codebase_relation_list_view_count(self):
        url = reverse("project_relations", args=[self.project1.slug])

        to_1 = make_resource_file(self.project1, "to/file1.ext")
        to_2 = make_resource_file(self.project1, "to/file2.ext")
        from_1 = make_resource_file(self.project1, "from/file1.ext")
        from_2 = make_resource_file(self.project1, "from/file2.ext")

        make_relation(from_resource=from_1, to_resource=to_1, map_type="path")
        make_relation(from_resource=from_2, to_resource=to_2, map_type="path")
        make_relation(from_resource=from_1, to_resource=to_2, map_type="path")

        self.assertEqual(3, self.project1.codebaserelations.count())
        self.assertEqual(3, self.project1.relation_count)

        response = self.client.get(url)
        self.assertContains(response, "3 relations")

    def test_scanpipe_views_codebase_relation_diff_view(self):
        url = reverse("resource_diff", args=[self.project1.slug])
        data = {
            "from_path": "",
            "to_path": "",
        }
        response = self.client.get(url, data=data)
        expected = "The requested resource was not found on this server."
        self.assertContains(response, expected, status_code=404)

        resource_files = [
            self.data / "codebase" / "a.txt",
            self.data / "codebase" / "b.txt",
        ]
        copy_inputs(resource_files, self.project1.codebase_path)
        resource1 = CodebaseResource.objects.create(
            project=self.project1,
            path="a.txt",
            type=CodebaseResource.Type.FILE,
            is_text=True,
        )
        resource2 = CodebaseResource.objects.create(
            project=self.project1,
            path="b.txt",
            type=CodebaseResource.Type.FILE,
            is_text=True,
        )
        data = {
            "from_path": resource1.path,
            "to_path": resource2.path,
        }
        response = self.client.get(url, data=data)
        self.assertContains(response, '<table class="diff"')

    def test_scanpipe_views_codebase_resource_views(self):
        resource1 = make_resource_file(self.project1, "file1.ext")
        resource2 = make_resource_file(self.project1, "file2.ext")
        package1 = DiscoveredPackage.create_from_data(self.project1, package_data1)
        package1.add_resources([resource1, resource2])

        url = reverse("project_resources", args=[self.project1.slug])
        with self.assertNumQueries(9):
            self.client.get(url)

        with self.assertNumQueries(8):
            self.client.get(resource1.get_absolute_url())

    def test_scanpipe_views_discovered_package_views(self):
        resource1 = make_resource_file(self.project1, "file1.ext")
        resource2 = make_resource_file(self.project1, "file2.ext")
        package1 = DiscoveredPackage.create_from_data(self.project1, package_data1)
        package1.add_resources([resource1, resource2])
        package2 = DiscoveredPackage.create_from_data(self.project1, package_data2)
        package2.add_resources([resource1, resource2])

        url = reverse("project_packages", args=[self.project1.slug])
        with self.assertNumQueries(5):
            self.client.get(url)

        with self.assertNumQueries(6):
            self.client.get(package1.get_absolute_url())

    def test_scanpipe_views_discovered_package_details_view_tabset(self):
        package1 = DiscoveredPackage.create_from_data(self.project1, package_data1)
        response = self.client.get(package1.get_absolute_url())
        self.assertContains(response, 'data-target="tab-essentials"')
        self.assertContains(response, 'id="tab-essentials"')
        self.assertContains(response, 'data-target="tab-others"')
        self.assertContains(response, 'id="tab-others"')
        self.assertContains(response, 'data-target="tab-terms"')
        self.assertContains(response, 'id="tab-terms"')
        self.assertNotContains(response, 'data-target="tab-resources"')
        self.assertNotContains(response, 'id="tab-resources"')
        self.assertNotContains(response, 'data-target="tab-dependencies"')
        self.assertNotContains(response, 'id="tab-dependencies"')
        self.assertNotContains(response, 'data-target="tab-vulnerabilities"')
        self.assertNotContains(response, 'id="tab-vulnerabilities"')
        self.assertNotContains(response, 'data-target="tab-extra_data"')
        self.assertNotContains(response, 'id="tab-extra_data"')

        package1.add_resources([make_resource_file(self.project1, "file1.ext")])
        package1.update(
            affected_by_vulnerabilities=[{"vulnerability_id": "VCID-cah8-awtr-aaad"}],
            extra_data={"extra": "data"},
        )
        dependency_data = dependency_data1.copy()
        dependency_data["datafile_path"] = ""
        update_or_create_dependency(self.project1, dependency_data)
        response = self.client.get(package1.get_absolute_url())
        self.assertContains(response, 'data-target="tab-resources"')
        self.assertContains(response, 'id="tab-resources"')
        self.assertContains(response, 'data-target="tab-dependencies"')
        self.assertContains(response, 'id="tab-dependencies"')
        self.assertContains(response, 'data-target="tab-vulnerabilities"')
        self.assertContains(response, 'id="tab-vulnerabilities"')
        self.assertContains(response, 'data-target="tab-extra_data"')
        self.assertContains(response, 'id="tab-extra_data"')

    def test_scanpipe_views_discovered_package_details_view_tab_vulnerabilities(self):
        package1 = DiscoveredPackage.create_from_data(self.project1, package_data1)
        package1.update(
            affected_by_vulnerabilities=[{"vulnerability_id": "VCID-cah8-awtr-aaad"}]
        )
        response = self.client.get(package1.get_absolute_url())
        self.assertContains(response, "tab-vulnerabilities")
        self.assertContains(response, '<section id="tab-vulnerabilities"')
        self.assertContains(response, "VCID-cah8-awtr-aaad")

    @mock.patch("scanpipe.pipes.purldb.is_configured")
    def test_scanpipe_views_discovered_package_purldb_tab_view(self, mock_configured):
        package1 = DiscoveredPackage.create_from_data(self.project1, package_data1)
        package_url = package1.get_absolute_url()

        mock_configured.return_value = False
        response = self.client.get(package_url)
        self.assertNotContains(response, "tab-purldb")
        self.assertNotContains(response, '<section id="tab-purldb"')

        mock_configured.return_value = True
        response = self.client.get(package_url)
        self.assertContains(response, "tab-purldb")
        self.assertContains(response, '<section id="tab-purldb"')

        with mock.patch("scanpipe.pipes.purldb.get_package_by_purl") as get_package:
            get_package.return_value = None
            purldb_tab_url = f"{package_url}purldb_tab/"
            response = self.client.get(purldb_tab_url)
            msg = "No entries found in the PurlDB for this package"
            self.assertContains(response, msg)

            get_package.return_value = {
                "uuid": "9261605f-e2fb-4db9-94ab-0d82d3273cdf",
                "filename": "abab-2.0.3.tgz",
                "type": "npm",
                "name": "abab",
                "version": "2.0.3",
                "primary_language": "JavaScript",
            }
            response = self.client.get(purldb_tab_url)
            self.assertContains(response, "abab-2.0.3.tgz")
            self.assertContains(response, "2.0.3")
            self.assertContains(response, "JavaScript")

    def test_scanpipe_views_discovered_dependency_views(self):
        DiscoveredPackage.create_from_data(self.project1, package_data1)
        make_resource_file(
            self.project1, "daglib-0.3.2.tar.gz-extract/daglib-0.3.2/PKG-INFO"
        )
        make_resource_file(self.project1, "data.tar.gz-extract/Gemfile.lock")
        dep1 = DiscoveredDependency.create_from_data(self.project1, dependency_data1)
        DiscoveredDependency.create_from_data(self.project1, dependency_data2)

        list_view_url = reverse("project_dependencies", args=[self.project1.slug])
        with self.assertNumQueries(10):
            self.client.get(list_view_url)

        details_url = dep1.get_absolute_url()
        with self.assertNumQueries(6):
            self.client.get(details_url)

    def test_scanpipe_views_codebase_relation_views(self):
        CodebaseRelation.objects.create(
            project=self.project1,
            from_resource=make_resource_file(self.project1, "r1"),
            to_resource=make_resource_file(self.project1, "r2"),
            map_type="java_to_class",
        )

        url = reverse("project_relations", args=[self.project1.slug])
        with self.assertNumQueries(8):
            self.client.get(url)

    def test_scanpipe_views_project_message_views(self):
        self.project1.add_message("warning")
        self.project1.add_message("error")
        url = reverse("project_messages", args=[self.project1.slug])
        with self.assertNumQueries(5):
            self.client.get(url)

    def test_scanpipe_views_license_list_view(self):
        url = reverse("license_list")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        expected = '<a href="/license/apache-2.0/">apache-2.0</a>'
        self.assertContains(response, expected)

    def test_scanpipe_views_license_details_view(self):
        license_url = reverse("license_detail", args=["apache-2.0"])
        response = self.client.get(license_url)
        self.assertEqual(response.status_code, 200)

        dummy_license_url = reverse("license_detail", args=["abcdefg"])
        response = self.client.get(dummy_license_url)
        self.assertEqual(response.status_code, 404)

        xss = "%3Cscript%3Ealert(document.cookie);%3C/script%3E/"
        with self.assertRaises(NoReverseMatch):
            reverse("license_detail", args=[xss])

        xss = "%3Cscript%3Ealert(document.cookie);%3C"
        xss_url = reverse("license_detail", args=[xss])
        response = self.client.get(xss_url)
        self.assertEqual(response.status_code, 404)
