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
import uuid
from pathlib import Path
from unittest import mock

from django.apps import apps
from django.http import FileResponse
from django.http.response import Http404
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch

import openpyxl
import requests

from scanpipe.forms import BaseProjectActionForm
from scanpipe.models import CodebaseRelation
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredLicense
from scanpipe.models import DiscoveredPackage
from scanpipe.models import Project
from scanpipe.pipes import make_relation
from scanpipe.pipes import update_or_create_dependency
from scanpipe.pipes.input import copy_input
from scanpipe.pipes.input import copy_inputs
from scanpipe.tests import dependency_data1
from scanpipe.tests import dependency_data2
from scanpipe.tests import make_dependency
from scanpipe.tests import make_package
from scanpipe.tests import make_project
from scanpipe.tests import make_resource_directory
from scanpipe.tests import make_resource_file
from scanpipe.tests import package_data1
from scanpipe.tests import package_data2
from scanpipe.views import CodebaseResourceDetailsView
from scanpipe.views import ProjectActionView
from scanpipe.views import ProjectCodebasePanelView
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
            '<input class="input is-smaller" type="search" '
            'placeholder="Search projects" name="search" value="query">'
        )
        self.assertContains(response, expected, html=True)

        expected = '<input type="hidden" name="status" value="failed">'
        self.assertContains(response, expected, html=True)

    def test_scanpipe_views_project_list_filter_by_status_distinct_results(self):
        url = reverse("project_list")
        pipeline1 = self.project1.add_pipeline(pipeline_name="scan_codebase")
        pipeline1.set_task_stopped()
        pipeline2 = self.project1.add_pipeline(pipeline_name="scan_codebase")
        pipeline2.set_task_stopped()

        data = {"status": "failed"}
        response = self.client.get(url, data=data)
        self.assertEqual(1, len(response.context["object_list"]))

    @mock.patch("scanpipe.views.ProjectListView.get_paginate_by")
    def test_scanpipe_views_project_list_filters_exclude_page(self, mock_paginate_by):
        url = reverse("project_list")
        # Create another project to enable pagination
        make_project()
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

    def test_scanpipe_views_project_list_modal_forms_include_url_query(self):
        url = reverse("project_list")
        response = self.client.get(url)

        expected_html_names = [
            "url_query",
            "download-url_query",
            "report-url_query",
            "archive-url_query",
            "reset-url_query",
        ]
        for html_name in expected_html_names:
            expected = f'<input type="hidden" name="{html_name}" value="">'
            self.assertContains(response, expected, html=True)

        url_query = "name=search_value"
        response = self.client.get(url + "?" + url_query)
        for html_name in expected_html_names:
            expected = f'<input type="hidden" name="{html_name}" value="{url_query}">'
            self.assertContains(response, expected, html=True)

    @mock.patch("scanpipe.views.ProjectListView.get_paginate_by")
    def test_scanpipe_views_project_list_modal_forms_include_show_on_all_checked(
        self, mock_paginate_by
    ):
        url = reverse("project_list")
        # Create another project to enable pagination
        make_project()
        mock_paginate_by.return_value = 1
        response = self.client.get(url)
        expected = '<div class="show-on-all-checked">'
        self.assertContains(response, expected)

        mock_paginate_by.return_value = 2
        response = self.client.get(url)
        self.assertNotContains(response, expected)

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

    def test_scanpipe_views_project_action_report_view(self):
        url = reverse("project_action")
        data = {
            "action": "report",
            "selected_ids": f"{self.project1.uuid}",
            "report-model_name": "todo",
        }
        response = self.client.post(url, data=data, follow=True)
        self.assertTrue(response.filename.startswith("scancodeio-report-"))
        self.assertTrue(response.filename.endswith(".xlsx"))

        output_file = io.BytesIO(b"".join(response.streaming_content))
        workbook = openpyxl.load_workbook(output_file, read_only=True, data_only=True)
        self.assertEqual(["TODOS"], workbook.sheetnames)

    def test_scanpipe_views_project_action_reset_view(self):
        url = reverse("project_action")
        data = {
            "action": "reset",
            "selected_ids": f"{self.project1.uuid}",
            "reset-restore_pipelines": "on",
        }
        self.project1.add_pipeline(pipeline_name="scan_codebase")
        response = self.client.post(url, data=data, follow=True)
        expected = "1 projects have been reset."
        self.assertContains(response, expected)

        self.assertTrue(Project.objects.filter(name=self.project1.name).exists())
        self.assertEqual(1, self.project1.runs.count())

    def test_scanpipe_views_project_action_view_get_project_queryset(self):
        queryset = ProjectActionView.get_project_queryset(
            selected_project_ids=[self.project1.uuid],
            action_form=None,
        )
        self.assertQuerySetEqual(queryset, [self.project1])

        # No project selection, no select_across
        form_data = {"select_across": 0}
        action_form = BaseProjectActionForm(data=form_data)
        action_form.full_clean()
        with self.assertRaises(Http404):
            ProjectActionView.get_project_queryset(
                selected_project_ids=None,
                action_form=action_form,
            )

        # select_across, no active filters
        form_data = {"select_across": 1}
        action_form = BaseProjectActionForm(data=form_data)
        action_form.full_clean()
        self.assertQuerySetEqual(queryset, [self.project1])

        # select_across, active filters
        make_project()
        self.assertEqual(2, Project.objects.count())
        form_data = {"select_across": 1, "url_query": f"name={self.project1.name}"}
        action_form = BaseProjectActionForm(data=form_data)
        action_form.full_clean()
        self.assertQuerySetEqual(queryset, [self.project1])

    def test_scanpipe_views_project_details_is_archived(self):
        url = self.project1.get_absolute_url()
        expected1 = "WARNING: This project is archived and read-only."

        response = self.client.get(url)
        self.assertNotContains(response, expected1)

        self.project1.archive()
        response = self.client.get(url)
        self.assertContains(response, expected1)

    @mock.patch("scanpipe.pipes.fetch.is_safe_url", return_value=True)
    @mock.patch("requests.sessions.Session.head")
    def test_scanpipe_views_project_details_add_inputs(
        self, mock_head, mock_is_safe_url
    ):
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
            'inline; filename="notice.NOTICE"',
            response.headers["Content-Disposition"],
        )

        with override_settings(SCANPIPE={"INLINE_DOWNLOAD_MAX_SIZE": 0}):
            response = self.client.get(url)
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
            'inline; filename="notice.NOTICE"',
            response.headers["Content-Disposition"],
        )

        with override_settings(SCANPIPE={"INLINE_DOWNLOAD_MAX_SIZE": 0}):
            response = self.client.get(url)
        self.assertEqual(
            'attachment; filename="notice.NOTICE"',
            response.headers["Content-Disposition"],
        )

    def test_scanpipe_views_project_results_json_view(self):
        make_package(self.project1, package_url="pkg:generic/name@1.0")

        url = reverse("project_results", args=[self.project1.slug, "json"])
        response = self.client.get(url)
        results = json.loads(response.getvalue())
        expected = ["dependencies", "files", "headers", "packages", "relations"]
        self.assertEqual(expected, sorted(results.keys()))
        self.assertEqual(1, len(results["packages"]))

        response = self.client.get(url, data={"sections": "packages"})
        results = json.loads(response.getvalue())
        self.assertEqual(["headers", "packages"], sorted(results.keys()))

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
        self.project1.refresh_from_db()
        self.assertEqual(["label1", "label2"], self.project1.labels)

        # Adding labels merges with, rather than replaces, the existing ones.
        data["labels"] = "label3"
        response = self.client.post(url, data, follow=True)
        self.assertContains(response, "Label(s) added.")
        self.project1.refresh_from_db()
        self.assertEqual(["label1", "label2", "label3"], self.project1.labels)

    def test_scanpipe_views_project_delete_label(self):
        self.project1.labels = ["label1"]
        self.project1.save()
        url = reverse("project_delete_label", args=[self.project1.slug, "label1"])
        response = self.client.get(url)
        self.assertEqual(405, response.status_code)

        response = self.client.post(url)
        self.assertEqual(200, response.status_code)
        self.assertEqual({}, response.json())
        self.project1.refresh_from_db()
        self.assertEqual([], self.project1.labels)

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

        with self.assertNumQueries(6):
            response = self.client.get(url)

        self.assertNotContains(response, 'id="package-charts"')
        self.assertNotContains(response, 'id="dependency-charts"')
        self.assertNotContains(response, 'id="resource-charts-charts"')

        make_resource_file(self.project1, path="", programming_language="Python")

        with self.assertNumQueries(6):
            response = self.client.get(url)
        self.assertContains(response, '{"Python": 1}')

    def test_scanpipe_views_project_details_charts_compliance_alert(self):
        url = reverse("project_charts", args=[self.project1.slug])
        resource = make_resource_file(self.project1)
        expected_resource_id = 'id="compliance_alert_chart"'
        expected_package_id = 'id="package_compliance_alert_chart"'

        response = self.client.get(url)
        self.assertNotContains(response, expected_resource_id)
        self.assertNotContains(response, expected_package_id)

        # Do not trigger the save() logic.
        CodebaseResource.objects.filter(id=resource.id).update(
            compliance_alert=CodebaseResource.Compliance.ERROR
        )
        make_package(
            self.project1,
            package_url="pkg:generic/name@1.0",
            compliance_alert=DiscoveredPackage.Compliance.WARNING,
        )

        response = self.client.get(url)
        self.assertContains(response, expected_resource_id)
        self.assertContains(response, expected_package_id)
        self.assertContains(response, '{"error": 1}')
        self.assertContains(response, '{"warning": 1}')

    def test_scanpipe_views_project_details_charts_copyrights(self):
        url = reverse("project_charts", args=[self.project1.slug])

        make_resource_file(self.project1)
        copyrights = [
            {
                "copyright": "Copyright (c) nexB Inc. and others",
                "start_line": 2,
                "end_line": 2,
            }
        ]
        make_resource_file(self.project1, copyrights=copyrights)

        response = self.client.get(url)
        expected = (
            '<script id="file_copyrights" type="application/json">'
            '{"Copyright (c) nexB Inc. and others": 1, "(No value detected)": 1}'
            "</script>"
        )
        self.assertContains(response, expected)

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

    def test_scanpipe_views_project_details_scan_summary_language_url_encoding(self):
        summary_file = self.project1.get_output_file_path("summary", "json")
        scan_summary_json = {
            "primary_language": [{"value": "C#", "count": 1}],
            "other_languages": [{"value": "C#", "count": 1}],
        }
        summary_file.write_text(json.dumps(scan_summary_json))
        url = self.project1.get_absolute_url()
        response = self.client.get(url)
        self.assertContains(response, "?programming_language=C%23")
        self.assertNotContains(response, "?programming_language=C#")

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

    @mock.patch.object(
        Project, "license_policies_enabled", new_callable=mock.PropertyMock
    )
    def test_scanpipe_views_project_details_compliance_panel_availability(
        self, mock_license_policies_enabled
    ):
        url = self.project1.get_absolute_url()
        make_package(
            self.project1,
            package_url="pkg:generic/name@1.0",
            compliance_alert=DiscoveredPackage.Compliance.ERROR,
        )

        expected_url = reverse("project_compliance_panel", args=[self.project1.slug])
        mock_license_policies_enabled.return_value = False
        response = self.client.get(url)
        self.assertNotContains(response, expected_url)

        mock_license_policies_enabled.return_value = True
        response = self.client.get(url)
        self.assertContains(response, expected_url)

    def test_scanpipe_views_project_create_view(self):
        url = reverse("project_add")
        response = self.client.get(url)
        self.assertContains(response, "scan_codebase")
        self.assertNotContains(response, "find_vulnerabilities")

    def test_scanpipe_views_project_codebase_view(self):
        url = reverse("project_codebase", args=[self.project1.slug])

        (self.project1.codebase_path / "dir1").mkdir()
        (self.project1.codebase_path / "dir1/dir2").mkdir()
        (self.project1.codebase_path / "file+.txt").touch()

        response = self.client.get(url)
        resource_tree_url = reverse(
            "project_resource_tree", args=[self.project1.slug, "dir1"]
        )
        self.assertContains(response, resource_tree_url)
        resource_tree_url = reverse(
            "project_resource_tree", args=[self.project1.slug, "file+.txt"]
        )
        self.assertContains(response, resource_tree_url)

    def test_scanpipe_views_project_codebase_view_ordering(self):
        url = reverse("project_codebase", args=[self.project1.slug])
        (self.project1.codebase_path / "z.txt").touch()
        (self.project1.codebase_path / "a.txt").touch()
        (self.project1.codebase_path / "z").mkdir()
        (self.project1.codebase_path / "a").mkdir()
        (self.project1.codebase_path / "Zdir").mkdir()
        (self.project1.codebase_path / "Dir").mkdir()

        response = self.client.get(url)
        codebase_tree = response.context_data["codebase_root_tree"]
        expected = ["Dir", "Zdir", "a", "z", "a.txt", "z.txt"]
        self.assertEqual(expected, [path.get("name") for path in codebase_tree])

    def test_scanpipe_views_project_codebase_view_get_root_tree(self):
        get_root_tree = ProjectCodebasePanelView.get_root_tree

        (self.project1.codebase_path / "dir1").mkdir()
        (self.project1.codebase_path / "dir1/dir2").mkdir()
        (self.project1.codebase_path / "file.txt").touch()

        with mock.patch.object(scanpipe_app, "workspace_path", ""):
            self.assertEqual("", scanpipe_app.workspace_path)
            with self.assertRaises(ValueError):
                get_root_tree(self.project1)

        codebase_tree = get_root_tree(self.project1)
        expected = [
            {"name": "dir1", "is_dir": True},
            {"name": "file.txt", "is_dir": False},
        ]
        self.assertEqual(expected, codebase_tree)

        shutil.rmtree(self.project1.work_directory, ignore_errors=True)
        self.assertFalse(self.project1.codebase_path.exists())
        with self.assertRaises(Exception):
            get_root_tree(self.project1)

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
        data = {"reset-restore_pipelines": "on"}
        response = self.client.post(url, data=data, follow=True)
        expected = "has been reset."
        self.assertContains(response, expected)
        self.assertTrue(Project.objects.filter(name=self.project1.name).exists())
        self.assertEqual(1, self.project1.runs.count())

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
        self.project1.labels = ["label1", "label2"]
        self.project1.save()
        Project.objects.create(name="Analysis2", labels=["label3", "label4"])

        url = reverse("project_list")
        with self.assertNumQueries(6):
            self.client.get(url)

        with self.assertNumQueries(9):
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

    def test_scanpipe_views_delete_webhook_view(self):
        webhook = self.project1.add_webhook_subscription(target_url="https://localhost")
        url = reverse("project_delete_webhook", args=[self.project1.slug, webhook.uuid])

        response = self.client.post(url, follow=True)
        expected = "Webhook deleted."
        self.assertContains(response, expected)
        self.assertEqual(0, self.project1.webhooksubscriptions.count())

        response = self.client.get(url)
        self.assertEqual(405, response.status_code)

    def test_scanpipe_views_run_status_view(self):
        run = self.project1.add_pipeline("analyze_docker_image")
        url = reverse("run_status", args=[run.uuid])

        response = self.client.get(url)
        expected = '<span class="tag is-hoverable">Not started</span>'
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
        expected = '<span class="tag is-danger is-hoverable">Failure</span>'
        self.assertContains(response, expected)

        run.set_task_ended(exitcode=0)
        response = self.client.get(url)
        expected = '<span class="tag is-success is-hoverable">Success</span>'
        self.assertContains(response, expected)

        run.set_task_staled()
        response = self.client.get(url)
        expected = '<span class="tag is-dark is-hoverable">Stale</span>'
        self.assertContains(response, expected)

        run.set_task_stopped()
        response = self.client.get(url)
        expected = '<span class="tag is-danger is-hoverable">Stopped</span>'
        self.assertContains(response, expected)

    def test_scanpipe_views_run_detail_view_results_url(self):
        run = self.project1.add_pipeline("find_vulnerabilities")
        self.assertTrue(run.results_url)

        url = reverse("run_detail", args=[run.uuid])
        run.set_task_ended(exitcode=0)
        response = self.client.get(url)
        self.assertContains(response, "View pipeline results")
        self.assertContains(response, run.results_url)

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

    @mock.patch.object(
        Project, "license_policies_enabled", new_callable=mock.PropertyMock
    )
    def test_scanpipe_views_project_compliance_panel_view(
        self, mock_license_policies_enabled
    ):
        url = reverse("project_compliance_panel", args=[self.project1.slug])
        make_package(
            self.project1,
            package_url="pkg:generic/name@1.0",
            compliance_alert=DiscoveredPackage.Compliance.ERROR,
        )

        self.project1.extra_data = {"license_clarity_compliance_alert": "warning"}
        self.project1.save(update_fields=["extra_data"])

        mock_license_policies_enabled.return_value = False
        response = self.client.get(url)
        self.assertEqual(404, response.status_code)

        mock_license_policies_enabled.return_value = True
        response = self.client.get(url)
        self.assertContains(response, "Compliance alerts")
        self.assertContains(response, "1 Error")
        self.assertContains(response, "License clarity")
        self.assertContains(response, "Warning")
        expected = f"/project/{self.project1.slug}/packages/?compliance_alert=error"
        self.assertContains(response, expected)

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

    def test_scanpipe_views_codebase_resource_list_programming_language_url_encoding(
        self,
    ):
        make_resource_file(
            self.project1, path="csharp_file.cs", programming_language="C#"
        )
        url = reverse("project_resources", args=[self.project1.slug])
        response = self.client.get(url)
        self.assertContains(response, "?programming_language=C%23")
        self.assertNotContains(response, "?programming_language=C#")

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
        self.project1.update_counts()
        self.project1.refresh_from_db()
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
        resource1 = make_resource_file(self.project1, path="a.txt")
        resource2 = make_resource_file(self.project1, path="b.txt")
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
        with self.assertNumQueries(8):
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
            affected_by_vulnerabilities=[{"advisory_uid": "ID-cah8-awtr-aaad"}],
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
        v1 = {"advisory_uid": "ID-cah8-awtr-aaad", "advisory_id": "ID-cah8-awtr-aaad"}
        package1.update(affected_by_vulnerabilities=[v1])
        response = self.client.get(package1.get_absolute_url())
        self.assertContains(response, "tab-vulnerabilities")
        self.assertContains(response, '<section id="tab-vulnerabilities"')
        self.assertContains(response, "ID-cah8-awtr-aaad")

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

        with mock.patch("scanpipe.pipes.purldb.get_packages_for_purl") as get_packages:
            get_packages.return_value = None
            purldb_tab_url = f"{package_url}purldb_tab/"
            response = self.client.get(purldb_tab_url)
            msg = "No entries found in the PurlDB for this package"
            self.assertContains(response, msg)

            get_packages.return_value = [
                {
                    "uuid": "9261605f-e2fb-4db9-94ab-0d82d3273cdf",
                    "filename": "abab-2.0.3.tgz",
                    "type": "npm",
                    "name": "abab",
                    "version": "2.0.3",
                    "primary_language": "JavaScript",
                }
            ]
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

    def test_scanpipe_views_vulnerability_list_view(self):
        self.assertEqual(0, self.project1.vulnerability_count)
        url = reverse("project_vulnerabilities", args=[self.project1.slug])
        with self.assertNumQueries(5):
            response = self.client.get(url)
        self.assertContains(response, "No Vulnerabilities found.")

        v1 = {
            "advisory_uid": "ID-1",
            "advisory_id": "ID-1",
        }
        v2 = {
            "advisory_uid": "ID-2",
            "advisory_id": "ID-2",
            "resource_url": "https://vcio/advisories/ID-2",
        }
        project = make_project()
        make_package(project, "pkg:type/a", affected_by_vulnerabilities=[v1])
        make_dependency(project, affected_by_vulnerabilities=[v2])

        self.assertEqual(2, project.vulnerability_count)
        url = reverse("project_vulnerabilities", args=[project.slug])
        with self.assertNumQueries(5):
            response = self.client.get(url)

        expected = "<td>ID-1</td>"
        self.assertContains(response, expected, html=True)
        expected = '<a href="https://vcio/advisories/ID-2" target="_blank">'
        self.assertContains(response, expected)
        self.assertContains(response, "pkg:type/a")

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

    def test_scanpipe_views_license_detection_details_view_match_texts(self):
        matches = [
            {
                "score": 100.0,
                "start_line": 1,
                "end_line": 1,
                "matched_length": 4,
                "match_coverage": 100.0,
                "matcher": "1-hash",
                "license_expression": "mit",
                "rule_identifier": "mit_1.RULE",
                "rule_text": "license: MIT",
                "matched_text": "License: MIT",
                "matched_text_diagnostics": "License MIT",
                "from_file": "LICENSE",
            }
        ]
        license_detection = DiscoveredLicense.objects.create(
            project=self.project1,
            license_expression="mit",
            license_expression_spdx="MIT",
            identifier="mit-123",
            matches=matches,
            file_regions=[{"path": "LICENSE", "start_line": 1, "end_line": 1}],
        )

        url = reverse(
            "license_detail",
            args=[self.project1.slug, license_detection.identifier],
        )
        response = self.client.get(url)

        self.assertContains(response, "Diagnostic matched text")
        self.assertContains(response, "License MIT")
        self.assertContains(response, "Matched text")
        self.assertContains(response, "License: MIT")
        self.assertContains(response, "Rule text")
        self.assertContains(response, "license: MIT")

    def test_scanpipe_views_license_detection_details_view_match_texts_null_from_file(self):
        matches = [
            {
                "score": 100.0,
                "start_line": 1,
                "end_line": 1,
                "matched_length": 3,
                "match_coverage": 100.0,
                "matcher": "1-spdx-id",
                "license_expression": "isc",
                "rule_identifier": "isc_9931cb7ad33c2eb18f322c94660b670a84186baa.RULE",
                "matched_text": "ISC",
                "from_file": None,
            }
        ]
        license_detection = DiscoveredLicense.objects.create(
            project=self.project1,
            license_expression="isc",
            license_expression_spdx="ISC",
            identifier="isc-null-from-file",
            matches=matches,
            detection_count=2,
            file_regions=[
                {"path": "a/package.json", "start_line": 1, "end_line": 1},
                {"path": "b/package-lock.json", "start_line": 1, "end_line": 1},
            ],
        )

        url = reverse(
            "license_detail",
            args=[self.project1.slug, license_detection.identifier],
        )
        response = self.client.get(url)

        self.assertContains(response, "Matches by file")
        self.assertContains(response, "a/package.json")
        self.assertContains(response, "b/package-lock.json")
        self.assertContains(response, "ISC")
        self.assertNotContains(response, "No match text is available for this file region.")
        self.assertNotContains(response, "No origin resource path")

    def test_scanpipe_views_license_detection_details_view_match_texts_mixed_from_file(self):
        matches = [
            {
                "score": 100.0,
                "start_line": 1,
                "end_line": 1,
                "matched_length": 4,
                "match_coverage": 100.0,
                "matcher": "1-hash",
                "license_expression": "mit",
                "rule_identifier": "mit_1.RULE",
                "matched_text": "License: MIT",
                "from_file": "LICENSE",
            },
            {
                "score": 100.0,
                "start_line": 5,
                "end_line": 5,
                "matched_length": 3,
                "match_coverage": 100.0,
                "matcher": "1-spdx-id",
                "license_expression": "apache-2.0",
                "rule_identifier": "apache2_99.RULE",
                "matched_text": "Apache-2.0",
                "from_file": None,
            },
        ]
        license_detection = DiscoveredLicense.objects.create(
            project=self.project1,
            license_expression="mit AND apache-2.0",
            license_expression_spdx="MIT AND Apache-2.0",
            identifier="mixed-from-file",
            matches=matches,
            detection_count=3,
            file_regions=[
                {"path": "LICENSE", "start_line": 1, "end_line": 1},
                {"path": "setup.py", "start_line": 5, "end_line": 5},
            ],
        )

        url = reverse(
            "license_detail",
            args=[self.project1.slug, license_detection.identifier],
        )
        response = self.client.get(url)

        self.assertContains(response, "Matches by file")
        self.assertContains(response, "LICENSE")
        self.assertContains(response, "setup.py")
        self.assertContains(response, "License: MIT")
        self.assertContains(response, "Apache-2.0")
        self.assertNotContains(response, "No match text is available for this file region.")

    def test_scanpipe_views_license_detection_details_view_match_texts_no_file_regions(self):
        matches = [
            {
                "score": 100.0,
                "start_line": 1,
                "end_line": 1,
                "matched_length": 3,
                "match_coverage": 100.0,
                "matcher": "1-spdx-id",
                "license_expression": "isc",
                "rule_identifier": "isc_99.RULE",
                "matched_text": "ISC",
                "from_file": None,
            }
        ]
        license_detection = DiscoveredLicense.objects.create(
            project=self.project1,
            license_expression="isc",
            license_expression_spdx="ISC",
            identifier="isc-no-regions",
            matches=matches,
            file_regions=[],
        )

        url = reverse(
            "license_detail",
            args=[self.project1.slug, license_detection.identifier],
        )
        response = self.client.get(url)

        self.assertContains(response, "Matches by file")
        self.assertContains(response, "ISC")
        self.assertContains(response, "No origin resource path")
        self.assertNotContains(response, "No match text is available for this file region.")

    def test_scanpipe_views_resource_details_view_inlines_detection_match_texts(self):
        license_detections = [
            {
                "identifier": "mit-123",
                "license_expression": "mit",
                "license_expression_spdx": "MIT",
                "matches": [
                    {
                        "score": 100.0,
                        "start_line": 1,
                        "end_line": 1,
                        "matched_length": 4,
                        "match_coverage": 100.0,
                        "matcher": "1-hash",
                        "license_expression": "mit",
                        "rule_identifier": "mit_1.RULE",
                        "rule_text": "license: MIT",
                        "matched_text": "License: MIT",
                        "matched_text_diagnostics": "License MIT",
                    }
                ],
            }
        ]
        resource = make_resource_file(
            self.project1,
            "LICENSE",
            detected_license_expression="mit",
            license_detections=license_detections,
        )

        response = self.client.get(resource.get_absolute_url())

        self.assertContains(response, "Diagnostic matched text")
        self.assertContains(response, "License MIT")
        self.assertContains(response, "Matched text")
        self.assertContains(response, "License: MIT")
        self.assertContains(response, "Rule text")
        self.assertContains(response, "license: MIT")

    @mock.patch("scanpipe.models.DiscoveredPackage.get_absolute_url")
    def test_scanpipe_views_project_dependency_tree(self, mock_get_url):
        mock_get_url.return_value = "mocked-url"
        url = reverse("project_dependency_tree", args=[self.project1.slug])
        response = self.client.get(url)
        expected_tree = {"name": "Analysis", "children": []}
        self.assertEqual(expected_tree, response.context["dependency_tree"])

        project = Project.objects.create(name="project")
        a = make_package(project, "pkg:type/a", compliance_alert="error")
        b = make_package(project, "pkg:type/b")
        c = make_package(project, "pkg:type/c")
        make_package(project, "pkg:type/z")
        # Project -> A -> B -> C
        # Project -> Z
        make_dependency(project, for_package=a, resolved_to_package=b)
        make_dependency(project, for_package=b, resolved_to_package=c)
        url = reverse("project_dependency_tree", args=[project.slug])
        response = self.client.get(url)
        expected_tree = {
            "name": "project",
            "children": [
                {
                    "name": "pkg:type/a",
                    "url": "mocked-url",
                    "compliance_alert": "error",
                    "has_compliance_issue": True,
                    "is_vulnerable": False,
                    "children": [
                        {
                            "name": "pkg:type/b",
                            "url": "mocked-url",
                            "compliance_alert": "",
                            "has_compliance_issue": False,
                            "is_vulnerable": False,
                            "children": [
                                {
                                    "name": "pkg:type/c",
                                    "url": "mocked-url",
                                    "compliance_alert": "",
                                    "has_compliance_issue": False,
                                    "is_vulnerable": False,
                                    "children": [],
                                }
                            ],
                        }
                    ],
                },
                {
                    "name": "pkg:type/z",
                    "url": "mocked-url",
                    "compliance_alert": "",
                    "has_compliance_issue": False,
                    "is_vulnerable": False,
                    "children": [],
                },
            ],
        }
        self.assertEqual(expected_tree, response.context["dependency_tree"])

        # Adding a circular reference such as: Project -> A -> B -> C -> B -> C -> ...
        make_dependency(project, for_package=c, resolved_to_package=b)
        response = self.client.get(url)
        self.assertTrue(response.context["recursion_error"])
        self.assertContains(response, "The dependency tree cannot be rendered")

    def test_scanpipe_policies_broken_policies_project_details(self):
        broken_policies = self.data / "policies" / "broken_policies.yml"
        project1 = make_project()
        shutil.copyfile(broken_policies, project1.input_path / "policies.yml")

        url = project1.get_absolute_url()
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        self.assertContains(response, "Policies file format error")

    def test_scanpipe_views_codebase_resource_details_get_matched_snippet_annotations(
        self,
    ):
        resource1 = make_resource_file(self.project1, "inherits.js")
        extra_data_loc = self.data / "matchcode" / "fingerprinting" / "extra_data.json"
        with open(extra_data_loc) as f:
            extra_data = json.load(f)
        resource1.extra_data.update(extra_data)
        resource1.save()
        resource1.refresh_from_db()
        results = CodebaseResourceDetailsView.get_matched_snippet_annotations(resource1)
        expected_results = [
            {
                "start_line": 1,
                "end_line": 6,
                "text": (
                    "package: pkg:github/isaacs/inherits@v2.0.3\n"
                    "resource: inherits-2.0.3/inherits.js\n"
                    "similarity: 1.0\n"
                ),
            }
        ]
        self.assertEqual(expected_results, results)

    def test_project_packages_export_json(self):
        make_package(self.project1, package_url="pkg:type/a")

        url = reverse("project_packages", args=[self.project1.slug])
        response = self.client.get(url + "?export_json=True")

        self.assertIsInstance(response, FileResponse)
        self.assertEqual(response.get("Content-Type"), "application/json")
        self.assertTrue(response.get("Content-Disposition").startswith("inline"))

        with override_settings(SCANPIPE={"INLINE_DOWNLOAD_MAX_SIZE": 0}):
            response = self.client.get(url + "?export_json=True")
        self.assertTrue(response.get("Content-Disposition").startswith("attachment"))

        file_content = b"".join(response.streaming_content).decode("utf-8")
        json_data = json.loads(file_content)

        expected_fields = [
            "purl",
            "type",
            "namespace",
            "name",
            "version",
            "qualifiers",
            "subpath",
            "tag",
            "primary_language",
            "description",
            "notes",
            "release_date",
            "parties",
            "keywords",
            "homepage_url",
            "download_url",
            "bug_tracking_url",
            "code_view_url",
            "vcs_url",
            "repository_homepage_url",
            "repository_download_url",
            "api_data_url",
            "size",
            "md5",
            "sha1",
            "sha256",
            "sha512",
            "copyright",
            "holder",
            "declared_license_expression",
            "declared_license_expression_spdx",
            "other_license_expression",
            "other_license_expression_spdx",
            "extracted_license_statement",
            "compliance_alert",
            "notice_text",
            "source_packages",
            "package_uid",
            "is_private",
            "is_virtual",
            "datasource_ids",
            "datafile_paths",
            "file_references",
            "missing_resources",
            "modified_resources",
        ]

        for field in expected_fields:
            self.assertIn(field, json_data[0])

    def test_project_dependencies_export_json(self):
        make_resource_file(self.project1, "file.ext")
        make_dependency(self.project1)

        url = reverse("project_dependencies", args=[self.project1.slug])
        response = self.client.get(url + "?export_json=True")

        self.assertIsInstance(response, FileResponse)
        self.assertEqual(response.get("Content-Type"), "application/json")
        self.assertTrue(response.get("Content-Disposition").startswith("inline"))

        file_content = b"".join(response.streaming_content).decode("utf-8")
        json_data = json.loads(file_content)

        expected_fields = [
            "purl",
            "extracted_requirement",
            "scope",
            "is_runtime",
            "is_optional",
            "is_pinned",
            "is_direct",
            "dependency_uid",
            "for_package_uid",
            "resolved_to_package_uid",
            "datafile_path",
            "datasource_id",
            "package_type",
        ]

        for field in expected_fields:
            self.assertIn(field, json_data[0])

    def test_project_relations_export_json(self):
        make_relation(
            from_resource=make_resource_file(self.project1, "file1.ext"),
            to_resource=make_resource_file(self.project1, "file2.ext"),
            map_type="path",
        )

        url = reverse("project_relations", args=[self.project1.slug])
        response = self.client.get(url + "?export_json=True")

        self.assertIsInstance(response, FileResponse)
        self.assertEqual(response.get("Content-Type"), "application/json")
        self.assertTrue(response.get("Content-Disposition").startswith("inline"))

        file_content = b"".join(response.streaming_content).decode("utf-8")
        json_data = json.loads(file_content)

        expected_fields = [
            "to_resource",
            "status",
            "map_type",
            "score",
            "from_resource",
        ]

        for field in expected_fields:
            self.assertIn(field, json_data[0])

    def test_project_messages_export_json(self):
        self.project1.add_message("warning")

        url = reverse("project_messages", args=[self.project1.slug])
        response = self.client.get(url + "?export_json=True")

        self.assertIsInstance(response, FileResponse)
        self.assertEqual(response.get("Content-Type"), "application/json")
        self.assertTrue(response.get("Content-Disposition").startswith("inline"))

        file_content = b"".join(response.streaming_content).decode("utf-8")
        json_data = json.loads(file_content)

        expected_fields = [
            "uuid",
            "severity",
            "description",
            "model",
            "details",
            "traceback",
            "created_date",
        ]

        for field in expected_fields:
            self.assertIn(field, json_data[0])

    def test_project_codebase_resources_export_json(self):
        make_resource_file(self.project1, "file.ext")

        url = reverse("project_resources", args=[self.project1.slug])
        response = self.client.get(url + "?export_json=True")

        self.assertIsInstance(response, FileResponse)
        self.assertEqual(response.get("Content-Type"), "application/json")
        self.assertTrue(response.get("Content-Disposition").startswith("inline"))

        file_content = b"".join(response.streaming_content).decode("utf-8")
        json_data = json.loads(file_content)

        expected_fields = [
            "path",
            "type",
            "name",
            "status",
            "for_packages",
            "tag",
            "extension",
            "size",
            "mime_type",
            "file_type",
            "programming_language",
            "detected_license_expression",
            "detected_license_expression_spdx",
            "license_detections",
            "license_clues",
            "percentage_of_license_text",
            "compliance_alert",
            "copyrights",
            "holders",
            "authors",
            "package_data",
            "emails",
            "urls",
            "md5",
            "sha1",
            "sha256",
            "sha512",
            "sha1_git",
            "is_binary",
            "is_text",
            "is_archive",
            "is_media",
            "is_legal",
            "is_manifest",
            "is_readme",
            "is_top_level",
            "is_key_file",
            "extra_data",
        ]

        for field in expected_fields:
            self.assertIn(field, json_data[0])

    def test_scanpipe_views_resource_tree_root_path(self):
        make_resource_file(self.project1, path="child1.txt")
        make_resource_file(self.project1, path="dir1")

        url = reverse("project_resource_tree", kwargs={"slug": self.project1.slug})
        response = self.client.get(url)
        children = response.context["children"]
        child1 = children[0]
        dir1 = children[1]

        self.assertEqual(child1.path, "child1.txt")
        self.assertEqual(dir1.path, "dir1")

    def test_scanpipe_views_resource_tree_children_path(self):
        make_resource_file(self.project1, path="parent/child1.txt")
        make_resource_file(self.project1, path="parent/dir1")
        make_resource_file(self.project1, path="parent/dir1/child2.txt")

        url = reverse(
            "project_resource_tree",
            kwargs={"slug": self.project1.slug, "path": "parent"},
        )
        response = self.client.get(url + "?tree_panel=true")
        children = response.context["children"]

        child1 = children[0]
        dir1 = children[1]

        self.assertEqual(child1.path, "parent/child1.txt")
        self.assertEqual(dir1.path, "parent/dir1")

        self.assertFalse(child1.has_children)
        self.assertTrue(dir1.has_children)

    def test_scanpipe_views_project_resource_tree_right_pane_view_with_path_directory(
        self,
    ):
        resource1 = make_resource_directory(self.project1, path="parent+special&chars")
        make_resource_file(self.project1, path="parent+special&chars/child1.txt")
        make_resource_file(self.project1, path="parent+special&chars/child2.py")

        url = reverse(
            "project_resource_tree_right_pane",
            kwargs={"slug": self.project1.slug, "path": resource1.path},
        )
        response = self.client.get(url)

        self.assertEqual(200, response.status_code)
        self.assertEqual(resource1.path, response.context["path"])
        resources = list(response.context["resources"])
        self.assertEqual(2, len(resources))

        resource_paths = [r.path for r in resources]
        self.assertEqual(
            ["parent+special&chars/child1.txt", "parent+special&chars/child2.py"],
            resource_paths,
        )

    def test_scanpipe_views_project_resource_tree_view_with_path_file(self):
        resource = make_resource_file(self.project1, path="specific_file.txt")

        url = reverse(
            "project_resource_tree",
            kwargs={"slug": self.project1.slug, "path": resource.path},
        )
        response = self.client.get(url)

        self.assertEqual(200, response.status_code)
        self.assertEqual("specific_file.txt", response.context["path"])
        self.assertEqual(resource, response.context["resource"])

    def test_scanpipe_views_project_resource_tree_right_pane_view_empty_directory(self):
        make_resource_directory(self.project1, path="empty_dir")

        url = reverse(
            "project_resource_tree_right_pane",
            kwargs={"slug": self.project1.slug, "path": "empty_dir"},
        )
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        self.assertEqual("empty_dir", response.context["path"])
        resources = list(response.context["resources"])
        self.assertEqual(0, len(resources))

    def test_scanpipe_views_project_resource_tree_search_view_filters_results(self):
        r1 = make_resource_file(self.project1, path="src/FooBar.py")
        make_resource_file(self.project1, path="src/other.py")

        url = reverse(
            "project_resource_tree_search", kwargs={"slug": self.project1.slug}
        )
        response = self.client.get(url, data={"search": "foobar"})

        self.assertEqual(200, response.status_code)
        self.assertEqual("foobar", response.context["query"])
        self.assertQuerySetEqual([r1], response.context["search_results"])

    @mock.patch("scanpipe.views.ProjectResourceTreeRightPaneView.paginate_by", 2)
    def test_scanpipe_views_project_resource_tree_right_pane_view_pagination(self):
        make_resource_directory(self.project1, path="parent")
        make_resource_file(self.project1, path="parent/file1.txt", parent_path="parent")
        make_resource_file(self.project1, path="parent/file2.txt", parent_path="parent")
        make_resource_file(self.project1, path="parent/file3.txt", parent_path="parent")

        url = reverse(
            "project_resource_tree_right_pane",
            kwargs={"slug": self.project1.slug, "path": "parent"},
        )

        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.context["is_paginated"])
        self.assertEqual(1, response.context["page_obj"].number)
        self.assertTrue(response.context["page_obj"].has_next())
        self.assertFalse(response.context["page_obj"].has_previous())

        response = self.client.get(url + "?page=2")
        self.assertEqual(200, response.status_code)
        self.assertEqual(2, response.context["page_obj"].number)
        self.assertFalse(response.context["page_obj"].has_next())
        self.assertTrue(response.context["page_obj"].has_previous())
