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
from pathlib import Path
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredPackage
from scanpipe.models import Project
from scanpipe.models import Run
from scanpipe.pipes import purldb
from scanpipe.tests import dependency_data2
from scanpipe.tests import dependency_data3
from scanpipe.tests import package_data1


class ScanPipePurlDBTest(TestCase):
    data_location = Path(__file__).parent.parent / "data"
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

    def test_scanpipe_pipes_purldb_get_unique_resolved_purls(self):
        DiscoveredPackage.create_from_data(self.project1, package_data1)
        CodebaseResource.objects.create(
            project=self.project1, path="data.tar.gz-extract/Gemfile.lock"
        )
        DiscoveredDependency.create_from_data(self.project1, dependency_data2)

        expected = {"pkg:gem/appraisal@2.2.0"}
        result = purldb.get_unique_resolved_purls(self.project1)

        self.assertEqual(expected, result)

    def test_scanpipe_pipes_purldb_get_unique_unresolved_purls(self):
        DiscoveredPackage.create_from_data(self.project1, package_data1)
        CodebaseResource.objects.create(
            project=self.project1,
            path="daglib-0.3.2.tar.gz-extract/daglib-0.3.2/PKG-INFO",
        )
        DiscoveredDependency.create_from_data(self.project1, dependency_data3)

        expected = {("pkg:pypi/dask", "vers:pypi/>=1.0")}
        result = purldb.get_unique_unresolved_purls(self.project1)

        self.assertEqual(expected, result)

    @mock.patch("scanpipe.pipes.purldb.request_post")
    @mock.patch("scanpipe.pipes.purldb.is_available")
    def test_scanpipe_pipes_purldb_feed_purldb(
        self, mock_is_available, mock_request_post
    ):
        mock_is_available.return_value = True

        packages = [("pkg:pypi/dask", "vers:pypi/>=1.0")]

        def mock_request_post_return(url, data, headers, timeout):
            return {
                "queued_packages_count": 1,
                "queued_packages": [],
                "unqueued_packages_count": 1,
                "unqueued_packages": [],
                "unsupported_packages_count": 0,
                "unsupported_packages": [],
            }

        mock_request_post.side_effect = mock_request_post_return

        buffer = io.StringIO()
        purldb.feed_purldb(
            packages=packages,
            chunk_size=10,
            logger=buffer.write,
        )

        expected_log = buffer.getvalue()
        self.assertIn(
            "Successfully queued 1 PURLs for indexing in PurlDB", expected_log
        )
        self.assertIn(
            "1 PURLs were already present in PurlDB index queue", expected_log
        )

    @mock.patch("scanpipe.pipes.purldb.request_get")
    @mock.patch("scanpipe.pipes.purldb.is_available")
    def test_scanpipe_pipes_purldb_get_next_download_url(
        self, mock_is_available, mock_request_get
    ):
        mock_is_available.return_value = True
        expected_download_url = "https://registry.npmjs.org/asdf/-/asdf-1.0.1.tgz"
        expected_scannable_uri_uuid = "52b2930d-6e85-4b3e-ba3e-17dd9a618650"
        expected_pipelines = ["scan_and_fingerprint_package"]
        mock_request_get.side_effect = [
            {
                "download_url": expected_download_url,
                "scannable_uri_uuid": expected_scannable_uri_uuid,
                "pipelines": expected_pipelines,
            },
            {"download_url": "", "scannable_uri_uuid": "", "pipelines": []},
            None,
        ]

        results = purldb.get_next_download_url()
        self.assertTrue(results)
        self.assertEqual(expected_scannable_uri_uuid, results["scannable_uri_uuid"])
        self.assertEqual(expected_download_url, results["download_url"])
        self.assertEqual(expected_pipelines, results["pipelines"])

        results = purldb.get_next_download_url()
        self.assertTrue(results)
        self.assertFalse(results["scannable_uri_uuid"])
        self.assertFalse(results["download_url"])
        self.assertFalse(results["pipelines"])

        results = purldb.get_next_download_url()
        self.assertFalse(results)

    def test_scanpipe_pipes_purldb_get_run_status(self):
        now = timezone.now()
        run = self.create_run(
            pipeline="succeed",
            task_start_date=now,
            task_end_date=now,
            task_exitcode=0,
        )
        status = purldb.get_run_status(run=run)
        self.assertEqual("success", status)

    @mock.patch("scanpipe.pipes.purldb.request_post")
    @mock.patch("scanpipe.pipes.purldb.is_available")
    def test_scanpipe_pipes_purldb_check_project_run_statuses(
        self, mock_is_available, mock_request_post
    ):
        def mock_request_post_return(url, data, timeout):
            return {
                "scannable_uri_uuid": "97627c6e-9acb-43e0-b8df-28bd92f2b7e5",
                "scan_status": "failed",
                "project_extra_data": '{"scannable_uri_uuid": '
                '"97627c6e-9acb-43e0-b8df-28bd92f2b7e5"}',
            }

        mock_is_available.return_value = True
        mock_request_post.side_effect = mock_request_post_return

        self.project1.extra_data.update(
            {"scannable_uri_uuid": "97627c6e-9acb-43e0-b8df-28bd92f2b7e5"}
        )
        now = timezone.now()

        # Test poll_run_status on individual pipelines
        self.assertEqual(0, self.project1.runs.count())
        self.create_run(
            pipeline="succeed",
            task_start_date=now,
            task_end_date=now,
            task_exitcode=0,
        )
        purldb.check_project_run_statuses(
            project=self.project1,
        )
        mock_request_post.assert_not_called()
        self.project1.runs.all().delete()

        self.create_run(
            pipeline="failed",
            task_start_date=now,
            task_end_date=now,
            task_exitcode=1,
            log="failed",
        )
        purldb.check_project_run_statuses(
            project=self.project1,
        )
        mock_request_post.assert_called_once()
        mock_request_post_call = mock_request_post.mock_calls[0]
        mock_request_post_call_kwargs = mock_request_post_call.kwargs
        expected_data = {
            "scannable_uri_uuid": "97627c6e-9acb-43e0-b8df-28bd92f2b7e5",
            "scan_status": "failed",
            "scan_log": "failed failed:\n\nfailed\n",
        }
        self.assertEqual(expected_data, mock_request_post_call_kwargs["data"])
        self.project1.runs.all().delete()

        self.create_run(
            pipeline="stopped",
            task_start_date=now,
            task_end_date=now,
            task_exitcode=99,
            log="stopped",
        )
        purldb.check_project_run_statuses(
            project=self.project1,
        )
        self.assertEqual(2, mock_request_post.call_count)
        mock_request_post_call = mock_request_post.mock_calls[0]
        mock_request_post_call_kwargs = mock_request_post_call.kwargs
        self.assertEqual(expected_data, mock_request_post_call_kwargs["data"])
        self.project1.runs.all().delete()

        self.create_run(
            pipeline="stale",
            task_start_date=now,
            task_end_date=now,
            task_exitcode=88,
            log="stale",
        )
        purldb.check_project_run_statuses(
            project=self.project1,
        )
        self.assertEqual(3, mock_request_post.call_count)
        mock_request_post_call = mock_request_post.mock_calls[0]
        mock_request_post_call_kwargs = mock_request_post_call.kwargs
        self.assertEqual(expected_data, mock_request_post_call_kwargs["data"])
        self.project1.runs.all().delete()

    def test_scanpipe_pipes_purldb_create_project_name(self):
        download_url = "https://registry.npmjs.org/asdf/-/asdf-1.0.1.tgz"
        scannable_uri_uuid = "52b2930d-6e85-4b3e-ba3e-17dd9a618650"
        project_name = purldb.create_project_name(download_url, scannable_uri_uuid)
        self.assertEqual("httpsregistrynpmjsorgasdf-asdf-101tgz-52b2930d", project_name)
