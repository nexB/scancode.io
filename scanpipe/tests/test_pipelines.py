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
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock
from unittest import skipIf

from django.conf import settings
from django.test import TestCase
from django.test import tag

from packageurl import PackageURL
from scancode.cli_test_utils import purl_with_fake_uuid

from scanpipe import pipes
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredPackage
from scanpipe.models import Project
from scanpipe.pipelines import CommonStepsMixin
from scanpipe.pipelines import InputFilesError
from scanpipe.pipelines import Pipeline
from scanpipe.pipelines import deploy_to_develop
from scanpipe.pipelines import is_pipeline
from scanpipe.pipelines import root_filesystem
from scanpipe.pipelines import scan_single_package
from scanpipe.pipes import output
from scanpipe.pipes import scancode
from scanpipe.pipes.input import copy_input
from scanpipe.tests import FIXTURES_REGEN
from scanpipe.tests import make_package
from scanpipe.tests import package_data1
from scanpipe.tests.pipelines.do_nothing import DoNothing
from scanpipe.tests.pipelines.download_inputs import DownloadInput
from scanpipe.tests.pipelines.profile_step import ProfileStep
from scanpipe.tests.pipelines.steps_as_attribute import StepsAsAttribute
from scanpipe.tests.pipelines.with_groups import WithGroups

from_docker_image = os.environ.get("FROM_DOCKER_IMAGE")


class ScanPipePipelinesTest(TestCase):
    data = Path(__file__).parent / "data"

    def test_scanpipe_pipeline_class_pipeline_name_attribute(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline_instance = DoNothing(run)
        self.assertEqual("do_nothing", pipeline_instance.pipeline_name)

    def test_scanpipe_pipeline_class_get_info(self):
        expected = {
            "description": "Description section of the doc string.",
            "summary": "Do nothing, in 2 steps.",
            "steps": [
                {"name": "step1", "doc": "Step1 doc.", "groups": []},
                {"name": "step2", "doc": "Step2 doc.", "groups": []},
            ],
            "available_groups": [],
        }
        self.assertEqual(expected, DoNothing.get_info())

        expected = {
            "summary": "Profile a step using the @profile decorator.",
            "description": "",
            "steps": [
                {"name": "step", "doc": "", "groups": []},
            ],
            "available_groups": [],
        }
        self.assertEqual(expected, ProfileStep.get_info())

    def test_scanpipe_pipeline_class_get_summary(self):
        expected = "Do nothing, in 2 steps."
        self.assertEqual(expected, DoNothing.get_summary())

        expected = "Profile a step using the @profile decorator."
        self.assertEqual(expected, ProfileStep.get_summary())

    def test_scanpipe_pipeline_class_log(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()
        pipeline.log("Event1")
        pipeline.log("Event2")

        run.refresh_from_db()
        self.assertIn("Event1", run.log)
        self.assertIn("Event2", run.log)

    def test_scanpipe_pipeline_class_execute(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode)
        self.assertEqual("", out)

        run.refresh_from_db()
        self.assertIn("Pipeline [do_nothing] starting", run.log)
        self.assertIn("Step [step1] starting", run.log)
        self.assertIn("Step [step1] completed", run.log)
        self.assertIn("Step [step2] starting", run.log)
        self.assertIn("Step [step2] completed", run.log)
        self.assertIn("Pipeline completed", run.log)

    def test_scanpipe_pipeline_class_execute_with_exception(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("raise_exception")
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(1, exitcode)
        self.assertTrue(out.startswith("Error message"))
        self.assertIn("Traceback:", out)
        self.assertIn("in execute", out)
        self.assertIn("step(self)", out)
        self.assertIn("in raise_exception", out)
        self.assertIn("raise ValueError", out)

        run.refresh_from_db()
        self.assertIn("Pipeline [raise_exception] starting", run.log)
        self.assertIn("Step [raise_exception_step] starting", run.log)
        self.assertIn("Pipeline failed", run.log)

    @mock.patch("scanpipe.tests.pipelines.do_nothing.DoNothing.step1")
    @mock.patch("scanpipe.tests.pipelines.do_nothing.DoNothing.step2")
    def test_scanpipe_pipeline_class_execute_with_selected_steps(self, step2, step1):
        step1.__name__ = "step1"
        step2.__name__ = "step2"

        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        run.update(selected_steps=["step2", "not_existing_step"])
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode)
        self.assertEqual("", out)

        step1.assert_not_called()
        step2.assert_called()

        run.refresh_from_db()
        self.assertIn("Pipeline [do_nothing] starting", run.log)
        self.assertIn("Step [step1] skipped", run.log)
        self.assertIn("Step [step2] starting", run.log)
        self.assertIn("Step [step2] completed", run.log)
        self.assertIn("Pipeline completed", run.log)

    def test_scanpipe_pipeline_class_download_inputs_attribute(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("download_inputs")
        pipeline = run.make_pipeline_instance()
        self.assertTrue(pipeline.download_inputs)
        expected = (CommonStepsMixin.download_missing_inputs,)
        self.assertEqual(expected, pipeline.get_initial_steps())
        expected = (CommonStepsMixin.download_missing_inputs, DownloadInput.step1)
        self.assertEqual(expected, pipeline.get_steps())
        pipeline.execute()
        self.assertIn("Step [download_missing_inputs]", run.log)

        run = project1.add_pipeline("profile_step")
        pipeline = run.make_pipeline_instance()
        self.assertFalse(pipeline.download_inputs)
        pipeline.execute()
        self.assertNotIn("Step [download_missing_inputs]", run.log)

    @mock.patch("requests.sessions.Session.get")
    def test_scanpipe_pipeline_class_download_missing_inputs(self, mock_get):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()

        file_location = self.data / "aboutcode" / "notice.NOTICE"
        input_source = project1.add_input_source(
            filename=file_location.name, is_uploaded=True
        )
        self.assertFalse(input_source.exists())
        with self.assertRaises(InputFilesError) as error:
            pipeline.download_missing_inputs()
        error_msg = (
            "InputFilesError encountered with the following issues:\n\n"
            "Error 1: Uploaded file filename=notice.NOTICE [uploaded] not available."
            "\n\nNo traceback available."
        )
        self.assertEqual(error_msg, str(error.exception))
        self.assertIn(
            "Uploaded file filename=notice.NOTICE [uploaded] not available.", run.log
        )

        project1.copy_input_from(file_location)
        self.assertTrue(input_source.exists())
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()
        pipeline.download_missing_inputs()
        self.assertEqual("", run.log)

        download_url = "https://download.url/file.zip"
        mock_get.return_value = mock.Mock(
            content=b"\x00", headers={}, status_code=200, url=download_url
        )
        input_source2 = project1.add_input_source(download_url=download_url)
        pipeline.download_missing_inputs()
        self.assertIn("Fetching input from https://download.url/file.zip", run.log)
        input_source2.refresh_from_db()
        self.assertEqual("file.zip", input_source2.filename)
        self.assertTrue(input_source2.exists())
        mock_get.assert_called_once()

    @mock.patch("scanpipe.models.InputSource.fetch")
    def test_scanpipe_pipeline_class_download_fetch_exception(self, mock_fetch):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()

        mock_fetch.side_effect = Exception("File not found")
        download_url = "https://download.url/file.zip"
        project1.add_input_source(download_url=download_url)

        with self.assertRaises(InputFilesError) as error:
            pipeline.download_missing_inputs()
        self.assertIn(
            "InputFilesError encountered with the following issues:",
            str(error.exception),
        )
        self.assertIn("Error 1: File not found", str(error.exception))
        self.assertIn("Traceback (most recent call last):", str(error.exception))
        self.assertIn("Exception: File not found", str(error.exception))

        self.assertIn("Fetching input from https://download.url/file.zip", run.log)
        self.assertIn("https://download.url/file.zip could not be fetched.", run.log)

    @mock.patch("git.repo.base.Repo.clone_from")
    def test_scanpipe_pipeline_class_download_missing_inputs_git_repo(self, mock_clone):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()

        download_url = "https://github.com/nexB/scancode.io.git"
        input_source = project1.add_input_source(download_url=download_url)

        def mock_make_to_path(**kwargs):
            to_path = kwargs.get("to_path")
            to_path.touch()

        mock_clone.side_effect = mock_make_to_path
        mock_clone.return_value = None

        pipeline.download_missing_inputs()
        self.assertIn(
            "Fetching input from https://github.com/nexB/scancode.io.git", run.log
        )
        input_source.refresh_from_db()
        self.assertEqual("scancode.io.git", input_source.filename)
        self.assertTrue(input_source.exists())

    def test_scanpipe_pipeline_class_save_errors_context_manager(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()
        self.assertEqual(project1, pipeline.project)

        with pipeline.save_errors(Exception):
            raise Exception("Error message")

        message = project1.projectmessages.get()
        self.assertEqual("do_nothing", message.model)
        self.assertEqual({}, message.details)
        self.assertEqual("Error message", message.description)
        self.assertIn('raise Exception("Error message")', message.traceback)

        resource1 = CodebaseResource.objects.create(project=project1, path="filename")
        with pipeline.save_errors(Exception, resource=resource1):
            raise Exception("Error message")
        message = project1.projectmessages.latest("created_date")
        self.assertEqual({"resource_path": str(resource1.path)}, message.details)

    def test_scanpipe_pipelines_is_pipeline(self):
        self.assertFalse(is_pipeline(None))
        self.assertFalse(is_pipeline(Pipeline))
        self.assertTrue(is_pipeline(DoNothing))

        class SubSubClass(DoNothing):
            pass

        self.assertTrue(is_pipeline(SubSubClass))

    def test_scanpipe_pipeline_class_get_graph(self):
        expected = [
            {"name": "step1", "doc": "Step1 doc.", "groups": []},
            {"name": "step2", "doc": "Step2 doc.", "groups": []},
        ]
        self.assertEqual(expected, DoNothing.get_graph())

    def test_scanpipe_pipelines_profile_decorator(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("profile_step")
        pipeline_instance = run.make_pipeline_instance()

        exitcode, out = pipeline_instance.execute()
        self.assertEqual(0, exitcode)

        run.refresh_from_db()
        self.assertIn("Profiling results at", run.log)
        self.assertIn("Pipeline completed", run.log)

        self.assertEqual(1, len(project1.output_root))
        output_file = project1.output_root[0]
        self.assertTrue(output_file.startswith("profile-"))
        self.assertTrue(output_file.endswith(".html"))

    def test_scanpipe_pipeline_class_get_steps(self):
        expected = (
            DoNothing.step1,
            DoNothing.step2,
        )
        self.assertEqual(expected, DoNothing.get_steps())

        with self.assertRaises(TypeError) as cm:
            StepsAsAttribute.get_steps()
        expected = "Use a ``steps(cls)`` classmethod to declare the steps."
        self.assertEqual(expected, str(cm.exception))

    def test_scanpipe_pipeline_class_get_steps_with_groups(self):
        expected = (
            WithGroups.grouped_with_foo_and_bar,
            WithGroups.grouped_with_bar,
            WithGroups.grouped_with_excluded,
            WithGroups.no_groups,
        )
        self.assertEqual(expected, WithGroups.get_steps())

        expected = (WithGroups.no_groups,)
        self.assertEqual(expected, WithGroups.get_steps(groups=[]))
        self.assertEqual(expected, WithGroups.get_steps(groups=["not"]))

        expected = (
            WithGroups.grouped_with_foo_and_bar,
            WithGroups.grouped_with_bar,
            WithGroups.no_groups,
        )
        self.assertEqual(expected, WithGroups.get_steps(groups=["bar"]))
        self.assertEqual(expected, WithGroups.get_steps(groups=["foo", "bar"]))

        expected = (
            WithGroups.grouped_with_foo_and_bar,
            WithGroups.no_groups,
        )
        self.assertEqual(expected, WithGroups.get_steps(groups=["foo"]))

    def test_scanpipe_pipeline_class_get_available_groups(self):
        self.assertEqual(["bar", "excluded", "foo"], WithGroups.get_available_groups())
        self.assertEqual([], DoNothing.get_available_groups())

    def test_scanpipe_pipeline_class_env_loaded_from_config_file(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()
        self.assertEqual({}, pipeline.env)

        config_file = project1.input_path / settings.SCANCODEIO_CONFIG_FILE
        config_file.write_text("{*this is not valid yml*}")
        pipeline = run.make_pipeline_instance()
        self.assertEqual({}, pipeline.env)

        config_file.write_text("product_name: Product")
        pipeline = run.make_pipeline_instance()
        self.assertEqual({"product_name": "Product"}, pipeline.env)

    def test_scanpipe_pipeline_class_env_reloaded_after_extraction(self):
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "settings" / "archived-scancode-config.zip"
        project1.copy_input_from(input_location)
        run = project1.add_pipeline("scan_codebase")
        pipeline = run.make_pipeline_instance()
        self.assertEqual({}, pipeline.env)

        # Manually run steps, env is reload from the scancode-config.yml contained in
        # the archive
        pipeline.copy_inputs_to_codebase_directory()
        pipeline.extract_archives()

        expected = {
            "product_name": "My Product Name",
            "product_version": "1.0",
            "ignored_patterns": ["*.tmp", "tests/*"],
        }
        self.assertEqual(expected, pipeline.env)

    def test_scanpipe_pipeline_class_flag_ignored_resources(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()
        self.assertIsNone(pipeline.env.get("ignored_patterns"))

        project1.settings.update({"ignored_patterns": "*.ext"})
        project1.save()
        pipeline = run.make_pipeline_instance()

        with mock.patch("scanpipe.pipes.flag.flag_ignored_patterns") as mock_flag:
            mock_flag.return_value = None
            pipeline.flag_ignored_resources()
        mock_flag.assert_called_with(project1, patterns="*.ext")

    def test_scanpipe_pipeline_class_extract_archive(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()

        target = tempfile.mkdtemp()
        input_location = str(self.data / "scancode" / "corrupted.tar.gz")
        pipeline.extract_archive(input_location, target)

        projects_errors = project1.projectmessages.all()
        self.assertEqual(1, len(projects_errors))
        project_error = projects_errors.get()
        self.assertEqual("error", project_error.severity)
        self.assertIn("gzip decompression failed", project_error.description)
        self.assertEqual("extract_archive", project_error.model)
        self.assertEqual({"filename": "corrupted.tar.gz"}, project_error.details)
        self.assertEqual("", project_error.traceback)

    def test_scanpipe_pipeline_class_extract_archives(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("do_nothing")
        pipeline = run.make_pipeline_instance()

        input_location = str(self.data / "scancode" / "corrupted.tar.gz")
        resource_location = copy_input(input_location, project1.codebase_path)
        pipeline.extract_archives()

        projects_errors = project1.projectmessages.all()
        self.assertEqual(1, len(projects_errors))
        project_error = projects_errors.get()
        self.assertEqual("error", project_error.severity)
        self.assertIn("gzip decompression failed", project_error.description)
        self.assertEqual("extract_archives", project_error.model)
        self.assertEqual(
            {"resource_path": str(resource_location)}, project_error.details
        )
        self.assertEqual("", project_error.traceback)


class RootFSPipelineTest(TestCase):
    def test_scanpipe_rootfs_pipeline_extract_input_files_errors(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("analyze_root_filesystem_or_vm_image")
        pipeline_instance = root_filesystem.RootFS(run)

        # Create 2 files in the input/ directory to generate error twice
        project1.move_input_from(tempfile.mkstemp()[1])
        project1.move_input_from(tempfile.mkstemp()[1])
        self.assertEqual(2, len(project1.input_files))

        with mock.patch("scanpipe.pipes.scancode.extract_archive") as extract_archive:
            extract_archive.return_value = {"path/to/resource": ["error1", "error2"]}
            pipeline_instance.extract_input_files_to_codebase_directory()

        projects_errors = project1.projectmessages.all()
        self.assertEqual(2, len(projects_errors))
        project_error = projects_errors[0]
        self.assertEqual("error", project_error.severity)
        self.assertEqual("error1\nerror2", project_error.description)
        self.assertEqual("extract_archive", project_error.model)
        self.assertEqual({"filename": "resource"}, project_error.details)
        self.assertEqual("", project_error.traceback)


def sort_for_os_compatibility(scan_data):
    """Sort the ``scan_data`` files and relations in place. Return ``scan_data``."""
    if files := scan_data.get("files"):
        files.sort(key=lambda x: x["path"])

    if relations := scan_data.get("relations"):
        relations.sort(key=lambda x: x["to_resource"])

    return scan_data


@tag("slow")
class PipelinesIntegrationTest(TestCase):
    """Integration tests to ensure the proper output for each built-in Pipelines."""

    # Un-comment the following to display full diffs:
    # maxDiff = None
    data = Path(__file__).parent / "data"
    exclude_from_diff = [
        "start_timestamp",
        "end_timestamp",
        "date",
        "duration",
        "input",
        "compliance_alert",
        "policy",
        "tool_version",
        "other_tools",
        "created_date",
        "log",
        "uuid",
        "size",  # directory sizes are OS dependant
        "size_count",
        "--json-pp",
        "--processes",
        "--verbose",
        # system_environment differs between systems
        "system_environment",
        "file_type",
        # mime type and is_script are inconsistent across systems
        "mime_type",
        "is_script",
        "notes",
        "settings",
        "description",
    ]

    def _without_keys(self, data, exclude_keys):
        """Return the `data` excluding the provided `exclude_keys`."""
        if isinstance(data, list):
            return [self._without_keys(entry, exclude_keys) for entry in data]

        if isinstance(data, dict):
            return {
                key: (
                    self._without_keys(value, exclude_keys)
                    if type(value) in [list, dict]
                    else value
                )
                for key, value in data.items()
                if key not in exclude_keys
            }

        return data

    def purl_fields_with_fake_uuid(self, value, key):
        purl_name = "fixed-name-for-testing-5642512d1758"
        purl_namespace = "fixed-namespace-for-testing-5642512d1758"
        if key == "name":
            return purl_name
        elif key == "namespace":
            return purl_namespace
        elif key == "purl" or key == "for_packages":
            purl_old = PackageURL.from_string(value)
            if purl_old.type != "local-files":
                return purl_with_fake_uuid(value)

            purl = PackageURL(
                name=purl_name,
                namespace=purl_namespace,
                type="local-files",
                version=purl_old.version,
                qualifiers=purl_old.qualifiers,
                subpath=purl_old.subpath,
            )
            return purl.to_string()

    def _normalize_package_uids(self, data):
        """
        Return the `data`, where any `package_uid` value has been normalized
        with `purl_with_fake_uuid()`
        """
        fields_with_package_uids = [
            "package_uid",
            "dependency_uid",
            "for_package_uid",
            "resolved_to_package_uid",
        ]
        if isinstance(data, list):
            return [self._normalize_package_uids(entry) for entry in data]

        if isinstance(data, dict):
            is_local_files = False
            if data.get("type") and data["type"] == "local-files":
                is_local_files = True
            normalized_data = {}
            for key, value in data.items():
                if isinstance(value, list | dict):
                    value = self._normalize_package_uids(value)
                if key in fields_with_package_uids and value:
                    value = purl_with_fake_uuid(value)
                if key == "for_packages" and value:
                    value = sorted(
                        [
                            self.purl_fields_with_fake_uuid(package_uid, key)
                            for package_uid in value
                        ]
                    )
                if is_local_files and key in ("name", "namespace", "purl") and value:
                    value = self.purl_fields_with_fake_uuid(value, key)
                normalized_data[key] = value
            return normalized_data

        return data

    def _sort_dependencies(self, data):
        """
        Sort dependencies by their "for_package_uid".

        After dependency resolution in some cases we have multiple
        dependency requirements resolved to a same package, and they
        are not sorted the same way every time.
        """
        mappings = data.get("dependencies")
        if mappings:
            mappings_by_uid = {}
            for mapping in mappings:
                uid = mapping.get("for_package_uid") or ""
                mappings_by_uid[uid] = mapping
            data["dependencies"] = list(dict(sorted(mappings_by_uid.items())).values())
        return data

    def assertPipelineResultEqual(
        self, expected_file, result_file, sort_dependencies=False, regen=FIXTURES_REGEN
    ):
        """Set `regen` to True to regenerate the expected results."""
        result_json = json.loads(Path(result_file).read_text())
        result_json = self._normalize_package_uids(result_json)
        result_data = self._without_keys(result_json, self.exclude_from_diff)
        if sort_dependencies:
            result_data = self._sort_dependencies(result_data)
        result_data = sort_for_os_compatibility(result_data)

        if regen:
            expected_file.write_text(json.dumps(result_data, indent=2))

        expected_json = json.loads(expected_file.read_text())
        expected_json = self._normalize_package_uids(expected_json)
        expected_data = self._without_keys(expected_json, self.exclude_from_diff)
        if sort_dependencies:
            result_data = self._sort_dependencies(result_data)
        expected_data = sort_for_os_compatibility(expected_data)

        self.assertEqual(expected_data, result_data)

    @skipIf(from_docker_image, "Random failure in the Docker context.")
    def test_scanpipe_scan_package_pipeline_integration(self):
        pipeline_name = "scan_single_package"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "scancode" / "is-npm-1.0.0.tgz"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(4, project1.codebaseresources.count())
        self.assertEqual(1, project1.discoveredpackages.count())
        self.assertEqual(1, project1.discovereddependencies.count())

        scancode_file = project1.get_latest_output(filename="scancode")
        expected_file = self.data / "scancode" / "is-npm-1.0.0_scan_package.json"
        self.assertPipelineResultEqual(expected_file, scancode_file)

        summary_file = project1.get_latest_output(filename="summary")
        expected_file = (
            self.data / "scancode" / "is-npm-1.0.0_scan_package_summary.json"
        )
        self.assertPipelineResultEqual(expected_file, summary_file)

        # Ensure that we only have one instance of is-npm in `key_files_packages`
        summary_data = json.loads(Path(summary_file).read_text())
        key_files_packages = summary_data.get("key_files_packages", [])
        self.assertEqual(1, len(key_files_packages))
        key_file_package = key_files_packages[0]
        key_file_package_purl = key_file_package.get("purl", "")
        self.assertEqual("pkg:npm/is-npm@1.0.0", key_file_package_purl)

    @skipIf(from_docker_image, "Random failure in the Docker context.")
    def test_scanpipe_scan_package_pipeline_integration_multiple_packages(self):
        pipeline_name = "scan_single_package"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "scancode" / "multiple-is-npm-1.0.0.tar.gz"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(9, project1.codebaseresources.count())
        self.assertEqual(2, project1.discoveredpackages.count())
        self.assertEqual(2, project1.discovereddependencies.count())

        scancode_file = project1.get_latest_output(filename="scancode")
        expected_file = (
            self.data / "scancode" / "multiple-is-npm-1.0.0_scan_package.json"
        )
        # Do not override the regen as this file is generated in regen_test_data
        self.assertPipelineResultEqual(expected_file, scancode_file)

        summary_file = project1.get_latest_output(filename="summary")
        expected_file = (
            self.data / "scancode" / "multiple-is-npm-1.0.0_scan_package_summary.json"
        )
        self.assertPipelineResultEqual(expected_file, summary_file)

    @mock.patch("scanpipe.pipelines.scan_single_package.is_archive")
    def test_scanpipe_scan_package_single_extract_input_to_codebase_directory(
        self, mock_is_archive
    ):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("scan_single_package")
        pipeline_instance = scan_single_package.ScanSinglePackage(run)

        project1.move_input_from(tempfile.mkstemp(suffix=".zip")[1])
        self.assertEqual(1, len(project1.input_files))

        mock_is_archive.return_value = True
        pipeline_instance.get_package_input()
        with mock.patch("scanpipe.pipes.scancode.extract_archive") as extract_archive:
            extract_archive.return_value = {"path/to/resource": ["error1", "error2"]}
            pipeline_instance.extract_input_to_codebase_directory()

        projects_errors = project1.projectmessages.all()
        self.assertEqual(1, len(projects_errors))
        project_error = projects_errors[0]
        self.assertEqual("error", project_error.severity)
        self.assertEqual("error1\nerror2", project_error.description)
        self.assertEqual("extract_archive", project_error.model)
        self.assertEqual({"filename": "resource"}, project_error.details)
        self.assertEqual("", project_error.traceback)

    def test_scanpipe_scan_package_single_file(self):
        pipeline_name = "scan_single_package"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "manifests" / "openpdf-parent-1.3.11.pom.xml"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(1, project1.codebaseresources.count())
        self.assertEqual(1, project1.discoveredpackages.count())
        self.assertEqual(10, project1.discovereddependencies.count())

        scancode_file = project1.get_latest_output(filename="scancode")
        expected_file = (
            self.data / "manifests" / "openpdf-parent-1.3.11_scan_package.json"
        )
        self.assertPipelineResultEqual(expected_file, scancode_file)

    def test_scanpipe_scan_codebase_pipeline_integration(self):
        pipeline_name = "scan_codebase"
        project1 = Project.objects.create(name="Analysis")

        filename = "is-npm-1.0.0.tgz"
        input_location = self.data / "scancode" / filename
        project1.copy_input_from(input_location)
        project1.add_input_source("https://download.url", filename)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(6, project1.codebaseresources.count())
        self.assertEqual(1, project1.discoveredpackages.count())
        self.assertEqual(1, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = self.data / "scancode" / "is-npm-1.0.0_scan_codebase.json"
        self.assertPipelineResultEqual(expected_file, result_file)

    def test_scanpipe_inspect_packages_creates_packages_npm(self):
        pipeline_name = "inspect_packages"
        project1 = Project.objects.create(name="Analysis")

        filename = "is-npm-1.0.0.tgz"
        input_location = self.data / "scancode" / filename
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(6, project1.codebaseresources.count())
        self.assertEqual(1, project1.discoveredpackages.count())
        self.assertEqual(1, project1.discovereddependencies.count())

        package = project1.discoveredpackages.get()
        dependency = project1.discovereddependencies.get()

        self.assertEqual(3, package.codebase_resources.count())
        self.assertEqual("pkg:npm/is-npm@1.0.0", dependency.for_package.purl)
        self.assertEqual(package.datasource_ids, [dependency.datasource_id])
        self.assertEqual(
            package.codebase_resources.get(
                path="is-npm-1.0.0.tgz-extract/package/package.json"
            ).path,
            dependency.datafile_resource.path,
        )

    def test_scanpipe_inspect_packages_creates_packages_pypi(self):
        pipeline_name = "inspect_packages"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "manifests" / "python-inspector-0.10.0.zip"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)
        self.assertEqual(6, project1.codebaseresources.count())
        self.assertEqual(0, project1.discoveredpackages.count())
        self.assertEqual(26, project1.discovereddependencies.count())

    @skipIf(sys.platform == "darwin", "Not supported on macOS")
    def test_scanpipe_inspect_packages_with_resolved_dependencies_npm(self):
        pipeline_name = "inspect_packages"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "dependencies" / "resolved_dependencies_npm.zip"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(
            pipeline_name=pipeline_name,
            selected_groups=["StaticResolver"],
        )
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)
        self.assertEqual(4, project1.codebaseresources.count())
        self.assertEqual(7, project1.discoveredpackages.count())
        self.assertEqual(6, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = (
            self.data
            / "dependencies"
            / "resolved_dependencies_npm_inspect_packages.json"
        )
        self.assertPipelineResultEqual(expected_file, result_file)

    @skipIf(sys.platform == "darwin", "Not supported on macOS")
    def test_scanpipe_inspect_packages_with_resolved_dependencies_poetry(self):
        pipeline_name = "inspect_packages"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "dependencies" / "resolved_dependencies_poetry.zip"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(
            pipeline_name=pipeline_name,
            selected_groups=["StaticResolver"],
        )
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)
        self.assertEqual(5, project1.codebaseresources.count())
        self.assertEqual(6, project1.discoveredpackages.count())
        self.assertEqual(10, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = (
            self.data
            / "dependencies"
            / "resolved_dependencies_poetry_inspect_packages.json"
        )
        self.assertPipelineResultEqual(expected_file, result_file)

    def test_scanpipe_resolved_dependencies_cocoapods(self):
        pipeline_name = "resolve_dependencies"
        project1 = Project.objects.create(name="Analysis")

        input_location = (
            self.data / "dependencies" / "resolved_dependencies_cocoapods.zip"
        )
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(
            pipeline_name=pipeline_name,
            selected_groups=["StaticResolver"],
        )
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)
        self.assertEqual(3, project1.codebaseresources.count())
        self.assertEqual(25, project1.discoveredpackages.count())
        self.assertEqual(30, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = (
            self.data / "dependencies" / "resolved_dependencies_cocoapods.json"
        )
        self.assertPipelineResultEqual(
            expected_file, result_file, sort_dependencies=True
        )

    def test_scanpipe_resolved_dependencies_pip_inspect(self):
        pipeline_name = "resolve_dependencies"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "dependencies" / "resolved_dependencies_pip.zip"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(
            pipeline_name=pipeline_name,
            selected_groups=["StaticResolver"],
        )
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)
        self.assertEqual(3, project1.codebaseresources.count())
        self.assertEqual(4, project1.discoveredpackages.count())
        self.assertEqual(17, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = self.data / "dependencies" / "resolved_dependencies_pip.json"
        self.assertPipelineResultEqual(
            expected_file,
            result_file,
        )

    def test_scanpipe_resolved_dependencies_nuget(self):
        pipeline_name = "resolve_dependencies"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "dependencies" / "resolved_dependencies_nuget.zip"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(
            pipeline_name=pipeline_name,
            selected_groups=["StaticResolver"],
        )
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)
        self.assertEqual(3, project1.codebaseresources.count())
        self.assertEqual(34, project1.discoveredpackages.count())
        self.assertEqual(108, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = self.data / "dependencies" / "resolved_dependencies_nuget.json"
        self.assertPipelineResultEqual(
            expected_file,
            result_file,
            sort_dependencies=True,
        )

    def test_scanpipe_scan_codebase_can_process_wheel(self):
        pipeline_name = "scan_codebase"
        project1 = Project.objects.create(name="Analysis")

        filename = "daglib-0.6.0-py3-none-any.whl"
        input_location = self.data / "scancode" / filename
        project1.copy_input_from(input_location)
        project1.add_input_source("https://download.url", filename)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(11, project1.codebaseresources.count())
        self.assertEqual(2, project1.discoveredpackages.count())
        self.assertEqual(8, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = (
            self.data / "scancode" / "daglib-0.6.0-py3-none-any.whl_scan_codebase.json"
        )
        self.assertPipelineResultEqual(expected_file, result_file)

    @skipIf(sys.platform != "linux", "Expected results are inconsistent across OS")
    def test_scanpipe_docker_pipeline_alpine_integration(self):
        pipeline_name = "analyze_docker_image"
        project1 = Project.objects.create(name="Analysis")

        filename = "alpine_3_15_4.tar.gz"
        input_location = self.data / "docker" / filename
        project1.copy_input_from(input_location)
        project1.add_input_source("https://download.url", filename)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(510, project1.codebaseresources.count())
        self.assertEqual(14, project1.discoveredpackages.count())
        self.assertEqual(0, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = self.data / "docker" / "alpine_3_15_4_scan_codebase.json"
        self.assertPipelineResultEqual(expected_file, result_file)

    def test_scanpipe_docker_pipeline_does_not_report_errors_for_broken_symlinks(self):
        pipeline_name = "analyze_docker_image"
        project1 = Project.objects.create(name="Analysis")

        filename = "minitag.tar"
        input_location = self.data / "image-with-symlinks" / filename
        project1.copy_input_from(input_location)
        project1.add_input_source("https://download.url", filename)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        project_messages = project1.projectmessages.all()
        self.assertEqual(1, len(project_messages))
        self.assertEqual("Distro not found.", project_messages[0].description)

        result_file = output.to_json(project1)
        expected_file = (
            self.data / "image-with-symlinks" / (filename + "-expected-scan.json")
        )
        self.assertPipelineResultEqual(expected_file, result_file)

    @skipIf(sys.platform != "linux", "RPM related features only supported on Linux.")
    def test_scanpipe_docker_pipeline_rpm_integration(self):
        pipeline_name = "analyze_docker_image"
        project1 = Project.objects.create(name="Analysis")

        filename = "centos.tar.gz"
        input_location = self.data / "docker" / filename
        project1.copy_input_from(input_location)
        project1.add_input_source("https://download.url", filename)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(29, project1.codebaseresources.count())
        self.assertEqual(101, project1.discoveredpackages.count())
        self.assertEqual(0, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = self.data / "docker" / "centos_scan_codebase.json"
        self.assertPipelineResultEqual(expected_file, result_file)

    def test_scanpipe_docker_pipeline_debian_integration(self):
        pipeline_name = "analyze_docker_image"
        project1 = Project.objects.create(name="Analysis")

        filename = "debian.tar.gz"
        input_location = self.data / "docker" / filename
        project1.copy_input_from(input_location)
        project1.add_input_source("https://download.url", filename)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(16, project1.codebaseresources.count())
        self.assertEqual(2, project1.discoveredpackages.count())
        self.assertEqual(0, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = self.data / "docker" / "debian_scan_codebase.json"
        self.assertPipelineResultEqual(expected_file, result_file)

    def test_scanpipe_docker_pipeline_distroless_debian_integration(self):
        pipeline_name = "analyze_docker_image"
        project1 = Project.objects.create(name="Analysis")

        filename = "gcr_io_distroless_base.tar.gz"
        input_location = self.data / "docker" / filename
        project1.copy_input_from(input_location)
        project1.add_input_source("https://download.url", filename)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(2458, project1.codebaseresources.count())
        self.assertEqual(6, project1.discoveredpackages.count())
        self.assertEqual(0, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = (
            self.data / "docker" / "gcr_io_distroless_base_scan_codebase.json"
        )
        self.assertPipelineResultEqual(expected_file, result_file)

    def test_scanpipe_rootfs_pipeline_integration(self):
        pipeline_name = "analyze_root_filesystem_or_vm_image"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "rootfs" / "basic-rootfs.tar.gz"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(16, project1.codebaseresources.count())
        self.assertEqual(2, project1.discoveredpackages.count())
        self.assertEqual(0, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = self.data / "rootfs" / "basic-rootfs_root_filesystems.json"
        self.assertPipelineResultEqual(expected_file, result_file)

    def test_scanpipe_load_inventory_pipeline_integration(self):
        pipeline_name = "load_inventory"
        project1 = Project.objects.create(name="Tool: scancode-toolkit")

        input_location = self.data / "asgiref" / "asgiref-3.3.0_toolkit_scan.json"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(18, project1.codebaseresources.count())
        self.assertEqual(2, project1.discoveredpackages.count())
        self.assertEqual(4, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = (
            self.data / "asgiref" / "asgiref-3.3.0_load_inventory_expected.json"
        )
        self.assertPipelineResultEqual(expected_file, result_file)

        # Using the ScanCode.io JSON output as the input
        project2 = Project.objects.create(name="Tool: scanpipe")

        input_location = self.data / "asgiref" / "asgiref-3.3.0_scanpipe_output.json"
        project2.copy_input_from(input_location)

        run = project2.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(18, project2.codebaseresources.count())
        self.assertEqual(2, project2.discoveredpackages.count())
        self.assertEqual(4, project2.discovereddependencies.count())

    @mock.patch("scanpipe.pipes.vulnerablecode.is_available")
    @mock.patch("scanpipe.pipes.vulnerablecode.is_configured")
    @mock.patch("scanpipe.pipes.vulnerablecode.bulk_search_by_purl")
    def test_scanpipe_find_vulnerabilities_pipeline_integration(
        self, mock_bulk_search_by_purl, mock_is_configured, mock_is_available
    ):
        pipeline_name = "find_vulnerabilities"
        project1 = Project.objects.create(name="Analysis")
        package1 = DiscoveredPackage.create_from_data(project1, package_data1)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()
        mock_is_configured.return_value = False
        mock_is_available.return_value = False
        exitcode, out = pipeline.execute()
        self.assertEqual(1, exitcode, msg=out)
        self.assertIn("VulnerableCode is not configured.", out)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()
        mock_is_configured.return_value = True
        mock_is_available.return_value = True
        vulnerability_data = [
            {
                "purl": "pkg:deb/debian/adduser@3.118?arch=all",
                "affected_by_vulnerabilities": [
                    {
                        "vulnerability_id": "VCID-cah8-awtr-aaad",
                        "summary": "An issue was discovered.",
                    },
                ],
            },
            {
                "purl": "pkg:deb/debian/adduser@3.118?qualifiers=1",
                "affected_by_vulnerabilities": [
                    {
                        "vulnerability_id": "VCID-cah8-awtr-aaad",
                        "summary": "An issue was discovered.",
                    },
                ],
            },
        ]
        mock_bulk_search_by_purl.return_value = vulnerability_data

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        package1.refresh_from_db()
        expected = vulnerability_data[0]["affected_by_vulnerabilities"]
        self.assertEqual(expected, package1.affected_by_vulnerabilities)

    @mock.patch("ossf_scorecard.scorecard.is_available")
    @mock.patch("ossf_scorecard.scorecard.is_configured")
    def test_scanpipe_get_scorecard_info_packages_integration(
        self, mock_is_configured, mock_is_available
    ):
        pipeline_name = "fetch_scorecode_info"
        project1 = Project.objects.create(name="Analysis")
        package1 = DiscoveredPackage.create_from_data(project1, package_data1)
        package1.vcs_url = "https://github.com/ossf/scorecard"
        package1.save()

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()
        mock_is_configured.return_value = False
        mock_is_available.return_value = False
        exitcode, out = pipeline.execute()
        self.assertEqual(1, exitcode, msg=out)
        self.assertIn("scorecode service is not configured.", out)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()
        mock_is_configured.return_value = True
        mock_is_available.return_value = True

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        package1.refresh_from_db()
        self.assertIsNotNone(
            package1.discovered_packages_score.filter(scoring_tool="OSSF")[0].score,
            msg=out,
        )

        self.assertEqual("https://github.com/ossf/scorecard", package1.vcs_url)

    def test_scanpipe_resolve_dependencies_pipeline_integration(self):
        pipeline_name = "resolve_dependencies"
        project1 = Project.objects.create(name="Analysis")

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        project1.move_input_from(tempfile.mkstemp()[1])
        pipeline.execute()
        self.assertEqual(1, project1.projectmessages.count())
        message = project1.projectmessages.get()
        self.assertEqual("get_packages_from_manifest", message.model)
        expected = "No resources containing package data found in codebase."
        self.assertIn(expected, message.description)

    def test_scanpipe_resolve_dependencies_pipeline_integration_empty_manifest(self):
        pipeline_name = "resolve_dependencies"
        project1 = Project.objects.create(name="Analysis")

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        project1.move_input_from(tempfile.mkstemp(suffix="requirements.txt")[1])
        pipeline.execute()
        self.assertEqual(1, project1.projectmessages.count())
        message = project1.projectmessages.get()
        self.assertEqual("get_packages_from_manifest", message.model)
        expected = "No packages could be resolved"
        self.assertIn(expected, message.description)

    def test_scanpipe_resolve_dependencies_pipeline_integration_misc(self):
        pipeline_name = "resolve_dependencies"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "manifests" / "requirements.txt"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)
        self.assertEqual(1, project1.discoveredpackages.count())

    @mock.patch("scanpipe.pipes.resolve.resolve_dependencies")
    def test_scanpipe_resolve_dependencies_pipeline_pypi_integration(
        self, resolve_dependencies
    ):
        pipeline_name = "resolve_dependencies"
        project1 = Project.objects.create(name="Analysis")

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        project1.move_input_from(tempfile.mkstemp(suffix="requirements.txt")[1])
        resolve_dependencies.return_value = mock.Mock(packages=[package_data1])
        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(1, project1.discoveredpackages.count())
        discoveredpackage = project1.discoveredpackages.get()
        exclude_fields = ["qualifiers", "release_date", "size"]
        for field_name, value in package_data1.items():
            if value and field_name not in exclude_fields:
                self.assertEqual(value, getattr(discoveredpackage, field_name))

    def test_scanpipe_load_sbom_pipeline_aboutfile_integration(self):
        pipeline_name = "load_sbom"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "manifests" / "Django-4.0.8-py3-none-any.whl.ABOUT"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(1, project1.discoveredpackages.count())
        discoveredpackage = project1.discoveredpackages.get()
        self.assertEqual("pypi", discoveredpackage.type)
        self.assertEqual("django", discoveredpackage.name)
        self.assertEqual("4.0.8", discoveredpackage.version)
        self.assertEqual("bsd-new", discoveredpackage.declared_license_expression)

    def test_scanpipe_load_sbom_pipeline_spdx_integration(self):
        pipeline_name = "load_sbom"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "manifests" / "toml.spdx.json"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(1, project1.discoveredpackages.count())
        discoveredpackage = project1.discoveredpackages.get()
        self.assertEqual("pypi", discoveredpackage.type)
        self.assertEqual("toml", discoveredpackage.name)
        self.assertEqual("0.10.2", discoveredpackage.version)
        self.assertEqual("https://github.com/uiri/toml", discoveredpackage.homepage_url)
        self.assertEqual("MIT", discoveredpackage.extracted_license_statement)
        self.assertEqual("mit", discoveredpackage.declared_license_expression)

    def test_scanpipe_load_sbom_pipeline_cyclonedx_integration(self):
        pipeline_name = "load_sbom"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "cyclonedx" / "nested.cdx.json"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(3, project1.discoveredpackages.count())
        packages = project1.discoveredpackages.all()
        expected_data = {
            "pkg:pypi/toml@0.10.2?extension=tar.gz": {
                "type": "pypi",
                "name": "toml",
                "version": "0.10.2",
                "extracted_license_statement": "OFL-1.1\nApache-2.0",
                "declared_license_expression": "ofl-1.1 OR apache-2.0",
                "homepage_url": "https://cyclonedx.org/website",
                "bug_tracking_url": "https://cyclonedx.org/issue-tracker",
                "vcs_url": "https://cyclonedx.org/vcs",
                "filename": "",
            },
            "pkg:pypi/billiard@3.6.3.0": {
                "type": "pypi",
                "name": "billiard",
                "version": "3.6.3.0",
                "extracted_license_statement": "BSD-3-Clause",
                "declared_license_expression": "bsd-new",
                "homepage_url": "",
                "bug_tracking_url": "",
                "vcs_url": "",
                "extra_data": "",
                "filename": "",
            },
            "pkg:pypi/fictional@9.10.2": {
                "type": "pypi",
                "name": "fictional",
                "version": "9.10.2",
                "extracted_license_statement": (
                    "LGPL-3.0-or-later"
                    " AND "
                    "LicenseRef-scancode-openssl-exception-lgpl3.0plus"
                ),
                "declared_license_expression": (
                    "lgpl-3.0-plus AND openssl-exception-lgpl-3.0-plus"
                ),
                "homepage_url": "https://home.page",
                "bug_tracking_url": "",
                "vcs_url": "",
                "extra_data": "",
                "filename": "package.zip",
            },
        }

        for package in packages:
            expected = expected_data.get(str(package))
            self.assertEqual(expected["type"], package.type)
            self.assertEqual(expected["name"], package.name)
            self.assertEqual(expected["version"], package.version)
            self.assertEqual(expected["homepage_url"], package.homepage_url)
            self.assertEqual(
                expected["extracted_license_statement"],
                package.extracted_license_statement,
            )
            self.assertEqual(
                expected["declared_license_expression"],
                package.declared_license_expression,
            )
            self.assertEqual(expected["filename"], package.filename)

    def test_scanpipe_load_sbom_pipeline_cyclonedx_with_dependencies_integration(self):
        pipeline_name = "load_sbom"
        project1 = Project.objects.create(name="Analysis")

        input_location = self.data / "cyclonedx" / "laravel-7.12.0" / "bom.1.4.json"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(62, project1.discoveredpackages.count())
        self.assertEqual(112, project1.discovereddependencies.count())
        dependency = project1.discovereddependencies.all()[0]
        self.assertEqual("bom.1.4.json", str(dependency.datafile_resource))

    @mock.patch("scanpipe.pipes.purldb.request_post")
    @mock.patch("uuid.uuid4")
    def test_scanpipe_deploy_to_develop_pipeline_integration(
        self, mock_uuid4, mock_request
    ):
        forced_uuid = "b74fe5df-e965-415e-ba65-f38421a0695d"
        mock_uuid4.return_value = forced_uuid
        mock_request.return_value = None
        pipeline_name = "map_deploy_to_develop"
        project1 = Project.objects.create(name="Analysis", uuid=forced_uuid)

        jar_location = self.data / "d2d" / "jars"
        project1.copy_input_from(jar_location / "from-flume-ng-node-1.9.0.zip")
        project1.copy_input_from(jar_location / "to-flume-ng-node-1.9.0.zip")

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(57, project1.codebaseresources.count())
        self.assertEqual(18, project1.codebaserelations.count())
        self.assertEqual(1, project1.discoveredpackages.count())
        self.assertEqual(0, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = self.data / "d2d" / "flume-ng-node-d2d.json"
        self.assertPipelineResultEqual(expected_file, result_file)

    def test_scanpipe_deploy_to_develop_pipeline_extract_input_files_errors(self):
        project1 = Project.objects.create(name="Analysis")
        run = project1.add_pipeline("map_deploy_to_develop")
        pipeline_instance = deploy_to_develop.DeployToDevelop(run)

        # Create 2 files in the input/ directory to generate error twice
        project1.move_input_from(tempfile.mkstemp(prefix="from-")[1])
        project1.move_input_from(tempfile.mkstemp(prefix="to-")[1])
        self.assertEqual(2, len(project1.input_files))

        pipeline_instance.get_inputs()
        with mock.patch("scanpipe.pipes.scancode.extract_archive") as extract_archive:
            extract_archive.return_value = {"path/to/resource": ["error1", "error2"]}
            pipeline_instance.extract_inputs_to_codebase_directory()

        projects_errors = project1.projectmessages.all()
        self.assertEqual(2, len(projects_errors))
        project_error = projects_errors[0]
        self.assertEqual("error", project_error.severity)
        self.assertEqual("error1\nerror2", project_error.description)
        self.assertEqual("extract_archive", project_error.model)
        self.assertEqual({"filename": "resource"}, project_error.details)
        self.assertEqual("", project_error.traceback)

    @mock.patch("scanpipe.pipes.purldb.request_post")
    @mock.patch("uuid.uuid4")
    def test_scanpipe_deploy_to_develop_pipeline_with_about_file(
        self, mock_uuid4, mock_request
    ):
        forced_uuid = "90cb6382-431c-4187-be76-d4f1a2199a2f"
        mock_uuid4.return_value = forced_uuid
        mock_request.return_value = None
        pipeline_name = "map_deploy_to_develop"
        project1 = Project.objects.create(name="Analysis", uuid=forced_uuid)

        data_dir = self.data / "d2d" / "about_files"
        project1.copy_input_from(data_dir / "from-with-about-file.zip")
        project1.copy_input_from(data_dir / "to-with-jar.zip")

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertEqual(44, project1.codebaseresources.count())
        self.assertEqual(31, project1.codebaserelations.count())
        self.assertEqual(2, project1.discoveredpackages.count())
        self.assertEqual(0, project1.discovereddependencies.count())

        result_file = output.to_json(project1)
        expected_file = data_dir / "expected.json"
        self.assertPipelineResultEqual(expected_file, result_file)

        self.assertEqual(1, project1.projectmessages.count())
        message = project1.projectmessages.get()
        self.assertEqual("map_about_files", message.model)
        expected = (
            "Resource paths listed at about_resource is not found in the to/ codebase"
        )
        self.assertIn(expected, message.description)

    @mock.patch("scanpipe.pipes.purldb.request_post")
    @mock.patch("scanpipe.pipes.purldb.is_available")
    def test_scanpipe_populate_purldb_pipeline_integration(
        self, mock_is_available, mock_request_post
    ):
        pipeline_name1 = "load_inventory"
        pipeline_name2 = "populate_purldb"
        project1 = Project.objects.create(name="Utility: PurlDB")

        input_location = self.data / "asgiref" / "asgiref-3.3.0_toolkit_scan.json"
        project1.copy_input_from(input_location)

        run = project1.add_pipeline(pipeline_name1)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        def mock_request_post_return(url, data, headers, timeout):
            payload = json.loads(data)
            return {
                "queued_packages_count": len(payload["packages"]),
                "queued_packages": payload["packages"],
                "unqueued_packages_count": 1,
                "unqueued_packages": [],
                "unsupported_packages_count": 1,
                "unsupported_packages": [],
            }

        mock_request_post.side_effect = mock_request_post_return
        mock_is_available.return_value = True

        run = project1.add_pipeline(pipeline_name2)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertIn("Populating PurlDB with 2 PURLs from DiscoveredPackage", run.log)
        self.assertIn("Successfully queued 2 PURLs for indexing in PurlDB", run.log)
        self.assertIn("1 PURLs were already present in PurlDB index queue", run.log)
        self.assertIn("Couldn't index 1 unsupported PURLs", run.log)

    @mock.patch("scanpipe.pipes.purldb.request_post")
    @mock.patch("scanpipe.pipes.purldb.is_available")
    def test_scanpipe_populate_purldb_pipeline_integration_without_assembly(
        self, mock_is_available, mock_request_post
    ):
        pipeline_name = "populate_purldb"
        project1 = Project.objects.create(name="Utility: PurlDB")

        def mock_request_post_return(url, data, headers, timeout):
            payload = json.loads(data)
            return {
                "queued_packages_count": len(payload["packages"]),
                "queued_packages": payload["packages"],
                "unqueued_packages_count": 1,
                "unqueued_packages": [],
                "unsupported_packages_count": 1,
                "unsupported_packages": [],
            }

        mock_request_post.side_effect = mock_request_post_return
        mock_is_available.return_value = True

        package_json_location = self.data / "manifests" / "package.json"
        copy_input(package_json_location, project1.codebase_path)
        pipes.collect_and_create_codebase_resources(project1)

        scancode.scan_for_application_packages(project1, assemble=False)
        scancode.process_package_data(project1)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        self.assertIn("Populating PurlDB with 1 PURLs from DiscoveredPackage", run.log)
        self.assertIn(
            "Populating PurlDB with 6 unresolved PURLs from DiscoveredDependency",
            run.log,
        )
        self.assertIn("1 PURLs were already present in PurlDB index queue", run.log)
        self.assertIn("Couldn't index 1 unsupported PURLs", run.log)

    @skipIf(sys.platform == "darwin", "Not supported on macOS")
    def test_scanpipe_collect_symbols_ctags_pipeline_integration(self):
        pipeline_name = "collect_symbols_ctags"
        project1 = Project.objects.create(name="Analysis")

        dir = project1.codebase_path / "codefile"
        dir.mkdir(parents=True)

        file_location = self.data / "d2d-javascript" / "from" / "main.js"
        copy_input(file_location, dir)

        pipes.collect_and_create_codebase_resources(project1)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        main_file = project1.codebaseresources.files()[0]
        result_extra_data_symbols = main_file.extra_data.get("source_symbols")
        expected_extra_data_symbols = ["generatePassword", "passwordLength", "charSet"]
        self.assertCountEqual(expected_extra_data_symbols, result_extra_data_symbols)

    @skipIf(sys.platform != "linux", "Only supported on Linux")
    def test_scanpipe_collect_strings_gettext_pipeline_integration(self):
        pipeline_name = "collect_strings_gettext"
        project1 = Project.objects.create(name="Analysis")

        dir = project1.codebase_path / "codefile"
        dir.mkdir(parents=True)

        file_location = self.data / "d2d-javascript" / "from" / "main.js"
        copy_input(file_location, dir)

        pipes.collect_and_create_codebase_resources(project1)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        main_file = project1.codebaseresources.files()[0]
        result_extra_data_strings = main_file.extra_data.get("source_strings")
        expected_extra_data_strings = [
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_-+=",  # noqa
            "Enter the desired length of your password:",
        ]
        self.assertCountEqual(expected_extra_data_strings, result_extra_data_strings)

    @skipIf(sys.platform == "darwin", "Not supported on macOS")
    def test_scanpipe_collect_symbols_pygments_pipeline_integration(self):
        pipeline_name = "collect_symbols_pygments"
        project1 = Project.objects.create(name="Analysis")

        dir = project1.codebase_path / "codefile"
        dir.mkdir(parents=True)

        file_location = self.data / "source-inspector" / "test3.cpp"
        copy_input(file_location, dir)

        pipes.collect_and_create_codebase_resources(project1)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        main_file = project1.codebaseresources.files()[0]
        result_extra_data = main_file.extra_data

        expected_extra_data = (
            self.data / "source-inspector" / "test3.cpp-pygments-expected.json"
        )

        with open(expected_extra_data) as f:
            expected_extra_data = json.load(f)

        self.assertDictEqual(expected_extra_data, result_extra_data)

    @skipIf(sys.platform == "darwin", "Not supported on macOS")
    def test_scanpipe_collect_symbols_tree_sitter_pipeline_integration(self):
        pipeline_name = "collect_symbols_tree_sitter"
        project1 = Project.objects.create(name="Analysis")

        dir = project1.codebase_path / "codefile"
        dir.mkdir(parents=True)

        file_location = self.data / "source-inspector" / "test3.cpp"
        copy_input(file_location, dir)

        pipes.collect_and_create_codebase_resources(project1)

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        main_file = project1.codebaseresources.files()[0]
        result_extra_data = main_file.extra_data

        expected_extra_data = (
            self.data / "source-inspector" / "test3.cpp-tree-sitter-expected.json"
        )

        with open(expected_extra_data) as f:
            expected_extra_data = json.load(f)

        self.assertDictEqual(expected_extra_data, result_extra_data)

    @mock.patch("scanpipe.pipes.purldb.is_available")
    @mock.patch("scanpipe.pipes.purldb.is_configured")
    @mock.patch("scanpipe.pipes.purldb.collect_data_for_purl")
    def test_scanpipe_enrich_with_purldb_pipeline_integration(
        self, mock_collect_data, mock_is_configured, mock_is_available
    ):
        pipeline_name = "enrich_with_purldb"
        project1 = Project.objects.create(name="Analysis")
        package1 = make_package(project1, package_url="pkg:npm/csvtojson@2.0.10")

        mock_is_configured.return_value = True
        mock_is_available.return_value = True

        purldb_entry_file = self.data / "purldb" / "csvtojson-2.0.10.json"
        purldb_entry = json.loads(purldb_entry_file.read_text())
        mock_collect_data.return_value = [purldb_entry]

        run = project1.add_pipeline(pipeline_name)
        pipeline = run.make_pipeline_instance()

        exitcode, out = pipeline.execute()
        self.assertEqual(0, exitcode, msg=out)

        package1.refresh_from_db()
        self.assertTrue(package1.extra_data.get("enrich_with_purldb"))

        run.refresh_from_db()
        self.assertIn("pkg:npm/csvtojson@2.0.10 ['release_date'", run.log)
        self.assertIn("1 discovered package enriched with the PurlDB.", run.log)
