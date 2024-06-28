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
import json
import uuid
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.management import CommandError
from django.core.management import call_command
from django.core.management.base import BaseCommand
from django.test import TestCase
from django.test import override_settings
from django.utils import timezone

from scanpipe.management import commands
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredPackage
from scanpipe.models import Project
from scanpipe.models import Run
from scanpipe.pipes import purldb

scanpipe_app = apps.get_app_config("scanpipe")


def task_success(run_pk):
    run = Run.objects.get(pk=run_pk)
    run.task_exitcode = 0
    run.save()


def task_failure(run_pk):
    run = Run.objects.get(pk=run_pk)
    run.task_output = "Error log"
    run.task_exitcode = 1
    run.save()


def raise_interrupt(run_pk):
    raise KeyboardInterrupt


class ScanPipeManagementCommandTest(TestCase):
    data_location = Path(__file__).parent / "data"
    pipeline_name = "analyze_docker_image"
    pipeline_class = scanpipe_app.pipelines.get(pipeline_name)
    purldb_update_status_url = f"{purldb.PURLDB_API_URL}scan_queue/update_status/"

    def test_scanpipe_management_command_create_project_base(self):
        out = StringIO()

        expected = "Error: the following arguments are required: name"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("create-project")

        call_command("create-project", "my_project", stdout=out)
        self.assertIn("Project my_project created", out.getvalue())
        self.assertTrue(Project.objects.get(name="my_project"))

        expected = "Project with this Name already exists."
        with self.assertRaisesMessage(CommandError, expected):
            call_command("create-project", "my_project")

    def test_scanpipe_management_command_create_project_verbosity(self):
        out = StringIO()
        call_command("create-project", "my_project", verbosity=0, stdout=out)
        self.assertEqual("", out.getvalue())
        self.assertTrue(Project.objects.get(name="my_project"))

    def test_scanpipe_management_command_create_project_notes(self):
        out = StringIO()
        notes = "Some notes about my project"
        options = ["--notes", notes]

        call_command("create-project", "my_project", *options, stdout=out)
        self.assertIn("Project my_project created", out.getvalue())
        project = Project.objects.get(name="my_project")
        self.assertEqual(notes, project.notes)

    def test_scanpipe_management_command_create_project_pipelines(self):
        out = StringIO()

        options = ["--pipeline", "non-existing"]
        expected = "non-existing is not a valid pipeline"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("create-project", "my_project", *options)

        options = [
            "--pipeline",
            self.pipeline_name,
            "--pipeline",
            "analyze_root_filesystem_or_vm_image:group1,group2",
            "--pipeline",
            "scan_package",  # old name backward compatibility
        ]
        call_command("create-project", "my_project", *options, stdout=out)
        self.assertIn("Project my_project created", out.getvalue())
        project = Project.objects.get(name="my_project")
        expected = [
            self.pipeline_name,
            "analyze_root_filesystem_or_vm_image",
            "scan_single_package",
        ]
        self.assertEqual(expected, [run.pipeline_name for run in project.runs.all()])
        run = project.runs.get(pipeline_name="analyze_root_filesystem_or_vm_image")
        self.assertEqual(["group1", "group2"], run.selected_groups)

    def test_scanpipe_management_command_create_project_inputs(self):
        out = StringIO()

        options = ["--input-file", "non-existing"]
        expected = "non-existing not found or not a file"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("create-project", "my_project", *options)

        parent_path = Path(__file__).parent
        options = [
            "--input-file",
            str(parent_path / "test_commands.py"),
            "--input-file",
            str(parent_path / "test_models.py:tag"),
        ]
        call_command("create-project", "my_project", *options, stdout=out)
        self.assertIn("Project my_project created", out.getvalue())
        project = Project.objects.get(name="my_project")
        expected = sorted(["test_commands.py", "test_models.py"])
        self.assertEqual(expected, sorted(project.input_files))
        tagged_source = project.inputsources.get(filename="test_models.py")
        self.assertEqual("tag", tagged_source.tag)

    def test_scanpipe_management_command_create_project_execute(self):
        options = ["--execute"]
        expected = "The --execute option requires one or more pipelines."
        with self.assertRaisesMessage(CommandError, expected):
            call_command("create-project", "my_project", *options)

        pipeline = "load_inventory"
        options = [
            "--pipeline",
            pipeline,
            "--execute",
        ]

        out = StringIO()
        with mock.patch("scanpipe.tasks.execute_pipeline_task", task_success):
            call_command("create-project", "my_project", *options, stdout=out)

        self.assertIn("Project my_project created", out.getvalue())
        self.assertIn(f"Start the {pipeline} pipeline execution...", out.getvalue())
        self.assertIn("successfully executed on project my_project", out.getvalue())

        options.append("--async")
        out = StringIO()
        expected = "SCANCODEIO_ASYNC=False is not compatible with --async option."
        with override_settings(SCANCODEIO_ASYNC=False):
            with self.assertRaisesMessage(CommandError, expected):
                call_command("create-project", "other_project", *options, stdout=out)
        self.assertIn(
            "Project other_project created with work directory", out.getvalue()
        )

    def test_scanpipe_management_command_add_input_file(self):
        out = StringIO()

        project = Project.objects.create(name="my_project")
        parent_path = Path(__file__).parent
        options = [
            "--input-file",
            str(parent_path / "test_commands.py"),
            "--input-file",
            str(parent_path / "test_models.py:tag"),
        ]

        expected = "the following arguments are required: --project"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("add-input", *options, stdout=out)

        options.extend(["--project", project.name])
        call_command("add-input", *options, stdout=out)
        self.assertIn("Files copied to the project inputs directory", out.getvalue())
        expected = sorted(["test_commands.py", "test_models.py"])
        self.assertEqual(expected, sorted(project.input_files))
        tagged_source = project.inputsources.get(filename="test_models.py")
        self.assertEqual("tag", tagged_source.tag)

        options = ["--project", project.name, "--input-file", "non-existing.py"]
        expected = "non-existing.py not found or not a file"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("add-input", *options, stdout=out)

    @mock.patch("requests.sessions.Session.get")
    def test_scanpipe_management_command_add_input_url(self, mock_get):
        mock_get.side_effect = None
        mock_get.return_value = mock.Mock(
            content=b"\x00",
            headers={},
            status_code=200,
            url="https://example.com/archive.zip",
        )

        project = Project.objects.create(name="my_project")
        options = [
            "--input-url",
            "https://example.com/archive.zip",
            "--project",
            project.name,
        ]
        out = StringIO()
        call_command("add-input", *options, stdout=out)
        expected = "File(s) downloaded to the project inputs directory"
        self.assertIn(expected, out.getvalue())
        self.assertIn("- archive.zip", out.getvalue())
        self.assertEqual(["archive.zip"], project.input_root)

    def test_scanpipe_management_command_add_input_copy_codebase(self):
        out = StringIO()

        project = Project.objects.create(name="my_project")

        options = ["--copy-codebase", "non-existing", "--project", project.name]
        expected = "non-existing not found"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("add-input", *options)

        parent_path = Path(__file__).parent
        options = [
            "--copy-codebase",
            str(parent_path / "data" / "codebase"),
            "--project",
            project.name,
        ]

        call_command("add-input", *options, stdout=out)
        self.assertIn("content copied in", out.getvalue())

        expected = ["a.txt", "b.txt", "c.txt"]
        self.assertEqual(
            expected, sorted([path.name for path in project.codebase_path.iterdir()])
        )

    def test_scanpipe_management_command_add_pipeline(self):
        out = StringIO()

        project = Project.objects.create(name="my_project")

        pipelines = [
            self.pipeline_name,
            "analyze_root_filesystem_or_vm_image:group1,group2",
            "scan_package",  # old name backward compatibility
        ]

        options = pipelines[:]
        expected = "the following arguments are required: --project"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("add-pipeline", *options, stdout=out)

        options.extend(["--project", project.name])
        call_command("add-pipeline", *options, stdout=out)
        expected = (
            "Pipelines analyze_docker_image, analyze_root_filesystem_or_vm_image, "
            "scan_single_package added to the project"
        )
        self.assertIn(expected, out.getvalue())
        expected = [
            "analyze_docker_image",
            "analyze_root_filesystem_or_vm_image",
            "scan_single_package",
        ]
        self.assertEqual(expected, [run.pipeline_name for run in project.runs.all()])
        run = project.runs.get(pipeline_name="analyze_root_filesystem_or_vm_image")
        self.assertEqual(["group1", "group2"], run.selected_groups)

        options = ["--project", project.name, "non-existing"]
        expected = "non-existing is not a valid pipeline"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("add-pipeline", *options, stdout=out)

    def test_scanpipe_management_command_show_pipeline(self):
        pipeline_names = [
            self.pipeline_name,
            "analyze_root_filesystem_or_vm_image",
        ]

        project = Project.objects.create(name="my_project")
        for pipeline_name in pipeline_names:
            project.add_pipeline(pipeline_name)

        options = ["--project", project.name, "--no-color"]
        out = StringIO()
        call_command("show-pipeline", *options, stdout=out)
        expected = (
            " [NOT_STARTED] analyze_docker_image\n"
            " [NOT_STARTED] analyze_root_filesystem_or_vm_image\n"
        )
        self.assertEqual(expected, out.getvalue())

        project.runs.filter(pipeline_name=pipeline_names[0]).update(
            task_exitcode=0, selected_groups=["group1", "group2"]
        )
        project.runs.filter(pipeline_name=pipeline_names[1]).update(task_exitcode=1)

        out = StringIO()
        call_command("show-pipeline", *options, stdout=out)
        expected = (
            " [SUCCESS] analyze_docker_image (group1,group2)\n"
            " [FAILURE] analyze_root_filesystem_or_vm_image\n"
        )
        self.assertEqual(expected, out.getvalue())

    def test_scanpipe_management_command_execute(self):
        project = Project.objects.create(name="my_project")
        options = ["--project", project.name]

        out = StringIO()
        expected = "No pipelines to run on project my_project"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("execute", *options, stdout=out)

        out = StringIO()
        run1 = project.add_pipeline(self.pipeline_name)
        with mock.patch("scanpipe.tasks.execute_pipeline_task", task_success):
            call_command("execute", *options, stdout=out)
        expected = "Start the analyze_docker_image pipeline execution..."
        self.assertIn(expected, out.getvalue())
        expected = "successfully executed on project my_project"
        self.assertIn(expected, out.getvalue())
        run1.refresh_from_db()
        self.assertTrue(run1.task_succeeded)
        self.assertEqual("", run1.task_output)
        run1.delete()

        err = StringIO()
        run2 = project.add_pipeline(self.pipeline_name)

        expected = "Error during analyze_docker_image execution:\nError log"
        with mock.patch("scanpipe.tasks.execute_pipeline_task", task_failure):
            with self.assertRaisesMessage(CommandError, expected):
                call_command("execute", *options, stdout=out, stderr=err)
        run2.refresh_from_db()
        self.assertTrue(run2.task_failed)
        self.assertEqual("Error log", run2.task_output)
        run2.delete()

        err = StringIO()
        run3 = project.add_pipeline(self.pipeline_name)
        with mock.patch("scanpipe.tasks.execute_pipeline_task", raise_interrupt):
            with self.assertRaisesMessage(CommandError, "Pipeline execution stopped."):
                call_command("execute", *options, stdout=out, stderr=err)
        run3.refresh_from_db()
        run3 = Run.objects.get(pk=run3.pk)
        self.assertTrue(run3.task_stopped)
        self.assertEqual("", run3.task_output)

    def test_scanpipe_management_command_execute_project_function(self):
        project = Project.objects.create(name="my_project")

        expected = "No pipelines to run on project my_project"
        with self.assertRaisesMessage(CommandError, expected):
            commands.execute_project(project)

        run1 = project.add_pipeline(self.pipeline_name)
        with mock.patch("scanpipe.tasks.execute_pipeline_task", task_success):
            returned_value = commands.execute_project(project, run_async=False)
        self.assertIsNone(returned_value)
        run1.refresh_from_db()
        self.assertTrue(run1.task_succeeded)
        run1.delete()

        project.add_pipeline(self.pipeline_name)
        expected = "SCANCODEIO_ASYNC=False is not compatible with --async option."
        with override_settings(SCANCODEIO_ASYNC=False):
            with self.assertRaisesMessage(CommandError, expected):
                commands.execute_project(project, run_async=True)

        with override_settings(SCANCODEIO_ASYNC=True):
            with mock.patch("scanpipe.models.Run.start") as mock_start:
                returned_value = commands.execute_project(project, run_async=True)
                mock_start.assert_called_once()
        self.assertIsNone(returned_value)

    def test_scanpipe_management_command_status(self):
        project = Project.objects.create(name="my_project")
        run = project.add_pipeline(self.pipeline_name)

        options = ["--project", project.name, "--no-color"]
        out = StringIO()
        call_command("status", *options, stdout=out)

        output = out.getvalue()
        self.assertIn("my_project", output)
        self.assertIn("- CodebaseResource: 0", output)
        self.assertIn("- DiscoveredPackage: 0", output)
        self.assertIn("- ProjectMessage: 0", output)
        self.assertIn("[NOT_STARTED] analyze_docker_image", output)

        run.task_id = uuid.uuid4()
        run.save()
        out = StringIO()
        call_command("status", *options, stdout=out)
        output = out.getvalue()
        self.assertIn("[QUEUED] analyze_docker_image", output)

        run.task_start_date = timezone.now()
        run.log = (
            "[1611839665826870/start/1 (pid 65890)] Task finished successfully.\n"
            "[1611839665826870/extract_images/2 (pid 65914)] Task is starting.\n"
        )
        run.save()
        out = StringIO()
        call_command("status", *options, stdout=out)

        output = out.getvalue()
        self.assertIn("[RUNNING] analyze_docker_image", output)
        for line in run.log.splitlines():
            self.assertIn(line, output)

        run.task_end_date = run.task_start_date + datetime.timedelta(0, 42)
        run.task_exitcode = 0
        run.save()
        out = StringIO()
        call_command("status", *options, stdout=out)
        output = out.getvalue()
        expected = (
            f"[SUCCESS] analyze_docker_image (executed in {run.execution_time} seconds)"
        )
        self.assertIn(expected, output)

    def test_scanpipe_management_command_list_project(self):
        project1 = Project.objects.create(name="project1")
        project2 = Project.objects.create(name="project2")
        project3 = Project.objects.create(name="archived", is_archived=True)

        options = []
        out = StringIO()
        call_command("list-project", *options, stdout=out)
        output = out.getvalue()
        self.assertIn(project1.name, output)
        self.assertIn(project2.name, output)
        self.assertNotIn(project3.name, output)

        options = ["--search", project2.name]
        out = StringIO()
        call_command("list-project", *options, stdout=out)
        output = out.getvalue()
        self.assertNotIn(project1.name, output)
        self.assertIn(project2.name, output)
        self.assertNotIn(project3.name, output)

        options = ["--include-archived"]
        out = StringIO()
        call_command("list-project", *options, stdout=out)
        output = out.getvalue()
        self.assertIn(project1.name, output)
        self.assertIn(project2.name, output)
        self.assertIn(project3.name, output)

    def test_scanpipe_management_command_output(self):
        project = Project.objects.create(name="my_project")

        out = StringIO()
        options = ["--project", project.name, "--no-color"]
        call_command("output", *options, stdout=out)
        out_value = out.getvalue().strip()
        self.assertTrue(out_value.endswith(".json"))
        filename = out_value.split("/")[-1]
        self.assertIn(filename, project.output_root)

        out = StringIO()
        options = ["--project", project.name, "--no-color"]
        options.extend(["--format", "csv"])
        call_command("output", *options, stdout=out)
        out_value = out.getvalue().strip()
        for output_file in out_value.splitlines():
            filename = output_file.split("/")[-1]
            self.assertIn(filename, project.output_root)

        out = StringIO()
        options = ["--project", project.name, "--no-color"]
        options.extend(["--format", "spdx", "xlsx"])
        call_command("output", *options, stdout=out)
        out_value = out.getvalue().strip()
        for output_file in out_value.splitlines():
            filename = output_file.split("/")[-1]
            self.assertIn(filename, project.output_root)

        out = StringIO()
        options = ["--project", project.name, "--no-color"]
        options.extend(["--format", "WRONG"])
        message = (
            "Error: argument --format: invalid choice: 'WRONG' "
            "(choose from 'json', 'csv', 'xlsx', 'spdx', 'cyclonedx', 'attribution')"
        )
        with self.assertRaisesMessage(CommandError, message):
            call_command("output", *options, stdout=out)

        out = StringIO()
        options = ["--project", project.name, "--no-color"]
        options.extend(["--format", "xlsx", "--print"])
        message = "--print is not compatible with xlsx and csv formats."
        with self.assertRaisesMessage(CommandError, message):
            call_command("output", *options, stdout=out)

        out = StringIO()
        options = ["--project", project.name, "--no-color"]
        options.extend(["--format", "json", "--print"])
        call_command("output", *options, stdout=out)
        out_value = out.getvalue().strip()
        self.assertIn('"tool_name": "scanpipe"', out_value)
        self.assertIn('"notice": "Generated with ScanCode.io', out_value)

    def test_scanpipe_management_command_delete_project(self):
        project = Project.objects.create(name="my_project")
        work_path = project.work_path
        self.assertTrue(work_path.exists())

        out = StringIO()
        options = ["--project", project.name, "--no-color", "--no-input"]
        call_command("delete-project", *options, stdout=out)
        out_value = out.getvalue().strip()

        expected = "All the my_project project data have been removed."
        self.assertEqual(expected, out_value)

        self.assertFalse(Project.objects.filter(name="my_project").exists())
        self.assertFalse(work_path.exists())

    def test_scanpipe_management_command_archive_project(self):
        project = Project.objects.create(name="my_project")
        (project.input_path / "input_file").touch()
        (project.codebase_path / "codebase_file").touch()
        self.assertEqual(1, len(Project.get_root_content(project.input_path)))
        self.assertEqual(1, len(Project.get_root_content(project.codebase_path)))

        out = StringIO()
        options = [
            "--project",
            project.name,
            "--remove-codebase",
            "--no-color",
            "--no-input",
        ]
        call_command("archive-project", *options, stdout=out)
        out_value = out.getvalue().strip()

        project.refresh_from_db()
        self.assertTrue(project.is_archived)

        expected = "The my_project project has been archived."
        self.assertEqual(expected, out_value)

        self.assertEqual(1, len(Project.get_root_content(project.input_path)))
        self.assertEqual(0, len(Project.get_root_content(project.codebase_path)))

    def test_scanpipe_management_command_reset_project(self):
        project = Project.objects.create(name="my_project")
        project.add_pipeline("analyze_docker_image")
        CodebaseResource.objects.create(project=project, path="filename.ext")
        DiscoveredPackage.objects.create(project=project)

        self.assertEqual(1, project.runs.count())
        self.assertEqual(1, project.codebaseresources.count())
        self.assertEqual(1, project.discoveredpackages.count())

        (project.input_path / "input_file").touch()
        (project.codebase_path / "codebase_file").touch()
        self.assertEqual(1, len(Project.get_root_content(project.input_path)))
        self.assertEqual(1, len(Project.get_root_content(project.codebase_path)))

        out = StringIO()
        options = [
            "--project",
            project.name,
            "--no-color",
            "--no-input",
        ]
        call_command("reset-project", *options, stdout=out)
        out_value = out.getvalue().strip()

        expected = (
            "All data, except inputs, for the my_project project have been removed."
        )
        self.assertEqual(expected, out_value)

        self.assertEqual(0, project.runs.count())
        self.assertEqual(0, project.codebaseresources.count())
        self.assertEqual(0, project.discoveredpackages.count())
        self.assertEqual(1, len(Project.get_root_content(project.input_path)))
        self.assertEqual(0, len(Project.get_root_content(project.codebase_path)))

    def test_scanpipe_management_command_create_user(self):
        out = StringIO()

        expected = "Error: the following arguments are required: username"
        with self.assertRaisesMessage(CommandError, expected):
            call_command("create-user", "--no-input")

        username = "my_username"
        call_command("create-user", "--no-input", username, stdout=out)
        self.assertIn(f"User {username} created with API key:", out.getvalue())
        user = get_user_model().objects.get(username=username)
        self.assertTrue(user.auth_token)

        expected = "Error: That username is already taken."
        with self.assertRaisesMessage(CommandError, expected):
            call_command("create-user", "--no-input", username)

        username = "^&*"
        expected = (
            "Enter a valid username. This value may contain only letters, numbers, "
            "and @/./+/-/_ characters."
        )
        with self.assertRaisesMessage(CommandError, expected):
            call_command("create-user", "--no-input", username)

    def test_scanpipe_management_command_run(self):
        expected = (
            "Error: the following arguments are required: pipelines, input_location"
        )
        with self.assertRaisesMessage(CommandError, expected):
            call_command("run")

        expected = "wrong_pipeline is not a valid pipeline."
        with self.assertRaisesMessage(CommandError, expected):
            call_command("run", "wrong_pipeline", str(self.data_location))

        expected = "bad_location not found."
        with self.assertRaisesMessage(CommandError, expected):
            call_command("run", "scan_single_package", "bad_location")

        out = StringIO()
        input_location = self.data_location / "codebase"
        with redirect_stdout(out):
            call_command("run", "inspect_packages", input_location)

        json_data = json.loads(out.getvalue())
        self.assertEqual(3, len(json_data["files"]))

    @mock.patch("scanpipe.models.Project.get_latest_output")
    @mock.patch("scanpipe.pipes.purldb.request_post")
    @mock.patch("requests.sessions.Session.get")
    @mock.patch("scanpipe.pipes.purldb.request_get")
    def test_scanpipe_management_command_purldb_scan_queue_worker(
        self,
        mock_request_get,
        mock_download_get,
        mock_request_post,
        mock_get_latest_output,
    ):
        scannable_uri_uuid = "97627c6e-9acb-43e0-b8df-28bd92f2b7e5"
        download_url = "https://registry.npmjs.org/asdf/-/asdf-1.2.2.tgz"
        mock_request_get.return_value = {
            "scannable_uri_uuid": scannable_uri_uuid,
            "download_url": download_url,
            "pipelines": ["scan_single_package"],
        }
        mock_request_post.return_value = {
            "status": f"scan indexed for scannable uri {scannable_uri_uuid}"
        }
        mock_get_latest_output.return_value = (
            self.data_location / "scancode" / "is-npm-1.0.0_summary.json"
        )
        mock_download_get.return_value = mock.Mock(
            content=b"\x00",
            headers={},
            status_code=200,
            url=download_url,
        )

        options = [
            "--max-loops",
            1,
        ]
        out = StringIO()
        with mock.patch("scanpipe.tasks.execute_pipeline_task", task_success):
            call_command("purldb-scan-worker", *options, stdout=out)

        out_value = out.getvalue()
        self.assertIn(
            "Project httpsregistrynpmjsorgasdf-asdf-122tgz-97627c6e created", out_value
        )
        self.assertIn("File(s) downloaded to the project inputs directory:", out_value)
        self.assertIn("asdf-1.2.2.tgz", out_value)
        self.assertIn(
            "scan_single_package successfully executed on project "
            "httpsregistrynpmjsorgasdf-asdf-122tgz-97627c6e",
            out_value,
        )

        project_name = purldb.create_project_name(download_url, scannable_uri_uuid)
        project = Project.objects.get(name=project_name)
        self.assertEqual(scannable_uri_uuid, project.extra_data["scannable_uri_uuid"])

    @mock.patch("scanpipe.pipes.purldb.request_post")
    @mock.patch("requests.sessions.Session.get")
    @mock.patch("scanpipe.pipes.purldb.request_get")
    def test_scanpipe_management_command_purldb_scan_queue_worker_failure(
        self, mock_request_get, mock_download_get, mock_request_post
    ):
        download_url = "https://registry.npmjs.org/asdf/-/asdf-1.2.2.tgz"
        scannable_uri_uuid = "97627c6e-9acb-43e0-b8df-28bd92f2b7e5"
        mock_request_get.return_value = {
            "scannable_uri_uuid": scannable_uri_uuid,
            "download_url": download_url,
            "pipelines": ["scan_single_package"],
        }
        mock_request_post.return_value = {
            "status": f"scan failed for scannable uri {scannable_uri_uuid}"
        }
        mock_download_get.return_value = mock.Mock(
            content=b"\x00",
            headers={},
            status_code=200,
            url=download_url,
        )

        options = [
            "--max-loops",
            1,
        ]
        out = StringIO()
        with mock.patch("scanpipe.tasks.execute_pipeline_task", task_failure):
            call_command("purldb-scan-worker", *options, stdout=out, stderr=out)

        out_value = out.getvalue()
        self.assertIn("Exception occured during scan project:", out_value)
        self.assertIn("Error during scan_single_package execution:", out_value)
        self.assertIn("Error log", out_value)

        mock_request_post.assert_called_once()
        mock_request_post_call = mock_request_post.mock_calls[0]
        mock_request_post_call_kwargs = mock_request_post_call.kwargs
        self.assertEqual(
            self.purldb_update_status_url, mock_request_post_call_kwargs["url"]
        )
        self.assertEqual(
            "97627c6e-9acb-43e0-b8df-28bd92f2b7e5",
            mock_request_post_call_kwargs["data"]["scannable_uri_uuid"],
        )
        self.assertEqual("failed", mock_request_post_call_kwargs["data"]["scan_status"])
        self.assertIn(
            "Exception occured during scan project:",
            mock_request_post_call_kwargs["data"]["scan_log"],
        )

    @mock.patch("scanpipe.pipes.purldb.request_post")
    @mock.patch("requests.sessions.Session.get")
    @mock.patch("scanpipe.pipes.purldb.request_get")
    def test_scanpipe_management_command_purldb_scan_queue_worker_continue_after_fail(
        self, mock_request_get, mock_download_get, mock_request_post
    ):
        scannable_uri_uuid1 = "97627c6e-9acb-43e0-b8df-28bd92f2b7e5"
        scannable_uri_uuid2 = "0bbdcf88-ad07-4970-9272-7d5f4c82cc7b"
        download_url1 = "https://registry.npmjs.org/asdf/-/asdf-1.2.2.tgz"
        download_url2 = "https://registry.npmjs.org/asdf/-/asdf-1.2.1.tgz"
        mock_request_get.side_effect = [
            {
                "scannable_uri_uuid": scannable_uri_uuid1,
                "download_url": download_url1,
                "pipelines": ["scan_single_package"],
            },
            {
                "scannable_uri_uuid": scannable_uri_uuid2,
                "download_url": download_url2,
                "pipelines": ["scan_single_package"],
            },
        ]

        mock_download_get.side_effect = [
            mock.Mock(
                content=b"\x00",
                headers={},
                status_code=200,
                url=download_url1,
            ),
            mock.Mock(
                content=b"\x00",
                headers={},
                status_code=200,
                url=download_url2,
            ),
        ]

        mock_request_post.side_effect = [
            {
                "status": f"updated scannable uri {scannable_uri_uuid1} "
                "scan_status to failed"
            },
            {"status": f"scan indexed for scannable uri {scannable_uri_uuid2}"},
        ]

        options = [
            "--max-loops",
            2,
        ]
        out = StringIO()
        with mock.patch("scanpipe.tasks.execute_pipeline_task", task_failure):
            call_command("purldb-scan-worker", *options, stdout=out, stderr=out)

        out_value = out.getvalue()
        self.assertIn(
            "Project httpsregistrynpmjsorgasdf-asdf-122tgz-97627c6e created", out_value
        )
        self.assertIn(
            "Project httpsregistrynpmjsorgasdf-asdf-121tgz-0bbdcf88 created", out_value
        )
        self.assertIn("- asdf-1.2.2.tgz", out_value)
        self.assertIn("- asdf-1.2.1.tgz", out_value)
        self.assertIn("Exception occured during scan project:", out_value)
        self.assertIn("Error during scan_single_package execution:", out_value)
        self.assertIn("Error log", out_value)

        update_status_url = f"{purldb.PURLDB_API_URL}scan_queue/update_status/"
        mocked_post_calls = mock_request_post.call_args_list
        self.assertEqual(2, len(mocked_post_calls))

        mock_post_call1 = mocked_post_calls[0]
        self.assertEqual(update_status_url, mock_post_call1.kwargs["url"])
        self.assertEqual(
            "97627c6e-9acb-43e0-b8df-28bd92f2b7e5",
            mock_post_call1.kwargs["data"]["scannable_uri_uuid"],
        )
        self.assertEqual("failed", mock_post_call1.kwargs["data"]["scan_status"])
        self.assertIn(
            "Exception occured during scan project:",
            mock_post_call1.kwargs["data"]["scan_log"],
        )

        mock_post_call2 = mocked_post_calls[1]
        self.assertEqual(update_status_url, mock_post_call2.kwargs["url"])
        self.assertEqual(
            "0bbdcf88-ad07-4970-9272-7d5f4c82cc7b",
            mock_post_call2.kwargs["data"]["scannable_uri_uuid"],
        )
        self.assertEqual("failed", mock_post_call1.kwargs["data"]["scan_status"])
        self.assertIn(
            "Exception occured during scan project:",
            mock_post_call2.kwargs["data"]["scan_log"],
        )


class ScanPipeManagementCommandMixinTest(TestCase):
    class CreateProjectCommand(
        commands.CreateProjectCommandMixin, commands.AddInputCommandMixin, BaseCommand
    ):
        verbosity = 0

    create_project_command = CreateProjectCommand()
    pipeline_name = "analyze_docker_image"
    pipeline_class = scanpipe_app.pipelines.get(pipeline_name)

    def test_scanpipe_management_command_mixin_create_project_base(self):
        expected = "This field cannot be blank."
        with self.assertRaisesMessage(CommandError, expected):
            self.create_project_command.create_project(name="")

        project = self.create_project_command.create_project(name="my_project")
        self.assertTrue("my_project", project.name)

        expected = "Project with this Name already exists."
        with self.assertRaisesMessage(CommandError, expected):
            self.create_project_command.create_project(name="my_project")

    def test_scanpipe_management_command_mixin_create_project_notes(self):
        notes = "Some notes about my project"
        project = self.create_project_command.create_project(
            name="my_project", notes=notes
        )
        self.assertEqual(notes, project.notes)

    def test_scanpipe_management_command_mixin_create_project_pipelines(self):
        expected = "non-existing is not a valid pipeline"
        with self.assertRaisesMessage(CommandError, expected):
            self.create_project_command.create_project(
                name="my_project", pipelines=["non-existing"]
            )

        pipelines = [
            self.pipeline_name,
            "analyze_root_filesystem_or_vm_image:group1,group2",
            "scan_package",
        ]
        project = self.create_project_command.create_project(
            name="my_project", pipelines=pipelines
        )
        expected = [
            self.pipeline_name,
            "analyze_root_filesystem_or_vm_image",
            "scan_single_package",
        ]
        self.assertEqual(expected, [run.pipeline_name for run in project.runs.all()])
        run = project.runs.get(pipeline_name="analyze_root_filesystem_or_vm_image")
        self.assertEqual(["group1", "group2"], run.selected_groups)

    def test_scanpipe_management_command_mixin_create_project_inputs(self):
        expected = "non-existing not found or not a file"
        with self.assertRaisesMessage(CommandError, expected):
            self.create_project_command.create_project(
                name="my_project", input_files=["non-existing"]
            )

        parent_path = Path(__file__).parent
        input_files = [
            str(parent_path / "test_commands.py"),
            str(parent_path / "test_models.py:tag"),
        ]
        project = self.create_project_command.create_project(
            name="my_project", input_files=input_files
        )
        expected = sorted(["test_commands.py", "test_models.py"])
        self.assertEqual(expected, sorted(project.input_files))
        tagged_source = project.inputsources.get(filename="test_models.py")
        self.assertEqual("tag", tagged_source.tag)

    def test_scanpipe_management_command_mixin_create_project_execute(self):
        expected = "The execute argument requires one or more pipelines."
        with self.assertRaisesMessage(CommandError, expected):
            self.create_project_command.create_project(name="my_project", execute=True)

        pipeline = "load_inventory"
        with mock.patch("scanpipe.tasks.execute_pipeline_task", task_success):
            project = self.create_project_command.create_project(
                name="my_project", pipelines=[pipeline], execute=True
            )
        run = project.runs.first()
        self.assertTrue(run.task_succeeded)

        expected = "SCANCODEIO_ASYNC=False is not compatible with --async option."
        with override_settings(SCANCODEIO_ASYNC=False):
            with self.assertRaisesMessage(CommandError, expected):
                self.create_project_command.create_project(
                    name="other_project",
                    pipelines=[pipeline],
                    execute=True,
                    run_async=True,
                )
