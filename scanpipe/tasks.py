# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/aboutcode-org/scancode.io
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
# Visit https://github.com/aboutcode-org/scancode.io for support and download.

import logging

from django.apps import apps

from django_rq import job

logger = logging.getLogger(__name__)


def info(message, pk):
    logger.info(f"Run[{pk}] {message}")


def get_run_instance(run_pk):
    """Return the run instance using the `run_pk`."""
    Run = apps.get_model("scanpipe", "Run")
    return Run.objects.get(pk=run_pk)


def report_failure(job, connection, type, value, traceback):
    """
    Report a job failure as a call back when an exception is raised during the Job
    execution but was not caught by the task itself.
    """
    Run = apps.get_model("scanpipe", "Run")
    try:
        run = get_run_instance(run_pk=job.id)
    except Run.DoesNotExist:
        info(f"FAILURE to get the Run instance with job.id={job.id}", "Unknown")
        return

    run.set_task_ended(exitcode=1, output=f"value={value} trace={traceback}")


def execute_pipeline_task(run_pk):
    info(f"Enter `execute_pipeline_task` Run.pk={run_pk}", run_pk)

    run = get_run_instance(run_pk)
    project = run.project

    run.reset_task_values()
    run.set_scancodeio_version()
    run.set_task_started(run_pk)

    info(f'Run pipeline: "{run.pipeline_name}" on project: "{project.name}"', run_pk)

    pipeline = run.make_pipeline_instance()
    exitcode, output = pipeline.execute()

    info("Update Run instance with exitcode, output, and end_date", run_pk)
    run.set_task_ended(exitcode, output)

    next_run = project.get_next_run()
    run.deliver_project_subscriptions(has_next_run=bool(next_run))

    if run.task_succeeded:
        # We keep the temporary files available for debugging in case of error
        project.clear_tmp_directory()
        if next_run:
            next_run.start()


@job
def background_delete_task(project):
    # Check if the project is still marked for deletion
    if not project.is_marked_for_deletion:
        return

    try:
        project.delete()
    except Exception as e:
        info(f"Deletion failed: {str(e)}", project.pk)
        project.update(is_marked_for_deletion=True)
        project.add_error(description=f"Deletion failed: {str(e)}")
