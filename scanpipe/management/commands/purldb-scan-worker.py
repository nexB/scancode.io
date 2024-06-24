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

import time
import traceback

from django.core.management.base import BaseCommand

from scanpipe.management.commands import AddInputCommandMixin
from scanpipe.management.commands import CreateProjectCommandMixin
from scanpipe.models import Run
from scanpipe.pipes import output
from scanpipe.pipes import purldb


class Command(CreateProjectCommandMixin, AddInputCommandMixin, BaseCommand):
    help = "Get a Package to be scanned from PurlDB and return the results"

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--sleep",
            type=int,
            default=0,
            action="store",
            help="Number in seconds how long the loop should sleep for before polling.",
        )

        parser.add_argument(
            "--max-loops",
            dest="max_loops",
            default=0,
            action="store",
            help="Limit the number of loops to a maximum number. "
            "0 means no limit. Used only for testing.",
        )

        parser.add_argument(
            "--max-concurrent-projects",
            dest="max_concurrent_projects",
            default=1,
            action="store",
            help="Limit the number of Projects that can be run at once.",
        )

    def handle(self, *args, **options):
        self.verbosity = options["verbosity"]
        sleep = options["sleep"]
        run_async = options["async"]
        max_loops = int(options["max_loops"])
        max_concurrent_projects = int(options["max_concurrent_projects"])

        loop_count = 0
        while True:
            if max_loops and loop_count >= max_loops:
                self.stdout.write("loop max reached")
                break

            time.sleep(sleep)
            loop_count += 1

            # Usually, a worker can only run one Run at a time
            queued_and_running = Run.objects.filter(
                status__in=[Run.Status.QUEUED, Run.Status.RUNNING]
            )
            if queued_and_running.count() > max_concurrent_projects:
                continue

            # 1. Get download url from purldb
            response = purldb.get_next_download_url()
            if response:
                scannable_uri_uuid = response["scannable_uri_uuid"]
                download_url = response["download_url"]
                pipelines = response["pipelines"]
            else:
                self.stderr.write("Bad response from PurlDB: unable to get next job.")
                continue

            if not (download_url and scannable_uri_uuid):
                self.stdout.write("No new job from PurlDB.")
                continue

            try:
                # 2. Create and run project

                # Run `send_project_results` to send results back to PurlDB
                # after all the pipelines have been run.
                pipelines.append("send_project_results")

                project = create_scan_project(
                    command=self,
                    scannable_uri_uuid=scannable_uri_uuid,
                    download_url=download_url,
                    pipelines=pipelines,
                    run_async=run_async,
                )

                self.stdout.write(
                    f"Project {project.name} has been created",
                    self.style.SUCCESS,
                )

            except Exception:
                tb = traceback.format_exc()
                error_log = f"Exception occured during scan project:\n\n{tb}"
                purldb.update_status(
                    scannable_uri_uuid,
                    status="failed",
                    scan_log=error_log,
                )
                self.stderr.write(error_log)


def create_scan_project(
    command, scannable_uri_uuid, download_url, pipelines, run_async=False
):
    """
    Create and return a Project for the scan project request with ID of
    `scannable_uri_uuid`, where the target at `download_url` is fetched, and the
    pipelines from `pipelines` is then run.

    If `run_async` is True, the pipelines on the Project is run in a separate
    thread.
    """
    name = purldb.create_project_name(download_url, scannable_uri_uuid)
    input_urls = [download_url]
    project = command.create_project(
        name=name,
        pipelines=pipelines,
        input_urls=input_urls,
        execute=True,
        run_async=run_async,
    )
    project.update_extra_data({"scannable_uri_uuid": scannable_uri_uuid})
    return project


def send_scan_project_results(project, scannable_uri_uuid):
    """
    Send the JSON summary and results of `project` to PurlDB for the scan
    request `scannable_uri_uuid`.

    Raise a PurlDBException if there is an issue sending results to PurlDB.
    """
    project.refresh_from_db()
    scan_results_location = output.to_json(project)
    scan_summary_location = project.get_latest_output(filename="summary")
    response = purldb.send_results_to_purldb(
        scannable_uri_uuid,
        scan_results_location,
        scan_summary_location,
        project.extra_data,
    )
    if not response:
        raise purldb.PurlDBException(
            "Bad response returned when sending results to PurlDB"
        )
