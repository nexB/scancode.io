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

from scanpipe.models import AbstractTaskFieldsModel
from scanpipe.pipelines import Pipeline
from scanpipe.pipes import output
from scanpipe.pipes import purldb


class SendProjectResults(Pipeline):
    """
    Generate Project JSON results and send it and the scan summary back to
    PurlDB.

    This pipeline is intended to be used in the PurlDB scan worker context.
    """

    @classmethod
    def steps(cls):
        return (
            cls.check_project_run_statuses,
            cls.send_project_results,
        )

    def check_project_run_statuses(self):
        """
        If any of the runs of this Project has failed, update the status of the
        Scannable URI associated with this Project to `failed` and send back a
        log of the failed runs.
        """
        purldb.check_project_run_statuses(
            project=self.project,
            logger=self.log,
        )

    def send_project_results(self):
        """
        Send the JSON summary and results of `project` to PurlDB for the scan
        request `scannable_uri_uuid`.

        Raise a PurlDBException if there is an issue sending results to PurlDB.
        """
        purldb.send_project_results(
            project=self.project,
            logger=self.log,
        )
