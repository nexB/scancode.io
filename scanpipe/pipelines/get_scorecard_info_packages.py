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

from ossf_scorecard import scorecard

from scanpipe.models import PackageScore
from scanpipe.pipelines import Pipeline


class FetchScoreCodeInfo(Pipeline):
    """
    Fetch ScoreCode information for packages and dependencies.

    This pipeline retrieves ScoreCode data for each package in the project
    and stores it in the corresponding package instances.
    """

    download_inputs = False
    is_addon = True

    @classmethod
    def steps(cls):
        return (
            cls.check_scorecode_service_availability,
            cls.fetch_packages_scorecode_info,
        )

    def check_scorecode_service_availability(self):
        """Check if the scorecode service is configured and available."""
        if not scorecard.is_configured():
            raise Exception("scorecode service is not configured.")

        if not scorecard.is_available():
            raise Exception("scorecode service is not available.")

    def fetch_packages_scorecode_info(self):
        """Fetch scorecode information for each of the project's discovered packages."""
        for package in self.project.discoveredpackages.all():

            scorecard_data = scorecard.fetch_scorecard_info(package=package)

            if scorecard_data:
                PackageScore.create_from_package_and_scorecard(
                    scorecard_data=scorecard_data,
                    package=package,
                )

            else:
                #We Want to create error instead of exception
                raise Exception("No data found for the package")
