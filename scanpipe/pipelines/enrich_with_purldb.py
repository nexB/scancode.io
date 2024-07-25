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

from scanpipe.pipelines import Pipeline
from scanpipe.pipes import purldb


class EnrichWithPurlDB(Pipeline):
    """Enrich the discovered packages with data available in the PurlDB."""

    download_inputs = False
    is_addon = True
    results_url = "/project/{slug}/packages/?extra_data=" + purldb.ENRICH_EXTRA_DATA_KEY

    @classmethod
    def steps(cls):
        return (
            purldb.check_service_availability,
            cls.enrich_discovered_packages_with_purldb,
        )

    def enrich_discovered_packages_with_purldb(self):
        """Lookup discovered packages in PurlDB."""
        purldb.enrich_discovered_packages(self.project, logger=self.log)
