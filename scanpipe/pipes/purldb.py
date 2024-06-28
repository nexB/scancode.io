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
import logging

from django.conf import settings
from django.utils.text import slugify

import requests
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import InvalidVersionRange

from scanpipe.pipes import LoopProgress
from scanpipe.pipes import output


class PurlDBException(Exception):
    pass


label = "PurlDB"
logger = logging.getLogger(__name__)
session = requests.Session()


# Only PURLDB_URL can be provided through setting
PURLDB_API_URL = None
PURLDB_URL = settings.PURLDB_URL
if PURLDB_URL:
    PURLDB_API_URL = f'{PURLDB_URL.rstrip("/")}/api/'

# Basic Authentication
PURLDB_USER = settings.PURLDB_USER
PURLDB_PASSWORD = settings.PURLDB_PASSWORD
basic_auth_enabled = PURLDB_USER and PURLDB_PASSWORD
if basic_auth_enabled:
    session.auth = (PURLDB_USER, PURLDB_PASSWORD)

# Authentication with single API key
PURLDB_API_KEY = settings.PURLDB_API_KEY
if PURLDB_API_KEY:
    session.headers.update({"Authorization": f"Token {PURLDB_API_KEY}"})

DEFAULT_TIMEOUT = 60


def is_configured():
    """Return True if the required PurlDB settings have been set."""
    if PURLDB_API_URL:
        return True
    return False


def is_available():
    """Return True if the configured PurlDB server is available."""
    if not is_configured():
        return False

    try:
        response = session.head(PURLDB_API_URL)
        response.raise_for_status()
    except requests.exceptions.RequestException as request_exception:
        logger.debug(f"{label} is_available() error: {request_exception}")
        return False

    return response.status_code == requests.codes.ok


def request_get(url, payload=None, timeout=DEFAULT_TIMEOUT):
    """Wrap the HTTP request calls on the API."""
    if not url:
        return

    params = {}
    if "format=json" not in url:
        params.update({"format": "json"})
    if payload:
        params.update(payload)

    logger.debug(f"{label}: url={url} params={params}")
    try:
        response = session.get(url, params=params, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError, TypeError) as exception:
        logger.debug(f"{label} [Exception] {exception}")


def request_post(url, data=None, headers=None, files=None, timeout=DEFAULT_TIMEOUT):
    try:
        response = session.post(
            url, data=data, timeout=timeout, headers=headers, files=files
        )
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError, TypeError) as exception:
        logger.debug(f"{label} [Exception] {exception}")


def collect_response_results(response, data, timeout=DEFAULT_TIMEOUT):
    """Return all results from a purldb API response."""
    results = []
    if response and response.get("count"):
        results.extend(response["results"])
        next_page = response.get("next")
        while next_page:
            response = request_post(url=next_page, data=data, timeout=timeout)
            if response and response.get("count"):
                results.extend(response["results"])
                next_page = response.get("next")
    return results


def match_packages(
    sha1_list,
    enhance_package_data=False,
    timeout=DEFAULT_TIMEOUT,
    api_url=PURLDB_API_URL,
):
    """
    Match a list of SHA1 in the PurlDB for package-type files.

    If `enhance_package_data` is True, then purldb will enhance Package data for
    matched Packages, if possible.
    """
    data = {
        "sha1": sha1_list,
        "enhance_package_data": enhance_package_data,
    }
    response = request_post(
        url=f"{api_url}packages/filter_by_checksums/", data=data, timeout=timeout
    )

    packages = collect_response_results(response, data=data, timeout=timeout)
    return packages


def match_resources(sha1_list, timeout=DEFAULT_TIMEOUT, api_url=PURLDB_API_URL):
    """Match a list of SHA1 in the PurlDB for resource files."""
    data = {"sha1": sha1_list}
    response = request_post(
        url=f"{api_url}resources/filter_by_checksums/", data=data, timeout=timeout
    )

    resources = collect_response_results(response, data=data, timeout=timeout)
    return resources


def match_directory(fingerprint, timeout=DEFAULT_TIMEOUT, api_url=PURLDB_API_URL):
    """
    Match directory content fingerprint in the PurlDB for a single directory
    resource.
    """
    payload = {"fingerprint": fingerprint}
    response = request_get(
        url=f"{api_url}approximate_directory_content_index/match/",
        payload=payload,
        timeout=timeout,
    )

    if response and len(response) > 0:
        return response


def submit_purls(packages, timeout=DEFAULT_TIMEOUT, api_url=PURLDB_API_URL):
    """
    Submit list of dict where each dict has either resolved PURL i.e. PURL with
    version or version-less PURL along with vers range to PurlDB for indexing.
    """
    payload = {"packages": packages}
    headers = {"Content-Type": "application/json"}
    data = json.dumps(payload)

    response = request_post(
        url=f"{api_url}collect/index_packages/",
        data=data,
        timeout=timeout,
        headers=headers,
    )

    return response


def feed_purldb(packages, chunk_size, logger=logger.info):
    """Feed PurlDB with list of PURLs for indexing."""
    if not is_available():
        raise Exception("PurlDB is not available.")

    if not packages:
        logger("No PURLs found. Skipping.")
        return

    package_batches = [
        packages[i : i + chunk_size] for i in range(0, len(packages), chunk_size)
    ]

    batches_count = len(package_batches)
    queued_packages_count = 0
    unqueued_packages_count = 0
    unsupported_packages_count = 0
    unsupported_vers_count = 0

    progress = LoopProgress(batches_count, logger)

    for batch in progress.iter(package_batches):
        if response := submit_purls(packages=batch):
            queued_packages_count += response.get("queued_packages_count", 0)
            unqueued_packages_count += response.get("unqueued_packages_count", 0)
            unsupported_packages_count += response.get("unsupported_packages_count", 0)
            unsupported_vers_count += response.get("unsupported_vers_count", 0)

    if queued_packages_count > 0:
        logger(
            f"Successfully queued {queued_packages_count:,d} "
            f"PURLs for indexing in PurlDB"
        )

    if unqueued_packages_count > 0:
        logger(
            f"{unqueued_packages_count:,d} PURLs were already "
            f"present in PurlDB index queue"
        )

    if unsupported_packages_count > 0:
        logger(f"Couldn't index {unsupported_packages_count:,d} unsupported PURLs")

    if unsupported_vers_count > 0:
        logger(f"Couldn't index {unsupported_vers_count:,d} unsupported vers")


def get_unique_resolved_purls(project):
    """Return PURLs from project's resolved DiscoveredDependencies."""
    packages_resolved = project.discovereddependencies.filter(is_resolved=True)

    distinct_results = packages_resolved.values("type", "namespace", "name", "version")

    distinct_combinations = {tuple(item.values()) for item in distinct_results}
    return {str(PackageURL(*values)) for values in distinct_combinations}


def get_unique_unresolved_purls(project):
    """Return PURLs from project's unresolved DiscoveredDependencies."""
    packages_unresolved = project.discovereddependencies.filter(
        is_resolved=False
    ).exclude(extracted_requirement="*")

    distinct_unresolved_results = packages_unresolved.values(
        "type", "namespace", "name", "extracted_requirement"
    )

    distinct_unresolved = {tuple(item.values()) for item in distinct_unresolved_results}

    packages = set()
    for item in distinct_unresolved:
        pkg_type, namespace, name, extracted_requirement = item
        if range_class := RANGE_CLASS_BY_SCHEMES.get(pkg_type):
            try:
                vers = range_class.from_native(extracted_requirement)
            except InvalidVersionRange:
                continue

            if not vers.constraints:
                continue

            purl = PackageURL(type=pkg_type, namespace=namespace, name=name)
            packages.add((str(purl), str(vers)))

    return packages


def populate_purldb_with_discovered_packages(project, logger=logger.info):
    """Add DiscoveredPackage to PurlDB."""
    discoveredpackages = project.discoveredpackages.all()
    packages_to_populate = []
    for pkg in discoveredpackages:
        package = {"purl": pkg.purl}
        if pkg.source_packages:
            package["source_purl"] = pkg.source_packages
        packages_to_populate.append(package)

    logger(
        f"Populating PurlDB with {len(packages_to_populate):,d}"
        f" PURLs from DiscoveredPackage"
    )
    feed_purldb(
        packages=packages_to_populate,
        chunk_size=100,
        logger=logger,
    )


def populate_purldb_with_discovered_dependencies(project, logger=logger.info):
    """Add DiscoveredDependency to PurlDB."""
    packages = [{"purl": purl} for purl in get_unique_resolved_purls(project)]

    logger(
        f"Populating PurlDB with {len(packages):,d} " "PURLs from DiscoveredDependency"
    )
    feed_purldb(
        packages=packages,
        chunk_size=100,
        logger=logger,
    )

    unresolved_packages = get_unique_unresolved_purls(project)
    unresolved_packages = [
        {"purl": purl, "vers": vers} for purl, vers in unresolved_packages
    ]

    logger(
        f"Populating PurlDB with {len(unresolved_packages):,d}"
        " unresolved PURLs from DiscoveredDependency"
    )
    feed_purldb(
        packages=unresolved_packages,
        chunk_size=10,
        logger=logger,
    )


def get_package_by_purl(package_url):
    """Get a Package details entry providing its `package_url`."""
    if results := find_packages({"purl": str(package_url)}):
        return results[0]


def find_packages(payload):
    """Get Packages using provided `payload` filters on the PurlDB package list."""
    package_api_url = f"{PURLDB_API_URL}packages/"
    response = request_get(package_api_url, payload=payload)
    if response and response.get("count") > 0:
        return response.get("results")


def get_next_download_url(timeout=DEFAULT_TIMEOUT, api_url=PURLDB_API_URL):
    """
    Return the ScannableURI UUID, download URL, and pipelines for the next
    Package to be scanned from PurlDB

    Return None if the request was not successful
    """
    response = request_get(
        url=f"{api_url}scan_queue/get_next_download_url/",
        timeout=timeout,
    )
    if response:
        return response


def send_results_to_purldb(
    scannable_uri_uuid,
    scan_results_location,
    scan_summary_location,
    project_extra_data,
    timeout=DEFAULT_TIMEOUT,
    api_url=PURLDB_API_URL,
):
    """
    Send project results to purldb for the package handeled by the ScannableURI
    with uuid of `scannable_uri_uuid`
    """
    with open(scan_results_location, "rb") as scan_results_file:
        with open(scan_summary_location, "rb") as scan_summary_file:
            data = {
                "scannable_uri_uuid": scannable_uri_uuid,
                "scan_status": "scanned",
                "project_extra_data": json.dumps(project_extra_data),
            }
            files = {
                "scan_results_file": scan_results_file,
                "scan_summary_file": scan_summary_file,
            }
            response = request_post(
                url=f"{api_url}scan_queue/update_status/",
                timeout=timeout,
                data=data,
                files=files,
            )
    return response


def update_status(
    scannable_uri_uuid,
    status,
    scan_log="",
    timeout=DEFAULT_TIMEOUT,
    api_url=PURLDB_API_URL,
):
    """Update the status of a ScannableURI on a PurlDB scan queue"""
    data = {
        "scannable_uri_uuid": scannable_uri_uuid,
        "scan_status": status,
        "scan_log": scan_log,
    }
    response = request_post(
        url=f"{api_url}scan_queue/update_status/",
        timeout=timeout,
        data=data,
    )
    return response


def create_project_name(download_url, scannable_uri_uuid):
    """Create a project name from `download_url` and `scannable_uri_uuid`"""
    if len(download_url) > 50:
        download_url = download_url[0:50]
    return f"{slugify(download_url)}-{scannable_uri_uuid[0:8]}"


def check_project_run_statuses(project, logger=None):
    """
    If any of the runs of this Project has failed, update the status of the
    Scannable URI associated with this Project to `failed` and send back a
    log of the failed runs.
    """
    from scanpipe.models import AbstractTaskFieldsModel

    run_status = AbstractTaskFieldsModel.Status
    failed_runs = project.runs.filter(status=run_status.FAILURE)
    if failed_runs:
        failure_msgs = []
        for failed_run in failed_runs:
            msg = f"{failed_run.pipeline_name} failed:\n\n{failed_run.log}\n"
            failure_msgs.append(msg)
        failure_msg = "\n".join(failure_msgs)

        if logger:
            logger(failure_msg)

        scannable_uri_uuid = project.extra_data.get("scannable_uri_uuid")
        update_status(
            scannable_uri_uuid=scannable_uri_uuid,
            status="failed",
            scan_log=failure_msg,
        )


def send_project_results(project, logger=None):
    """
    Send the JSON summary and results of `project` to PurlDB for the scan
    request `scannable_uri_uuid`.

    Raise a PurlDBException if there is an issue sending results to PurlDB.
    """
    scan_results_location = output.to_json(project)
    scan_summary_location = project.get_latest_output(filename="summary")
    scannable_uri_uuid = project.extra_data.get("scannable_uri_uuid")
    response = send_results_to_purldb(
        scannable_uri_uuid,
        scan_results_location,
        scan_summary_location,
        project.extra_data,
    )

    if not response:
        raise PurlDBException(
            "Bad response returned when sending results to PurlDB"
        )

    if logger:
        logger("Scan results and other data have been sent to PurlDB")
