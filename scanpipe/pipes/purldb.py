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

from django.utils.text import slugify
from scanpipe.models import AbstractTaskFieldsModel
from scanpipe.pipes import LoopProgress
from scanpipe.pipes import flag
from scanpipe.pipes.output import to_json


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


def poll_run_url_status(run_url, sleep=10):
    """
    Given a URL to a scancode.io run instance, `run_url`, return True when the
    run instance has completed successfully.

    Raise a PurlDBException when the run instance has failed, stopped, or gone
    stale.
    """
    if poll_until_success(check=get_run_url_status, sleep=sleep, run_url=run_url):
        return True
    else:
        response = request_get(run_url)
        if response:
            log = response["log"]
            msg = f"Matching run has stopped:\n\n{log}"
            raise PurlDBException(msg)


def poll_until_success(check, sleep=10, **kwargs):
    """
    Given a function `check`, which returns the status of a run, return True
    when the run instance has completed successfully.

    Return False when the run instance has failed, stopped, or gone stale.

    The arguments for `check` need to be provided as keyword argument into this
    function.
    """
    run_status = AbstractTaskFieldsModel.Status
    while True:
        status = check(**kwargs)
        if status == run_status.SUCCESS:
            return True

        if status in [
            run_status.NOT_STARTED,
            run_status.QUEUED,
            run_status.RUNNING,
        ]:
            continue

        if status in [
            run_status.FAILURE,
            run_status.STOPPED,
            run_status.STALE,
        ]:
            return False

        time.sleep(sleep)


def get_run_url_status(run_url, **kwargs):
    """
    Given a `run_url`, which is a URL to a ScanCode.io Project run, return its
    status, otherwise return None.
    """
    response = request_get(run_url)
    if response:
        status = response["status"]
        return status


def get_match_results(run_url):
    """
    Given the `run_url` for a pipeline running the matchcode matching pipeline,
    return the match results for that run.
    """
    response = request_get(run_url)
    project_url = response["project"]
    # `project_url` can have params, such as "?format=json"
    if "?" in project_url:
        project_url, _ = project_url.split("?")
    project_url = project_url.rstrip("/")
    results_url = project_url + "/results/"
    return request_get(results_url)


def map_match_results(match_results):
    """
    Given `match_results`, which is a mapping of ScanCode.io codebase results,
    return a defaultdict(list) where the keys are the package_uid of matched
    packages and the value is a list containing the paths of Resources
    associated with the package_uid.
    """
    resource_results = match_results.get("files", [])
    resource_paths_by_package_uids = defaultdict(list)
    for resource in resource_results:
        for_packages = resource.get("for_packages", [])
        for package_uid in for_packages:
            resource_paths_by_package_uids[package_uid].append(resource["path"])
    return resource_paths_by_package_uids


def create_packages_from_match_results(project, match_results):
    """
    Given `match_results`, which is a mapping of ScanCode.io codebase results,
    use the Package data from it to create DiscoveredPackages for `project` and
    associate the proper Resources of `project` to the DiscoveredPackages.
    """
    from scanpipe.pipes.d2d import create_package_from_purldb_data

    resource_paths_by_package_uids = map_match_results(match_results)
    matched_packages = match_results.get("packages", [])
    for matched_package in matched_packages:
        package_uid = matched_package["package_uid"]
        resource_paths = resource_paths_by_package_uids[package_uid]
        resources = project.codebaseresources.filter(path__in=resource_paths)
        create_package_from_purldb_data(
            project,
            resources=resources,
            package_data=matched_package,
            status=flag.MATCHED_TO_PURLDB_PACKAGE,
        )


def _get_next_job(timeout=DEFAULT_TIMEOUT, api_url=PURLDB_API_URL):
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
        scannable_uri_uuid = response["scannable_uri_uuid"]
        download_url = response["download_url"]
        pipelines = response["pipelines"]
        return scannable_uri_uuid, download_url, pipelines


def get_next_job():
    scannable_uri_uuid = download_url = pipelines = None
    msg = ""
    try:
        response = _get_next_job()
        if response:
            scannable_uri_uuid, download_url, pipelines = response
        else:
            msg = "Bad response from PurlDB, unable to get next job."
    except Exception as e:
        msg = f"Exception occured when calling `purldb.get_next_job()`:\n\n{str(e)}"
    return scannable_uri_uuid, download_url, pipelines, msg


def send_results_to_purldb(
    scannable_uri_uuid,
    scan_output_location,
    timeout=DEFAULT_TIMEOUT,
    api_url=PURLDB_API_URL,
):
    """
    Send project results to purldb for the package handeled by the ScannableURI
    with uuid of `scannable_uri_uuid`
    """
    with open(scan_output_location, "rb") as f:
        data = {
            "scannable_uri_uuid": scannable_uri_uuid,
            "scan_status": "scanned",
        }
        files = {
            "scan_file": f,
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
    scan_project_url="",
    timeout=DEFAULT_TIMEOUT,
    api_url=PURLDB_API_URL,
):
    """Update the status of a ScannableURI on a PurlDB scan queue"""
    data = {
        "scannable_uri_uuid": scannable_uri_uuid,
        "scan_status": status,
        "scan_log": scan_log,
        "scan_project_url": scan_project_url,
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


def poll_run_status(project, sleep=10):
    """
    Poll the status of all runs of `project`. Return the log of the run if
    the run has stopped, failed, or gone stale, otherwise return an empty
    string.
    """
    runs = project.runs.all()
    for run in runs:
        if not poll_until_success(check=get_run_status, sleep=sleep, run=run):
            return run.log
    return ""


def get_run_status(run, **kwargs):
    """Refresh the values of `run` and return its status"""
    run.refresh_from_db()
    return run.status
