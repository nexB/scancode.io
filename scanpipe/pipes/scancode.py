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
import multiprocessing
import os
import shlex
import warnings
from collections import defaultdict
from concurrent import futures
from functools import partial
from pathlib import Path

from django.apps import apps
from django.conf import settings
from django.db.models import ObjectDoesNotExist

from commoncode import fileutils
from commoncode.resource import VirtualCodebase
from extractcode import api as extractcode_api
from packagedcode import get_package_handler
from packagedcode import models as packagedcode_models
from scancode import Scanner
from scancode import api as scancode_api
from scancode import cli as scancode_cli
from scancode.cli import run_scan as scancode_run_scan

from pipeline import LoopProgress
from scanpipe import pipes
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredPackage
from scanpipe.pipes import flag

logger = logging.getLogger("scanpipe.pipes")

"""
Utilities to deal with ScanCode toolkit features and objects.
"""

scanpipe_app = apps.get_app_config("scanpipe")


class InsufficientResourcesError(Exception):
    pass


def get_max_workers(keep_available):
    """
    Return the `SCANCODEIO_PROCESSES` if defined in the setting,
    or returns a default value based on the number of available CPUs,
    minus the provided `keep_available` value.

    On operating system where the multiprocessing start method is not "fork",
    but for example "spawn", such as on macOS, multiprocessing and threading are
    disabled by default returning -1 `max_workers`.
    """
    processes_from_settings = settings.SCANCODEIO_PROCESSES
    if processes_from_settings in [-1, 0, 1]:
        return processes_from_settings

    if multiprocessing.get_start_method() != "fork":
        return -1

    max_workers = os.cpu_count() - keep_available
    if max_workers < 1:
        return 1

    if processes_from_settings is not None:
        if processes_from_settings <= max_workers:
            return processes_from_settings
        else:
            msg = (
                f"The value {processes_from_settings} specified in SCANCODEIO_PROCESSES"
                f" exceeds the number of available CPUs on this machine."
                f" {max_workers} CPUs will be used instead for multiprocessing."
            )
            warnings.warn(msg, ResourceWarning)

    return max_workers


def extract_archive(location, target):
    """
    Extract a single archive or compressed file at `location` to the `target`
    directory.

    Return a dict of extraction errors, keyed by the resource location.

    Wrapper of the `extractcode.api.extract_archive` function.
    """
    errors = {}

    for event in extractcode_api.extract_archive(location, target):
        if event.done and event.errors:
            errors[str(event.source)] = event.errors

    return errors


def extract_archives(location, recurse=False):
    """
    Extract all archives at `location` and return errors.

    Archives and compressed files are extracted in a new directory named
    "<file_name>-extract" created in the same directory as each extracted
    archive.

    If `recurse` is True, extract nested archives-in-archives recursively.

    Return a dict of extraction errors, keyed by the resource location.

    Wrapper of the `extractcode.api.extract_archives` function.
    """
    options = {
        "recurse": recurse,
        "replace_originals": False,
        "all_formats": True,
    }

    errors = {}
    for event in extractcode_api.extract_archives(location, **options):
        if event.done and event.errors:
            errors[str(event.source)] = event.errors

    return errors


def get_resource_info(location):
    """Return a mapping suitable for the creation of a new CodebaseResource."""
    file_info = {}

    location_path = Path(location)
    is_symlink = location_path.is_symlink()
    is_file = location_path.is_file()

    if is_symlink:
        resource_type = CodebaseResource.Type.SYMLINK
        file_info["status"] = "symlink"
    elif is_file:
        resource_type = CodebaseResource.Type.FILE
    else:
        resource_type = CodebaseResource.Type.DIRECTORY

    file_info.update(
        {
            "type": resource_type,
            "name": fileutils.file_name(location),
            "extension": fileutils.file_extension(location),
        }
    )

    if is_symlink:
        return file_info

    # Missing fields on CodebaseResource model returned by `get_file_info`.
    unsupported_fields = [
        "is_source",
        "is_script",
        "date",
    ]

    other_info = scancode_api.get_file_info(location)

    # Skip unsupported_fields
    # Skip empty values to avoid null vs. '' conflicts
    other_info = {
        field_name: value
        for field_name, value in other_info.items()
        if field_name not in unsupported_fields and value
    }

    file_info.update(other_info)

    return file_info


def _scan_resource(
    location,
    scanners,
    with_threading=True,
    timeout=settings.SCANCODEIO_SCAN_FILE_TIMEOUT,
):
    """
    Wrap the scancode-toolkit `scan_resource` method to support timeout on direct
    scanner functions calls.
    Return a dictionary of scan `results` and a list of `errors`.
    The `with_threading` needs to be enabled for the timeouts support.
    """
    # `rid` is not needed in this context, yet required in the scan_resource args
    location_rid = location, 0
    _, _, errors, _, results, _ = scancode_cli.scan_resource(
        location_rid,
        scanners,
        timeout=timeout,
        with_threading=with_threading,
    )
    return results, errors


def scan_file(location, with_threading=True, min_license_score=0, **kwargs):
    """
    Run a license, copyright, email, and url scan on a provided `location`,
    using the scancode-toolkit direct API.

    Return a dictionary of scan `results` and a list of `errors`.
    """
    scancode_get_licenses = partial(
        scancode_api.get_licenses,
        min_score=min_license_score,
        include_text=True,
    )
    scanners = [
        Scanner("copyrights", scancode_api.get_copyrights),
        Scanner("licenses", scancode_get_licenses),
        Scanner("emails", scancode_api.get_emails),
        Scanner("urls", scancode_api.get_urls),
    ]
    return _scan_resource(location, scanners, with_threading=with_threading)


def scan_for_package_data(location, with_threading=True, package_only=False, **kwargs):
    """
    Run a package scan on provided `location` using the scancode-toolkit direct API.

    Return a dict of scan `results` and a list of `errors`.
    """
    scancode_get_packages = partial(
        scancode_api.get_package_data,
        package_only=package_only,
    )
    scanners = [
        Scanner("package_data", scancode_get_packages),
    ]
    return _scan_resource(location, scanners, with_threading=with_threading)


def save_scan_file_results(codebase_resource, scan_results, scan_errors):
    """
    Save the resource scan file results in the database.
    Create project errors if any occurred during the scan.
    """
    status = flag.SCANNED

    if scan_errors:
        codebase_resource.add_errors(scan_errors)
        status = flag.SCANNED_WITH_ERROR

    codebase_resource.set_scan_results(scan_results, status)


def save_scan_package_results(codebase_resource, scan_results, scan_errors):
    """
    Save the resource scan package results in the database.
    Create project errors if any occurred during the scan.
    """
    if package_data := scan_results.get("package_data", []):
        codebase_resource.update(
            package_data=package_data,
            status=flag.APPLICATION_PACKAGE,
        )

    if scan_errors:
        codebase_resource.add_errors(scan_errors)
        codebase_resource.update(status=flag.SCANNED_WITH_ERROR)


def scan_resources(
    resource_qs, scan_func, save_func, scan_func_kwargs=None, progress_logger=None
):
    """
    Run the `scan_func` on the codebase resources of the provided `resource_qs`.
    The `save_func` is called to save the results.

    Multiprocessing is enabled by default on this pipe, the number of processes can be
    controlled through the `SCANCODEIO_PROCESSES` setting.
    Multiprocessing can be disabled using `SCANCODEIO_PROCESSES=0`,
    and threading can also be disabled `SCANCODEIO_PROCESSES=-1`

    The codebase resources QuerySet is chunked in 2000 results at the time,
    this can result in a significant reduction in memory usage.

    Note that all database related actions are executed in this main process as the
    database connection does not always fork nicely in the pool processes.
    """
    if not scan_func_kwargs:
        scan_func_kwargs = {}

    resource_count = resource_qs.count()
    logger.info(f"Scan {resource_count} codebase resources with {scan_func.__name__}")
    resource_iterator = resource_qs.iterator(chunk_size=2000)
    progress = LoopProgress(resource_count, logger=progress_logger)
    max_workers = get_max_workers(keep_available=1)

    if max_workers <= 0:
        with_threading = False if max_workers == -1 else True
        for resource in progress.iter(resource_iterator):
            progress.log_progress()
            logger.debug(f"{scan_func.__name__} pk={resource.pk}")
            scan_results, scan_errors = scan_func(
                resource.location, with_threading, **scan_func_kwargs
            )
            save_func(resource, scan_results, scan_errors)
        return

    logger.info(f"Starting ProcessPoolExecutor with {max_workers} max_workers")

    with futures.ProcessPoolExecutor(max_workers) as executor:
        future_to_resource = {
            executor.submit(scan_func, resource.location): resource
            for resource in resource_iterator
        }

        # Iterate over the Futures as they complete (finished or cancelled)
        future_as_completed = futures.as_completed(future_to_resource)

        for future in progress.iter(future_as_completed):
            resource = future_to_resource[future]
            progress.log_progress()
            logger.debug(f"{scan_func.__name__} pk={resource.pk}")
            try:
                scan_results, scan_errors = future.result()
            except futures.process.BrokenProcessPool as broken_pool_error:
                message = (
                    "You may not have enough resources to complete this operation. "
                    "Please ensure that there is at least 2 GB of available memory per "
                    "CPU core for successful execution."
                )
                raise broken_pool_error from InsufficientResourcesError(message)
            save_func(resource, scan_results, scan_errors)


def scan_for_files(project, resource_qs=None, progress_logger=None):
    """
    Run a license, copyright, email, and url scan on files without a status for
    a `project`.

    Multiprocessing is enabled by default on this pipe, the number of processes can be
    controlled through the SCANCODEIO_PROCESSES setting.
    """
    # Checking for None to make the distinction with an empty resource_qs queryset
    if resource_qs is None:
        resource_qs = project.codebaseresources.no_status()

    scan_resources(
        resource_qs=resource_qs,
        scan_func=scan_file,
        save_func=save_scan_file_results,
        progress_logger=progress_logger,
    )


def scan_for_application_packages(
    project, assemble=True, package_only=False, resource_qs=None, progress_logger=None
):
    """
    Run a package scan on resources without a status for a `project`,
    and add them in their respective `package_data` attribute.
    Then create DiscoveredPackage and DiscoveredDependency instances
    from the detected package data optionally. If the `assemble` argument
    is set to `True`, DiscoveredPackage and DiscoveredDependency instances
    are created and added to the project by assembling resource level
    package_data, and resources which belong in the DiscoveredPackage
    instance, are assigned to that package.

    Multiprocessing is enabled by default on this pipe, the number of processes can be
    controlled through the SCANCODEIO_PROCESSES setting.
    """
    if not resource_qs:
        resource_qs = project.codebaseresources.no_status()

    scan_func_kwargs = {
        "package_only": package_only,
    }

    # Collect detected Package data and save it to the CodebaseResource it was
    # detected from.
    scan_resources(
        resource_qs=resource_qs,
        scan_func=scan_for_package_data,
        save_func=save_scan_package_results,
        progress_logger=progress_logger,
        scan_func_kwargs=scan_func_kwargs,
    )

    # Iterate through CodebaseResources with Package data and handle them using
    # the proper Package handler from packagedcode.
    if assemble:
        assemble_packages(project=project)


def add_resource_to_package(package_uid, resource, project):
    """
    Relate a DiscoveredPackage to `resource` from `project` using `package_uid`.

    Add a ProjectMessage when the DiscoveredPackage could not be fetched using the
    provided `package_uid`.
    """
    if not package_uid:
        return

    resource_package = resource.discovered_packages.filter(package_uid=package_uid)
    if resource_package.exists():
        return

    try:
        package = project.discoveredpackages.get(package_uid=package_uid)
    except ObjectDoesNotExist as error:
        details = {"package_uid": str(package_uid)}
        project.add_error(
            error, model="assemble_package", details=details, resource=resource
        )
        return

    resource.discovered_packages.add(package)


def assemble_packages(project):
    """
    Create instances of DiscoveredPackage and DiscoveredDependency for `project`
    from the parsed package data present in the CodebaseResources of `project`,
    using the respective package handlers for each package manifest type.
    """
    logger.info(f"Project {project} assemble_packages:")
    seen_resource_paths = set()

    for resource in project.codebaseresources.has_package_data():
        if resource.path in seen_resource_paths:
            continue

        logger.info(f"  Processing: {resource.path}")
        for package_mapping in resource.package_data:
            pd = packagedcode_models.PackageData.from_dict(mapping=package_mapping)
            logger.info(f"  Package data: {pd.purl}")

            handler = get_package_handler(pd)
            logger.info(f"  Selected package handler: {handler.__name__}")

            items = handler.assemble(
                package_data=pd,
                resource=resource,
                codebase=project,
                package_adder=add_resource_to_package,
            )

            for item in items:
                logger.info(f"    Processing item: {item}")
                if isinstance(item, packagedcode_models.Package):
                    package_data = item.to_dict()
                    pipes.update_or_create_package(project, package_data)
                elif isinstance(item, packagedcode_models.Dependency):
                    dependency_data = item.to_dict()
                    pipes.update_or_create_dependency(project, dependency_data)
                elif isinstance(item, CodebaseResource):
                    seen_resource_paths.add(item.path)
                else:
                    logger.info(f"Unknown Package assembly item type: {item!r}")


def process_package_data(project, static_resolve=False):
    """
    Create instances of DiscoveredPackage and DiscoveredDependency for `project`
    from the parsed package data present in the CodebaseResources of `project`.

    Here package assembly though package handlers are not performed, instead
    package/dependency objects are created directly from package data.
    """
    logger.info(f"Project {project} process_package_data:")

    for resource in project.codebaseresources.has_package_data():
        logger.info(f"  Processing: {resource.path}")
        for package_mapping in resource.package_data:
            create_packages_and_dependencies_from_mapping(
                project=project,
                resource=resource,
                package_mapping=package_mapping,
                find_package=False,
                process_resolved=False,
            )

    if static_resolve:
        resolve_dependencies(project)


def create_packages_and_dependencies_from_mapping(
    project,
    resource,
    package_mapping,
    find_package=False,
    process_resolved=False,
):
    """
    Create or update packages and dependencies from a `package_mapping`,
    for a respective `resource` and `project`.

    If `find_package` is True, find the package with the respective purl data,
    instead of trying to create it.
    If `process_resolved` is True, also create packages and dependency relations
    from the resolved packages of dependencies of this `package_mapping`.
    """
    pd = packagedcode_models.PackageData.from_dict(mapping=package_mapping)
    if not pd.can_assemble:
        return

    logger.info(f"  Package data: {pd.purl}")

    package_data = pd.to_dict()
    dependencies = package_data.pop("dependencies")

    package = None
    if pd.purl:
        if find_package:
            purl_data = DiscoveredPackage.extract_purl_data(package_mapping)
            packages = DiscoveredPackage.objects.filter(
                project=project,
                **purl_data,
            )

            for package in packages:
                if resource.location in package.datafile_paths:
                    break
        else:
            package = pipes.update_or_create_package(
                project=project,
                package_data=package_data,
                codebase_resources=[resource],
            )

    update_packages_and_dependencies(
        project=project,
        dependencies=dependencies,
        package=package,
        resource=resource,
        datasource_id=pd.datasource_id,
        process_resolved=process_resolved,
    )


def resolve_dependencies(project):
    """
    Match and merge resolved dependencies to create a dependency graph of
    direct dependency relations between resolved packages.
    """
    logger.info(f"Project {project} resolve_dependencies:")
    for resource in project.codebaseresources.has_package_data():
        for package_mapping in resource.package_data:
            create_packages_and_dependencies_from_mapping(
                project=project,
                resource=resource,
                package_mapping=package_mapping,
                find_package=True,
                process_resolved=True,
            )

    match_and_resolve_dependencies(project)


def update_packages_and_dependencies(
    project,
    dependencies,
    package,
    resource,
    datasource_id,
    process_resolved=True,
):
    """
    Create DiscoveredPackage and DiscoveredDependency objects from
    a package_data dependencies, and also from nested resolved packages
    and dependencies if present.

    If `process_resolved` is True, also create packages and dependency relations
    from the resolved packages of `dependencies`.
    """
    for dep in dependencies:
        resolved_package = dep.get("resolved_package") or {}
        resolved_to_package = None
        if process_resolved and resolved_package:
            resolved_to_package = pipes.update_or_create_package(
                project=project,
                package_data=resolved_package,
                codebase_resources=[resource],
                is_virtual=True,
            )

            deps_from_resolved = resolved_package.get("dependencies") or []
            for dep_from_resolved in deps_from_resolved:
                pipes.update_or_create_dependency(
                    project=project,
                    dependency_data=dep_from_resolved,
                    for_package=resolved_to_package,
                    datafile_resource=resource,
                    datasource_id=datasource_id,
                )

        pipes.update_or_create_dependency(
            project=project,
            dependency_data=dep,
            for_package=package,
            resolved_to_package=resolved_to_package,
            datafile_resource=resource,
            datasource_id=datasource_id,
        )


def match_and_resolve_dependencies(project):
    """
    From a project with both direct dependency relationships (contains
    only the parent package and the requirement) and indirect dependency
    relationships like in lockfiles (this contains the resolved package
    and the requirement), match and update dependencies to contain the
    full dependency graph.
    """
    for dependency in project.discovereddependencies.all():
        if dependency.resolved_to_package:
            continue

        purl_data = DiscoveredDependency.extract_purl_data(
            dependency_data={"purl": dependency.purl},
            ignore_nulls=True,
        )
        extracted_requirement = dependency.extracted_requirement
        if not extracted_requirement:
            extracted_requirement = ""

        matched_dependencies = DiscoveredDependency.objects.filter(
            project=project,
            extracted_requirement=dependency.extracted_requirement,
            **purl_data,
        )

        other_dependencies = [
            matched_dependency
            for matched_dependency in matched_dependencies
            if matched_dependency.purl != dependency.purl
        ]
        if not other_dependencies:
            # We also have cases where multiple dependency requirements have one
            # resolved package and the extracted requirements field is combined
            matched_dependencies = DiscoveredDependency.objects.filter(
                project=project,
                **purl_data,
            )
            other_dependencies = [
                matched_dependency
                for matched_dependency in matched_dependencies
                if (
                    matched_dependency.purl != dependency.purl
                    and dependency.extracted_requirement
                    in matched_dependency.extracted_requirement
                )
            ]

            # This should be done only in the case of lockfiles where only one version
            # of a package is present for an environment
            if not other_dependencies:
                other_dependencies = [
                    matched_dependency
                    for matched_dependency in matched_dependencies
                    if (
                        matched_dependency.base_purl == dependency.base_purl
                        and matched_dependency.resolved_to_package
                    )
                ]

        if other_dependencies:
            resolved_dependency = other_dependencies.pop()
            dependency.update(
                resolved_to_package=resolved_dependency.resolved_to_package,
            )

    # We need only the direct dependency relationships but not the from indirect
    # dependency realtionships which are between the main package to resolved packages
    indirect_dependencies = project.discovereddependencies.filter(is_direct=False)
    indirect_dependencies.delete()


def get_packages_with_purl_from_resources(project):
    """
    Yield Dependency or PackageData objects created from detected package_data
    in all the project resources. Both Dependency and PackageData objects have
    the `purl` attribute with a valid purl.
    """
    for resource in project.codebaseresources.has_package_data():
        for package_mapping in resource.package_data:
            for dependency in package_mapping.get("dependencies"):
                yield packagedcode_models.Dependency.from_dependent_package(
                    dependent_package=dependency,
                    datafile_path=resource.path,
                    datasource_id=package_mapping.get("datasource_id"),
                    package_uid=None,
                )
            yield packagedcode_models.PackageData.from_dict(mapping=package_mapping)


def get_pretty_params(args):
    """Format provided ``args`` for the ``pretty_params`` run_scan argument."""
    return {f"--{key.replace('_', '-')}": value for key, value in args.items()}


def run_scan(location, output_file, run_scan_args):
    """Scan the `location` content and write the results into an `output_file`."""
    _success, results = scancode_run_scan(
        input=shlex.quote(location),
        processes=get_max_workers(keep_available=1),
        quiet=True,
        verbose=False,
        return_results=True,
        echo_func=None,
        pretty_params=get_pretty_params(run_scan_args),
        timeout=settings.SCANCODEIO_SCAN_FILE_TIMEOUT,
        **run_scan_args,
    )

    # ``_success`` will be False if any scanning errors occur, but we still want
    # to generate the results output in that case.
    if results:
        Path(output_file).write_text(json.dumps(results, indent=2))

    # Capture scan errors logged at the files level.
    scanning_errors = {}
    for file in results.get("files", []):
        if errors := file.get("scan_errors"):
            scanning_errors[file.get("path")] = errors

    return scanning_errors


def get_virtual_codebase(project, input_location):
    """
    Return a ScanCode virtual codebase built from the JSON scan file located at
    the `input_location`.
    """
    temp_path = project.tmp_path / "scancode-temp-resource-cache"
    temp_path.mkdir(parents=True, exist_ok=True)

    return VirtualCodebase(input_location, temp_dir=str(temp_path), max_in_memory=0)


def create_codebase_resources(project, scanned_codebase):
    """
    Save the resources of a ScanCode `scanned_codebase` scancode.resource.Codebase
    object to the database as a CodebaseResource of the `project`.
    This function can be used to expend an existing `project` Codebase with new
    CodebaseResource objects as the existing objects (based on the `path`) will be
    skipped.
    """
    for scanned_resource in scanned_codebase.walk(skip_root=True):
        resource_data = {}

        for field in CodebaseResource._meta.fields:
            # Do not include the path as provided by the scanned_resource since it
            # includes the "root". The `get_path` method is used instead.
            if field.name == "path":
                continue
            value = getattr(scanned_resource, field.name, None)
            if value is not None:
                resource_data[field.name] = value

        resource_type = "FILE" if scanned_resource.is_file else "DIRECTORY"
        resource_data["type"] = CodebaseResource.Type[resource_type]
        resource_path = scanned_resource.get_path(strip_root=True)

        codebase_resource, _ = CodebaseResource.objects.get_or_create(
            project=project,
            path=resource_path,
            defaults=resource_data,
        )

        for_packages = getattr(scanned_resource, "for_packages", [])
        for package_uid in for_packages:
            logger.debug(f"Assign {package_uid} to {codebase_resource}")
            package = project.discoveredpackages.get(package_uid=package_uid)
            set_codebase_resource_for_package(
                codebase_resource=codebase_resource,
                discovered_package=package,
            )


def create_discovered_packages(project, scanned_codebase):
    """
    Save the packages of a ScanCode `scanned_codebase` scancode.resource.Codebase
    object to the database as a DiscoveredPackage of `project`.
    """
    if hasattr(scanned_codebase.attributes, "packages"):
        for package_data in scanned_codebase.attributes.packages:
            pipes.update_or_create_package(project, package_data)


def create_discovered_dependencies(
    project, scanned_codebase, strip_datafile_path_root=False
):
    """
    Save the dependencies of a ScanCode `scanned_codebase` scancode.resource.Codebase
    object to the database as a DiscoveredDependency of `project`.

    If `strip_datafile_path_root` is True, then
    `DiscoveredDependency.create_from_data()` will strip the root path segment
    from the `datafile_path` of `dependency_data` before looking up the
    corresponding CodebaseResource for `datafile_path`. This is used in the case
    where Dependency data is imported from a scancode-toolkit scan, where the
    root path segments are not stripped for `datafile_path`.
    """
    if hasattr(scanned_codebase.attributes, "dependencies"):
        for dependency_data in scanned_codebase.attributes.dependencies:
            pipes.update_or_create_dependency(
                project,
                dependency_data,
                strip_datafile_path_root=strip_datafile_path_root,
            )


def set_codebase_resource_for_package(codebase_resource, discovered_package):
    """
    Assign the `discovered_package` to the `codebase_resource` and set its
    status to "application-package".
    """
    codebase_resource.add_package(discovered_package)
    codebase_resource.update(status=flag.APPLICATION_PACKAGE)


def get_detection_data(detection_entry):
    license_expression = detection_entry.get("license_expression")
    identifier = detection_entry.get("identifier")
    matches = []

    for match in detection_entry.get("matches", []):
        match_license_expression = match.get("license_expression")
        # Do not include those match.expression when not part of this detection
        # entry license_expression as those are not counted in the summary
        if match_license_expression in license_expression:
            matches.append(
                {
                    "license_expression": match_license_expression,
                    "matched_text": match.get("matched_text"),
                }
            )

    return {
        "license_expression": license_expression,
        "identifier": identifier,
        "matches": matches,
    }


def get_license_matches_grouped(project):
    """
    Return a dictionary of all license_matches of a given ``project`` grouped by
    ``resource.detected_license_expression``.
    """
    resources_with_license = project.codebaseresources.has_license_detections()
    license_matches = defaultdict(dict)

    for resource in resources_with_license:
        matches = [
            get_detection_data(detection_entry)
            for detection_entry in resource.license_detections
        ]
        license_matches[resource.detected_license_expression][resource.path] = matches

    return dict(license_matches)


def make_results_summary(project, scan_results_location):
    """
    Extract selected sections of the Scan results, such as the `summary`
    `license_clarity_score`, and `license_matches` related data.
    The `key_files` are also collected and injected in the `summary` output.
    """
    from scanpipe.api.serializers import CodebaseResourceSerializer
    from scanpipe.api.serializers import DiscoveredPackageSerializer

    with open(scan_results_location) as f:
        scan_data = json.load(f)

    summary = scan_data.get("summary")

    # Inject the generated `license_matches` in the summary from the project
    # codebase resources.
    summary["license_matches"] = get_license_matches_grouped(project)

    # Inject the `key_files` and their file content in the summary
    key_files = []
    key_files_qs = project.codebaseresources.filter(is_key_file=True, is_text=True)

    for resource in key_files_qs:
        resource_data = CodebaseResourceSerializer(resource).data
        resource_data["content"] = resource.file_content
        key_files.append(resource_data)

    summary["key_files"] = key_files

    # Inject the `key_files_packages` filtered from the key_files_qs
    key_files_packages_qs = project.discoveredpackages.filter(
        codebase_resources__in=key_files_qs
    ).distinct()

    summary["key_files_packages"] = [
        DiscoveredPackageSerializer(package).data for package in key_files_packages_qs
    ]

    return summary
