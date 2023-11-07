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

from collections import Counter
from collections import defaultdict
from contextlib import suppress
from pathlib import Path

from django.contrib.postgres.aggregates.general import ArrayAgg
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import F
from django.db.models import Q
from django.db.models import Value
from django.db.models.expressions import Subquery
from django.db.models.functions import Concat
from django.template.defaultfilters import pluralize

from commoncode.paths import common_prefix
from extractcode import EXTRACT_SUFFIX
from packagedcode.npm import NpmPackageJsonHandler
from summarycode.classify import LEGAL_STARTS_ENDS

from scanpipe import pipes
from scanpipe.models import CodebaseRelation
from scanpipe.models import CodebaseResource
from scanpipe.pipes import LoopProgress
from scanpipe.pipes import flag
from scanpipe.pipes import get_resource_diff_ratio
from scanpipe.pipes import js
from scanpipe.pipes import jvm
from scanpipe.pipes import pathmap
from scanpipe.pipes import purldb
from scanpipe.pipes import resolve
from scanpipe.pipes import scancode

FROM = "from/"
TO = "to/"


def get_inputs(project):
    """Locate the ``from`` and ``to`` input files in project inputs/ directory."""
    from_files = list(project.inputs("from*"))
    to_files = list(project.inputs("to*"))

    if len(from_files) < 1:
        raise FileNotFoundError("from* input files not found.")

    if len(to_files) < 1:
        raise FileNotFoundError("to* input files not found.")

    return from_files, to_files


def get_extracted_path(resource):
    """Return the ``-extract/`` extracted path of provided ``resource``."""
    return resource.path + "-extract/"


def get_extracted_subpath(path):
    """Return the path segments located after the last ``-extract/`` segment."""
    return path.split("-extract/")[-1]


def get_best_path_matches(to_resource, matches):
    """Return the best ``matches`` for the provided ``to_resource``."""
    path_parts = Path(to_resource.path.lstrip("/")).parts

    for path_parts_index in range(1, len(path_parts)):
        subpath = "/".join(path_parts[path_parts_index:])
        subpath_matches = [
            from_resource
            for from_resource in matches
            if from_resource.path.endswith(subpath)
        ]
        if subpath_matches:
            return subpath_matches

    return matches


def get_from_files_for_scanning(resources):
    """
    Return resources in the "from/" side which has been mapped to the "to/"
    side, but are not mapped using ABOUT files.
    """
    mapped_from_files = resources.from_codebase().files().has_relation()
    return mapped_from_files.filter(~Q(status=flag.ABOUT_MAPPED))


def _map_checksum_resource(to_resource, from_resources, checksum_field):
    checksum_value = getattr(to_resource, checksum_field)
    matches = from_resources.filter(**{checksum_field: checksum_value})
    for match in get_best_path_matches(to_resource, matches):
        pipes.make_relation(
            from_resource=match,
            to_resource=to_resource,
            map_type=checksum_field,
        )


def map_checksum(project, checksum_field, logger=None):
    """Map using checksum."""
    project_files = project.codebaseresources.files().no_status()
    from_resources = project_files.from_codebase().has_value(checksum_field)
    to_resources = (
        project_files.to_codebase().has_value(checksum_field).has_no_relation()
    )
    resource_count = to_resources.count()

    if logger:
        logger(
            f"Mapping {resource_count:,d} to/ resources using {checksum_field} "
            f"against from/ codebase"
        )

    resource_iterator = to_resources.iterator(chunk_size=2000)
    progress = LoopProgress(resource_count, logger)

    for to_resource in progress.iter(resource_iterator):
        _map_checksum_resource(to_resource, from_resources, checksum_field)


def _map_java_to_class_resource(to_resource, from_resources, from_classes_index):
    """
    Map the ``to_resource`` .class file Resource with a Resource in
    ``from_resources`` .java files, using the ``from_classes_index`` index of
    from/ fully qualified Java class names.
    """
    normalized_java_path = jvm.get_normalized_java_path(to_resource.path)
    match = pathmap.find_paths(path=normalized_java_path, index=from_classes_index)
    if not match:
        return

    for resource_id in match.resource_ids:
        from_resource = from_resources.get(id=resource_id)
        # compute the root of the packages on the source side
        from_source_root_parts = from_resource.path.strip("/").split("/")
        from_source_root = "/".join(
            from_source_root_parts[: -match.matched_path_length]
        )
        pipes.make_relation(
            from_resource=from_resource,
            to_resource=to_resource,
            map_type="java_to_class",
            extra_data={"from_source_root": f"{from_source_root}/"},
        )


def map_java_to_class(project, logger=None):
    """
    Map to/ compiled Java .class(es) to from/ .java source using Java fully
    qualified paths and indexing from/ .java files.
    """
    project_files = project.codebaseresources.files().no_status()
    from_resources = project_files.from_codebase()
    to_resources = project_files.to_codebase().has_no_relation()

    to_resources_dot_class = to_resources.filter(extension=".class")
    resource_count = to_resources_dot_class.count()
    if logger:
        logger(f"Mapping {resource_count:,d} .class resources to .java")

    from_resources_dot_java = from_resources.filter(extension=".java")
    if not from_resources_dot_java.exists():
        logger("No .java resources to map.")
        return

    # build an index using from-side Java fully qualified class file names
    # built from the "java_package" and file name
    indexables = get_indexable_qualified_java_paths(from_resources_dot_java)

    # we do not index subpath since we want to match only fully qualified names
    from_classes_index = pathmap.build_index(indexables, with_subpaths=False)

    resource_iterator = to_resources_dot_class.iterator(chunk_size=2000)
    progress = LoopProgress(resource_count, logger)

    for to_resource in progress.iter(resource_iterator):
        _map_java_to_class_resource(to_resource, from_resources, from_classes_index)


def get_indexable_qualified_java_paths_from_values(resource_values):
    """
    Yield tuples of (resource id, fully-qualified Java path) for indexable
    classes from a list of ``resource_data`` tuples of "from/" side of the
    project codebase.

    These ``resource_data`` input tuples are in the form:
        (resource.id, resource.name, resource.extra_data)

    And the output tuples look like this example::
        (123, "org/apache/commons/LoggerImpl.java")
    """
    for resource_id, resource_name, resource_extra_data in resource_values:
        java_package = resource_extra_data and resource_extra_data.get("java_package")
        if not java_package:
            continue
        fully_qualified = jvm.get_fully_qualified_java_path(
            java_package,
            filename=resource_name,
        )
        yield resource_id, fully_qualified


def get_indexable_qualified_java_paths(from_resources_dot_java):
    """
    Yield tuples of (resource id, fully-qualified Java class name) for indexable
    classes from the "from/" side of the project codebase using the
    "java_package" Resource.extra_data.
    """
    resource_values = from_resources_dot_java.values_list("id", "name", "extra_data")
    return get_indexable_qualified_java_paths_from_values(resource_values)


def find_java_packages(project, logger=None):
    """
    Collect the Java packages of Java source files for a ``project``.

    Multiprocessing is enabled by default on this pipe, the number of processes
    can be controlled through the SCANCODEIO_PROCESSES setting.

    Note: we use the same API as the ScanCode scans by design
    """
    from_java_resources = (
        project.codebaseresources.files()
        .no_status()
        .from_codebase()
        .has_no_relation()
        .filter(extension=".java")
    )

    if logger:
        logger(
            f"Finding Java package for {from_java_resources.count():,d} "
            ".java resources."
        )

    scancode.scan_resources(
        resource_qs=from_java_resources,
        scan_func=scan_for_java_package,
        save_func=save_java_package_scan_results,
        progress_logger=logger,
    )


def scan_for_java_package(location, with_threading=True):
    """
    Run a Java package scan on provided ``location``.

    Return a dict of scan ``results`` and a list of ``errors``.
    """
    scanners = [scancode.Scanner("java_package", jvm.get_java_package)]
    return scancode._scan_resource(location, scanners, with_threading=with_threading)


def save_java_package_scan_results(codebase_resource, scan_results, scan_errors):
    """
    Save the resource Java package scan results in the database as Resource.extra_data.
    Create project errors if any occurred during the scan.
    """
    # The status is only updated in case of errors.
    if scan_errors:
        codebase_resource.add_errors(scan_errors)
        codebase_resource.update(status=flag.SCANNED_WITH_ERROR)
    else:
        codebase_resource.update_extra_data(scan_results)


def _map_jar_to_source_resource(jar_resource, to_resources, from_resources):
    jar_extracted_path = get_extracted_path(jar_resource)
    jar_extracted_dot_class_files = list(
        to_resources.filter(
            extension=".class", path__startswith=jar_extracted_path
        ).values("id", "status")
    )

    # Rely on the status flag to avoid triggering extra SQL queries.
    not_mapped_dot_class = [
        dot_class_file
        for dot_class_file in jar_extracted_dot_class_files
        if dot_class_file.get("status") == flag.NO_JAVA_SOURCE
    ]
    # Do not continue if any .class files couldn't be mapped.
    if any(not_mapped_dot_class):
        return

    # Using ids from already evaluated QuerySet to avoid triggering an expensive
    # SQL subquery in the following CodebaseRelation QuerySet.
    dot_class_file_ids = [
        dot_class_file.get("id") for dot_class_file in jar_extracted_dot_class_files
    ]
    java_to_class_extra_data_list = CodebaseRelation.objects.filter(
        to_resource__in=dot_class_file_ids, map_type="java_to_class"
    ).values_list("extra_data", flat=True)

    from_source_roots = [
        extra_data.get("from_source_root", "")
        for extra_data in java_to_class_extra_data_list
    ]
    if len(set(from_source_roots)) != 1:
        # Could not determine a common root directory for the java_to_class files
        return

    common_source_root = from_source_roots[0].rstrip("/")
    if common_from_resource := from_resources.get_or_none(path=common_source_root):
        pipes.make_relation(
            from_resource=common_from_resource,
            to_resource=jar_resource,
            map_type="jar_to_source",
        )


def map_jar_to_source(project, logger=None):
    """Map .jar files to their related source directory."""
    project_files = project.codebaseresources.files()
    # Include the directories to map on the common source
    from_resources = project.codebaseresources.from_codebase()
    to_resources = project_files.to_codebase()
    to_jars = to_resources.filter(extension=".jar")

    to_jars_count = to_jars.count()
    if logger:
        logger(
            f"Mapping {to_jars_count:,d} .jar resources using map_jar_to_source "
            f"against from/ codebase"
        )

    resource_iterator = to_jars.iterator(chunk_size=2000)
    progress = LoopProgress(to_jars_count, logger)

    for jar_resource in progress.iter(resource_iterator):
        _map_jar_to_source_resource(jar_resource, to_resources, from_resources)


def _map_path_resource(
    to_resource, from_resources, from_resources_index, diff_ratio_threshold=0.7
):
    match = pathmap.find_paths(to_resource.path, from_resources_index)
    if not match:
        return

    # Don't path map resource solely based on the file name.
    if match.matched_path_length < 2:
        return

    # Only create relations when the number of matches if inferior or equal to
    # the current number of path segment matched.
    if len(match.resource_ids) > match.matched_path_length:
        return

    for resource_id in match.resource_ids:
        from_resource = from_resources.get(id=resource_id)
        diff_ratio = get_resource_diff_ratio(to_resource, from_resource)
        if diff_ratio is not None and diff_ratio < diff_ratio_threshold:
            continue

        # Do not count the "to/" segment as it is not "matchable"
        to_path_length = len(to_resource.path.split("/")) - 1
        extra_data = {
            "path_score": f"{match.matched_path_length}/{to_path_length}",
        }
        if diff_ratio:
            extra_data["diff_ratio"] = f"{diff_ratio:.1%}"

        pipes.make_relation(
            from_resource=from_resource,
            to_resource=to_resource,
            map_type="path",
            extra_data=extra_data,
        )


def map_path(project, logger=None):
    """Map using path suffix similarities."""
    project_files = project.codebaseresources.files().no_status()
    from_resources = project_files.from_codebase()
    to_resources = project_files.to_codebase().has_no_relation()
    resource_count = to_resources.count()

    if logger:
        logger(
            f"Mapping {resource_count:,d} to/ resources using path map "
            f"against from/ codebase"
        )

    if not from_resources.exists():
        logger("No from/ resources to map.")
        return

    from_resources_index = pathmap.build_index(
        from_resources.values_list("id", "path"), with_subpaths=True
    )

    resource_iterator = to_resources.iterator(chunk_size=2000)
    progress = LoopProgress(resource_count, logger)

    for to_resource in progress.iter(resource_iterator):
        _map_path_resource(to_resource, from_resources, from_resources_index)


def get_project_resources_qs(project, resources):
    """
    Return a queryset of CodebaseResources from `project` containing the
    CodebaseResources from `resources` . If a CodebaseResource in `resources` is
    an archive or directory, then their descendants are also included in the
    queryset.

    Return None if `resources` is empty or None.
    """
    lookups = Q()
    for resource in resources or []:
        lookups |= Q(path=resource.path)
        if resource.is_archive:
            # This is done to capture the extracted contents of the archive we
            # matched to. Generally, the archive contents are in a directory
            # that is the archive path with `-extract` at the end.
            lookups |= Q(path__startswith=resource.path)
        elif resource.is_dir:
            # We add a trailing slash to avoid matching on directories we do not
            # intend to. For example, if we have matched on the directory with
            # the path `foo/bar/1`, using the __startswith filter without
            # including a trailing slash on the path would have us get all
            # diretories under `foo/bar/` that start with 1, such as
            # `foo/bar/10001`, `foo/bar/123`, etc., when we just want `foo/bar/1`
            # and its descendants.
            path = f"{resource.path}/"
            lookups |= Q(path__startswith=path)
    if lookups:
        return project.codebaseresources.filter(lookups)


def create_package_from_purldb_data(project, resources, package_data, status):
    """
    Create a DiscoveredPackage instance from PurlDB ``package_data``.

    Return a tuple, containing the created DiscoveredPackage and the number of
    CodebaseResources matched to PurlDB that are part of that DiscoveredPackage.
    """
    package_data = package_data.copy()
    # Do not re-use uuid from PurlDB as DiscoveredPackage.uuid is unique and a
    # PurlDB match can be found in different projects.
    package_data.pop("uuid", None)
    package_data.pop("dependencies", None)

    resources_qs = get_project_resources_qs(project, resources)
    package = pipes.update_or_create_package(
        project=project,
        package_data=package_data,
        codebase_resources=resources_qs,
    )
    # Get the number of already matched CodebaseResources from `resources_qs`
    # before we update the status of all CodebaseResources from `resources_qs`,
    # then subtract the number of already matched CodebaseResources from the
    # total number of CodebaseResources updated. This is to prevent
    # double-counting of CodebaseResources that were matched to purldb
    purldb_statuses = [
        flag.MATCHED_TO_PURLDB_PACKAGE,
        flag.MATCHED_TO_PURLDB_RESOURCE,
        flag.MATCHED_TO_PURLDB_DIRECTORY,
    ]
    matched_resources_count = resources_qs.exclude(status__in=purldb_statuses).update(
        status=status
    )
    return package, matched_resources_count


def match_purldb_package(
    project, resources_by_sha1, enhance_package_data=True, **kwargs
):
    """
    Given a mapping of lists of CodebaseResources by their sha1 values,
    `resources_by_sha1`, send those sha1 values to purldb packages API endpoint,
    process the matched Package data, then return the number of
    CodebaseResources that were matched to a Package.
    """
    match_count = 0
    sha1_list = list(resources_by_sha1.keys())
    if results := purldb.match_packages(
        sha1_list=sha1_list,
        enhance_package_data=enhance_package_data,
    ):
        # Process matched Package data
        for package_data in results:
            sha1 = package_data["sha1"]
            resources = resources_by_sha1.get(sha1) or []
            if not resources:
                continue
            _, matched_resources_count = create_package_from_purldb_data(
                project=project,
                resources=resources,
                package_data=package_data,
                status=flag.MATCHED_TO_PURLDB_PACKAGE,
            )
            match_count += matched_resources_count
    return match_count


def match_purldb_resource(
    project, resources_by_sha1, package_data_by_purldb_urls=None, **kwargs
):
    """
    Given a mapping of lists of CodebaseResources by their sha1 values,
    `resources_by_sha1`, send those sha1 values to purldb resources API
    endpoint, process the matched Package data, then return the number of
    CodebaseResources that were matched to a Package.

    `package_data_by_purldb_urls` is a mapping of package data by their purldb
    package instance URLs. This is intended to be used as a cache, to avoid
    retrieving package data we retrieved before.
    """
    package_data_by_purldb_urls = package_data_by_purldb_urls or {}
    match_count = 0
    sha1_list = list(resources_by_sha1.keys())
    if results := purldb.match_resources(sha1_list=sha1_list):
        # Process match results
        for result in results:
            # Get package data
            package_instance_url = result["package"]
            if package_instance_url not in package_data_by_purldb_urls:
                # Get and cache package data if we do not have it
                if package_data := purldb.request_get(url=package_instance_url):
                    package_data_by_purldb_urls[package_instance_url] = package_data
            else:
                # Use cached package data
                package_data = package_data_by_purldb_urls[package_instance_url]
            sha1 = result["sha1"]
            resources = resources_by_sha1.get(sha1) or []
            if not resources:
                continue
            _, matched_resources_count = create_package_from_purldb_data(
                project=project,
                resources=resources,
                package_data=package_data,
                status=flag.MATCHED_TO_PURLDB_RESOURCE,
            )
            match_count += matched_resources_count
    return match_count


def match_purldb_directory(project, resource):
    """Match a single directory resource in the PurlDB."""
    fingerprint = resource.extra_data.get("directory_content", "")

    if results := purldb.match_directory(fingerprint=fingerprint):
        package_url = results[0]["package"]
        if package_data := purldb.request_get(url=package_url):
            return create_package_from_purldb_data(
                project, [resource], package_data, flag.MATCHED_TO_PURLDB_DIRECTORY
            )


def match_sha1s_to_purldb(
    project, resources_by_sha1, matcher_func, package_data_by_purldb_urls
):
    """
    Process `resources_by_sha1` with `matcher_func` and return a 3-tuple
    contaning an empty defaultdict(list), the number of matches and the number
    of sha1s sent to purldb.
    """
    matched_count = matcher_func(
        project=project,
        resources_by_sha1=resources_by_sha1,
        package_data_by_purldb_urls=package_data_by_purldb_urls,
    )
    sha1_count = len(resources_by_sha1)
    # Clear out resources_by_sha1 when we are done with the current batch of
    # CodebaseResources
    resources_by_sha1 = defaultdict(list)
    return resources_by_sha1, matched_count, sha1_count


def match_purldb_resources(
    project, extensions, matcher_func, chunk_size=1000, logger=None
):
    """
    Match against PurlDB selecting codebase resources using provided
    ``package_extensions`` for archive type files, and ``resource_extensions``.

    Match requests are sent off in batches of 1000 SHA1s. This number is set
    using `chunk_size`.
    """
    to_resources = (
        project.codebaseresources.files()
        .to_codebase()
        .no_status()
        .has_value("sha1")
        .filter(extension__in=extensions)
    )
    resource_count = to_resources.count()

    extensions_str = ", ".join(extensions)
    if logger:
        if resource_count > 0:
            logger(
                f"Matching {resource_count:,d} {extensions_str} resources in PurlDB, "
                "using SHA1"
            )
        else:
            logger(
                f"Skipping matching for {extensions_str} resources, "
                f"as there are {resource_count:,d}"
            )

    _match_purldb_resources(
        project=project,
        to_resources=to_resources,
        matcher_func=matcher_func,
        chunk_size=chunk_size,
        logger=logger,
    )


def _match_purldb_resources(
    project, to_resources, matcher_func, chunk_size=1000, logger=None
):
    resource_count = to_resources.count()
    resource_iterator = to_resources.iterator(chunk_size=chunk_size)
    progress = LoopProgress(resource_count, logger)
    total_matched_count = 0
    total_sha1_count = 0
    processed_resources_count = 0
    resources_by_sha1 = defaultdict(list)
    package_data_by_purldb_urls = {}

    for to_resource in progress.iter(resource_iterator):
        resources_by_sha1[to_resource.sha1].append(to_resource)
        if to_resource.path.endswith(".map"):
            for js_sha1 in js.source_content_sha1_list(to_resource):
                resources_by_sha1[js_sha1].append(to_resource)
        processed_resources_count += 1

        if processed_resources_count % chunk_size == 0:
            resources_by_sha1, matched_count, sha1_count = match_sha1s_to_purldb(
                project=project,
                resources_by_sha1=resources_by_sha1,
                matcher_func=matcher_func,
                package_data_by_purldb_urls=package_data_by_purldb_urls,
            )
            total_matched_count += matched_count
            total_sha1_count += sha1_count

    if resources_by_sha1:
        resources_by_sha1, matched_count, sha1_count = match_sha1s_to_purldb(
            project=project,
            resources_by_sha1=resources_by_sha1,
            matcher_func=matcher_func,
            package_data_by_purldb_urls=package_data_by_purldb_urls,
        )
        total_matched_count += matched_count
        total_sha1_count += sha1_count

    logger(
        f"{total_matched_count:,d} resources matched in PurlDB "
        f"using {total_sha1_count:,d} SHA1s"
    )


def match_purldb_directories(project, logger=None):
    """Match against PurlDB selecting codebase directories."""
    # If we are able to get match results for a directory fingerprint, then that
    # means every resource and directory under that directory is part of a
    # Package. By starting from the root to/ directory, we are attempting to
    # match as many files as we can before attempting to match further down. The
    # more "higher-up" directories we can match to means that we reduce the
    # number of queries made to purldb.
    to_directories = (
        project.codebaseresources.directories()
        .to_codebase()
        .no_status(status=flag.ABOUT_MAPPED)
        .no_status(status=flag.MATCHED_TO_PURLDB_PACKAGE)
        .order_by("path")
    )
    directory_count = to_directories.count()

    if logger:
        logger(
            f"Matching {directory_count:,d} "
            f"director{pluralize(directory_count, 'y,ies')} from to/ in PurlDB"
        )

    directory_iterator = to_directories.iterator(chunk_size=2000)
    progress = LoopProgress(directory_count, logger)

    for directory in progress.iter(directory_iterator):
        directory.refresh_from_db()
        if directory.status != flag.MATCHED_TO_PURLDB_DIRECTORY:
            match_purldb_directory(project, directory)

    matched_count = (
        project.codebaseresources.directories()
        .to_codebase()
        .filter(status=flag.MATCHED_TO_PURLDB_DIRECTORY)
        .count()
    )
    logger(
        f"{matched_count:,d} director{pluralize(matched_count, 'y,ies')} "
        f"matched in PurlDB"
    )


def map_javascript(project, logger=None):
    """Map a packed or minified JavaScript, TypeScript, CSS and SCSS to its source."""
    project_files = project.codebaseresources.files()

    to_resources = project_files.to_codebase().no_status().exclude(name__startswith=".")
    to_resources_dot_map = to_resources.filter(extension=".map")
    to_resources_minified = to_resources.filter(extension__in=[".css", ".js"])

    to_resources_dot_map_count = to_resources_dot_map.count()
    if logger:
        logger(
            f"Mapping {to_resources_dot_map_count:,d} .map resources using javascript "
            f"map against from/ codebase."
        )

    from_resources = project_files.from_codebase().exclude(path__contains="/test/")
    from_resources_index = pathmap.build_index(
        from_resources.values_list("id", "path"), with_subpaths=True
    )

    resource_iterator = to_resources_dot_map.iterator(chunk_size=2000)
    progress = LoopProgress(to_resources_dot_map_count, logger)

    for to_dot_map in progress.iter(resource_iterator):
        _map_javascript_resource(
            to_dot_map, to_resources_minified, from_resources_index, from_resources
        )


def _map_javascript_resource(
    to_map, to_resources_minified, from_resources_index, from_resources
):
    matches = js.get_matches_by_sha1(to_map, from_resources)

    # Use diff_ratio if no sha1 match is found.
    if not matches:
        matches = js.get_matches_by_ratio(to_map, from_resources_index, from_resources)

    transpiled = [to_map]
    if minified_resource := js.get_minified_resource(
        map_resource=to_map,
        minified_resources=to_resources_minified,
    ):
        transpiled.append(minified_resource)

    for resource in transpiled:
        for match, extra_data in matches:
            pipes.make_relation(
                from_resource=match,
                to_resource=resource,
                map_type="js_compiled",
                extra_data=extra_data,
            )
            resource.update(status=flag.MAPPED)


def _map_about_file_resource(project, about_file_resource, to_resources):
    about_file_location = str(about_file_resource.location_path)
    package_data = resolve.resolve_about_package(about_file_location)

    error_message_details = {
        "path": about_file_resource.path,
        "package_data": package_data,
    }
    if not package_data:
        project.add_error(
            description="Cannot create package from ABOUT file",
            model="map_about_files",
            details=error_message_details,
        )
        return

    filename = package_data.get("filename")
    if not filename:
        # Cannot map anything without the about_resource value.
        project.add_error(
            description="ABOUT file does not have about_resource",
            model="map_about_files",
            details=error_message_details,
        )
        return

    ignored_resources = []
    if extra_data := package_data.get("extra_data"):
        ignored_resources = extra_data.get("ignored_resources")

    # Fetch all resources that are covered by the .ABOUT file.
    codebase_resources = to_resources.filter(path__contains=f"/{filename.lstrip('/')}")
    if not codebase_resources:
        # If there's nothing to map on the ``to/`` do not create the package.
        project.add_warning(
            description=(
                "Resource paths listed at about_resource is not found"
                " in the to/ codebase"
            ),
            model="map_about_files",
            details=error_message_details,
        )
        return

    # Ignore resources for paths in `ignored_resources` attribute
    if ignored_resources:
        lookups = Q()
        for resource_path in ignored_resources:
            lookups |= Q(**{"path__contains": resource_path})
        codebase_resources = codebase_resources.filter(~lookups)

    # Create the Package using .ABOUT data and assigned related codebase_resources
    pipes.update_or_create_package(project, package_data, codebase_resources)

    # Map the .ABOUT file resource to all related resources in the ``to/`` side.
    for to_resource in codebase_resources:
        pipes.make_relation(
            from_resource=about_file_resource,
            to_resource=to_resource,
            map_type="about_file",
        )

    codebase_resources.update(status=flag.ABOUT_MAPPED)
    about_file_resource.update(status=flag.ABOUT_MAPPED)


def map_about_files(project, logger=None):
    """Map ``from/`` .ABOUT files to their related ``to/`` resources."""
    project_resources = project.codebaseresources
    from_files = project_resources.files().from_codebase()
    from_about_files = from_files.filter(extension=".ABOUT")
    to_resources = project_resources.to_codebase()

    if logger:
        logger(
            f"Mapping {from_about_files.count():,d} .ABOUT files found in the from/ "
            f"codebase."
        )

    for about_file_resource in from_about_files:
        _map_about_file_resource(project, about_file_resource, to_resources)

        about_file_companions = (
            about_file_resource.siblings()
            .filter(name__startswith=about_file_resource.name_without_extension)
            .filter(extension__in=[".LICENSE", ".NOTICE"])
        )
        about_file_companions.update(status=flag.ABOUT_MAPPED)


def map_javascript_post_purldb_match(project, logger=None):
    """Map minified javascript file based on existing PurlDB match."""
    project_files = project.codebaseresources.files()

    to_resources = project_files.to_codebase()

    to_resources_dot_map = to_resources.filter(
        status=flag.MATCHED_TO_PURLDB_RESOURCE
    ).filter(extension=".map")

    to_resources_minified = to_resources.no_status().filter(
        extension__in=[".css", ".js"]
    )

    to_resources_minified_count = to_resources_minified.count()

    if not to_resources_dot_map:
        logger("No PurlDB matched .map file is available. Skipping.")
        return

    if logger:
        logger(
            f"Mapping {to_resources_minified_count:,d} minified .js and .css "
            f"resources based on existing PurlDB match."
        )

    to_resources_dot_map_index = pathmap.build_index(
        to_resources_dot_map.values_list("id", "path"), with_subpaths=True
    )

    resource_iterator = to_resources_minified.iterator(chunk_size=2000)
    progress = LoopProgress(to_resources_minified_count, logger)

    for to_minified in progress.iter(resource_iterator):
        _map_javascript_post_purldb_match_resource(
            to_minified, to_resources_dot_map, to_resources_dot_map_index
        )


def _map_javascript_post_purldb_match_resource(
    to_minified, to_resources_dot_map, to_resources_dot_map_index
):
    path = Path(to_minified.path.lstrip("/"))
    map_file_name = f"{path.name}.map"
    map_file_path = path.parent / map_file_name

    if not js.is_source_mapping_in_minified(to_minified, map_file_name):
        return

    prospect = pathmap.find_paths(str(map_file_path), to_resources_dot_map_index)
    if not prospect:
        return

    # Only create relations when the number of matches is inferior or equal to
    # the current number of path segment matched.
    too_many_prospects = len(prospect.resource_ids) > prospect.matched_path_length
    if too_many_prospects:
        return

    map_file = to_resources_dot_map.get(id=prospect.resource_ids[0])

    if package := map_file.discovered_packages.first():
        package.add_resources([to_minified])
        to_minified.update(status=flag.MAPPED)


def map_javascript_path(project, logger=None):
    """Map javascript file based on path."""
    project_files = project.codebaseresources.files()

    to_resources_key = (
        project_files.to_codebase()
        .no_status()
        .filter(extension__in=[".map", ".ts"])
        .exclude(name__startswith=".")
        .exclude(path__contains="/node_modules/")
    )

    to_resources = project_files.to_codebase().no_status().exclude(name__startswith=".")

    from_resources = project_files.from_codebase().exclude(path__contains="/test/")
    resource_count = to_resources_key.count()

    if logger:
        logger(
            f"Mapping {resource_count:,d} to/ resources using javascript map "
            f"against from/ codebase."
        )

    from_resources_index = pathmap.build_index(
        from_resources.values_list("id", "path"), with_subpaths=True
    )

    resource_iterator = to_resources_key.iterator(chunk_size=2000)
    progress = LoopProgress(resource_count, logger)
    map_count = 0

    for to_resource in progress.iter(resource_iterator):
        map_count += _map_javascript_path_resource(
            to_resource, to_resources, from_resources_index, from_resources
        )

    logger(f"{map_count:,d} resources mapped")


def _map_javascript_path_resource(
    to_resource, to_resources, from_resources_index, from_resources, map_type="js_path"
):
    """
    Map JavaScript deployed files using their .map files.
    Return the number of mapped files.
    """
    path = Path(to_resource.path.lstrip("/"))

    basename_and_extension = js.get_js_map_basename_and_extension(path.name)
    if not basename_and_extension:
        return 0

    basename, extension = basename_and_extension
    path_parts = (path.parent / basename).parts
    path_parts_len = len(path_parts)

    base_path = path.parent / basename

    prospect = js.PROSPECTIVE_JAVASCRIPT_MAP.get(extension, {})

    max_matched_path = 0
    from_resource, extra_data = None, None
    for source_ext in prospect.get("sources", []):
        match = pathmap.find_paths(f"{base_path}{source_ext}", from_resources_index)

        # Only create relations when the number of matches if inferior or equal to
        # the current number of path segment matched.
        if not match or len(match.resource_ids) > match.matched_path_length:
            continue

        # Don't map resources solely based on their names.
        if match.matched_path_length <= 1:
            continue

        if match.matched_path_length > max_matched_path:
            max_matched_path = match.matched_path_length
            from_resource = from_resources.get(id=match.resource_ids[0])
            extra_data = {"path_score": f"{match.matched_path_length}/{path_parts_len}"}

    return js.map_related_files(
        to_resources,
        to_resource,
        from_resource,
        map_type,
        extra_data,
    )


def map_javascript_colocation(project, logger=None):
    """Map JavaScript files based on neighborhood file mapping."""
    project_files = project.codebaseresources.files()

    to_resources_key = (
        project_files.to_codebase()
        .no_status()
        .filter(extension__in=[".map", ".ts"])
        .exclude(name__startswith=".")
        .exclude(path__contains="/node_modules/")
    )

    to_resources = project_files.to_codebase().no_status().exclude(name__startswith=".")

    from_resources = project_files.from_codebase().exclude(path__contains="/test/")
    resource_count = to_resources_key.count()

    if logger:
        logger(
            f"Mapping {resource_count:,d} to/ resources against from/ codebase"
            " based on neighborhood file mapping."
        )

    resource_iterator = to_resources_key.iterator(chunk_size=2000)
    progress = LoopProgress(resource_count, logger)
    map_count = 0

    for to_resource in progress.iter(resource_iterator):
        map_count += _map_javascript_colocation_resource(
            to_resource, to_resources, from_resources, project
        )


def _map_javascript_colocation_resource(
    to_resource, to_resources, from_resources, project
):
    """Map JavaScript files based on neighborhood file mapping."""
    path = to_resource.path

    if to_resource.status or "-extract/" not in path:
        return 0

    coloaction_path, _ = path.rsplit("-extract/", 1)

    neighboring_relations = project.codebaserelations.filter(
        to_resource__path__startswith=coloaction_path,
        map_type__in=["java_to_class", "js_compiled"],
    )

    if not neighboring_relations:
        return 0

    common_parent = neighboring_relations[0].from_resource.path
    for relation in neighboring_relations:
        s2 = relation.from_resource.path
        common_parent, _ = common_prefix(common_parent, s2)

    # No colocation mapping if the common parent is the root directory.
    if not common_parent or len(Path(common_parent).parts) < 2:
        return 0

    from_neighboring_resources = from_resources.filter(path__startswith=common_parent)

    if sources := js.get_map_sources(to_resource):
        with suppress(MultipleObjectsReturned, ObjectDoesNotExist):
            from_resource = from_neighboring_resources.get(path__endswith=sources[0])
            return js.map_related_files(
                to_resources,
                to_resource,
                from_resource,
                "js_colocation",
                {},
            )

    from_neighboring_resources_index = pathmap.build_index(
        from_neighboring_resources.values_list("id", "path"), with_subpaths=True
    )

    return _map_javascript_path_resource(
        to_resource,
        to_resources,
        from_neighboring_resources_index,
        from_neighboring_resources,
        map_type="js_colocation",
    )


def flag_processed_archives(project):
    """
    Flag package archives as processed if they meet the following criteria:

    1. They have no assigned status.
    2. They are identified as package archives.
    3. All resources inside the corresponding archive '-extract' directory
       have an assigned status.

    This function iterates through the package archives in the project and
    checks whether all resources within their associated '-extract' directory
    have statuses. If so, it updates the status of the package archive to
    "archive-processed".
    """
    to_resources = (
        project.codebaseresources.all().to_codebase().no_status().order_by("-path")
    )

    for archive_resource in to_resources.archives():
        extract_path = archive_resource.path + EXTRACT_SUFFIX
        archive_unmapped_resources = to_resources.filter(path__startswith=extract_path)
        # Check if all resources in the archive "-extract" directory have been mapped.
        # Flag the archive resource as processed only when all resources are mapped.
        if not archive_unmapped_resources.exists():
            archive_resource.update(status=flag.ARCHIVE_PROCESSED)


def map_thirdparty_npm_packages(project, logger=None):
    """Map thirdparty package using package.json metadata."""
    project_files = project.codebaseresources.files()

    to_package_json = (
        project_files.to_codebase()
        .filter(path__regex=r"^.*\/node_modules\/.*\/package\.json$")
        .exclude(path__regex=r"^.*\/node_modules\/.*\/node_modules\/.*$")
    )

    to_resources = project_files.to_codebase().no_status()
    resource_count = to_package_json.count()

    if logger:
        logger(
            f"Mapping {resource_count:,d} to/ resources against from/ codebase"
            " based on package.json metadata."
        )

    resource_iterator = to_package_json.iterator(chunk_size=2000)
    progress = LoopProgress(resource_count, logger)
    map_count = 0

    for package_json in progress.iter(resource_iterator):
        map_count += _map_thirdparty_npm_packages(package_json, to_resources, project)

    logger(f"{map_count:,d} resources mapped")


def _map_thirdparty_npm_packages(package_json, to_resources, project):
    """Map thirdparty package using package.json metadata."""
    path = Path(package_json.path.lstrip("/"))
    path_parent = str(path.parent)

    package = next(NpmPackageJsonHandler.parse(package_json.location))

    package_resources = to_resources.filter(path__startswith=path_parent)

    purl_in_package = all([package, package.type, package.name, package.version])

    if not package_resources or not purl_in_package:
        return 0

    package_data = package.to_dict()
    package_data.pop("dependencies")
    pipes.update_or_create_package(
        project=project,
        package_data=package_data,
        codebase_resources=package_resources,
    )

    package_resources.no_status().update(status=flag.NPM_PACKAGE_LOOKUP)
    return package_resources.count()


def get_from_files_related_with_not_in_package_to_files(project):
    """
    Return from-side resource files that have one or more relations
    with to-side resources that are not part of a package.
    Only resources with a ``detected_license_expression`` value are returned.
    """
    files_qs = project.codebaseresources.files()
    to_files_without_package = files_qs.to_codebase().not_in_package()
    from_files_qs = (
        files_qs.from_codebase()
        .has_license_expression()
        .filter(
            related_to__to_resource__in=Subquery(to_files_without_package.values("pk"))
        )
    )
    return from_files_qs


def create_local_files_packages(project):
    """
    Create local-files packages for codebase resources not part of a package.

    Resources are grouped by license_expression within a local-files packages.
    """
    from_files_qs = get_from_files_related_with_not_in_package_to_files(project)

    # Do not include any other fields in the ``values()``
    license_field = CodebaseResource.license_expression_field
    grouped_by_license = from_files_qs.values(license_field).order_by(license_field)

    grouped_by_license = grouped_by_license.annotate(
        grouped_resource_ids=ArrayAgg("id", distinct=True),
        grouped_copyrights=ArrayAgg("copyrights", distinct=True),
    )

    for group in grouped_by_license:
        codebase_resource_ids = sorted(set(group["grouped_resource_ids"]))
        copyrights = [
            entry["copyright"]
            for copyrights in group["grouped_copyrights"]
            for entry in copyrights
        ]

        defaults = {
            "declared_license_expression": group.get("detected_license_expression"),
            # The Counter is used to sort by most frequent values.
            "copyright": "\n\n".join(Counter(copyrights).keys()),
        }
        pipes.create_local_files_package(project, defaults, codebase_resource_ids)


def match_resources_with_no_java_source(project, logger=None):
    """
    Match resources with ``no-java-source`` to PurlDB, if no match
    is found update status to ``requires-review``.
    """
    project_files = project.codebaseresources.files()

    to_no_java_source = project_files.to_codebase().filter(status=flag.NO_JAVA_SOURCE)

    if to_no_java_source:
        resource_count = to_no_java_source.count()
        if logger:
            logger(
                f"Mapping {resource_count:,d} to/ resources with {flag.NO_JAVA_SOURCE} "
                "status in PurlDB using SHA1"
            )

        _match_purldb_resources(
            project=project,
            to_resources=to_no_java_source,
            matcher_func=match_purldb_resource,
            logger=logger,
        )
        to_no_java_source.exclude(status=flag.MATCHED_TO_PURLDB_RESOURCE).update(
            status=flag.REQUIRES_REVIEW
        )


def match_unmapped_resources(project, matched_extensions=None, logger=None):
    """
    Match resources with empty status to PurlDB, if unmatched
    update status as ``requires-review``.
    """
    project_files = project.codebaseresources.files()

    to_unmapped = project_files.to_codebase().no_status().exclude(is_media=True)

    if matched_extensions:
        to_unmapped.exclude(extension__in=matched_extensions)

    if to_unmapped:
        resource_count = to_unmapped.count()
        if logger:
            logger(
                f"Mapping {resource_count:,d} to/ resources with "
                "empty status in PurlDB using SHA1"
            )

        _match_purldb_resources(
            project=project,
            to_resources=to_unmapped,
            matcher_func=match_purldb_resource,
            logger=logger,
        )
        to_unmapped.exclude(status=flag.MATCHED_TO_PURLDB_RESOURCE).update(
            status=flag.REQUIRES_REVIEW
        )

    to_without_status = project_files.to_codebase().no_status()

    to_without_status.filter(is_media=True).update(status=flag.IGNORED_MEDIA_FILE)

    to_without_status.update(status=flag.REQUIRES_REVIEW)


def flag_undeployed_resources(project):
    """Update status for undeployed files."""
    project_files = project.codebaseresources.files()
    from_unmapped = project_files.from_codebase().no_status()
    from_unmapped.update(status=flag.NOT_DEPLOYED)


def scan_unmapped_to_files(project, logger=None):
    """
    Scan unmapped/matched ``to/`` files for copyrights, licenses,
    emails, and urls and update the status to `requires-review`.
    """
    scan_files = (
        project.codebaseresources.files()
        .to_codebase()
        .filter(status=flag.REQUIRES_REVIEW)
    )
    scancode.scan_for_files(project, scan_files, progress_logger=logger)

    project.codebaseresources.files().to_codebase().filter(status=flag.SCANNED).update(
        status=flag.REQUIRES_REVIEW
    )


def flag_deployed_from_resources_with_missing_license(project, doc_extensions=None):
    """Update the status for deployed from files with missing license."""
    # Retrieve scanned from files with an empty ``detected_license_expression``
    # or a ``unknown`` license expression.
    scanned_from_files = (
        project.codebaseresources.files().from_codebase().filter(status=flag.SCANNED)
    )

    # Media files don't require any review.
    scanned_from_files.filter(is_media=True).update(status=flag.IGNORED_MEDIA_FILE)

    # Document files don't require any review.
    if doc_extensions:
        scanned_from_files.filter(extension__in=doc_extensions).update(
            status=flag.IGNORED_DOC_FILE
        )

    no_license_files = scanned_from_files.filter(detected_license_expression="")
    unknown_license_files = scanned_from_files.unknown_license()

    no_license_files.update(status=flag.NO_LICENSES)
    unknown_license_files.update(status=flag.UNKNOWN_LICENSE)


def handle_dangling_deployed_legal_files(project, logger):
    """
    Scan the legal files with empty status and update status
    to `REVIEW_DANGLING_LEGAL_FILE`.
    """
    to_resources = project.codebaseresources.files().to_codebase().no_status()

    legal_file_filter = Q()

    for token in LEGAL_STARTS_ENDS:
        legal_file_filter |= Q(name__istartswith=token)
        legal_file_filter |= Q(name__iendswith=token)
        legal_file_filter |= Q(name__iendswith=Concat(Value(token), F("extension")))

    legal_files = to_resources.filter(legal_file_filter)

    if legal_files:
        scancode.scan_resources(
            resource_qs=legal_files,
            scan_func=scancode.scan_file,
            save_func=save_scan_legal_file_results,
            progress_logger=logger,
        )


def save_scan_legal_file_results(codebase_resource, scan_results, scan_errors):
    """
    Save the legal resource scan results with `REVIEW_DANGLING_LEGAL_FILE`
    status in the database. Create project errors if any occurred
    during the scan.
    """
    status = flag.REVIEW_DANGLING_LEGAL_FILE

    if scan_errors:
        codebase_resource.add_errors(scan_errors)
        status = flag.SCANNED_WITH_ERROR

    codebase_resource.set_scan_results(scan_results, status)


def flag_whitespace_files(project):
    """
    Flag whitespace files with size less than or equal
    to 100 byte as ignored.
    """
    resources = project.codebaseresources.files().no_status().filter(size__lte=100)

    # Set of whitespace characters.
    whitespace_set = set(b" \n\r\t\f\b")

    for resource in resources:
        binary_data = open(resource.location, "rb").read()
        binary_set = set(binary_data)
        non_whitespace_bytes = binary_set - whitespace_set

        # If resource contains only whitespace characters.
        if not non_whitespace_bytes:
            resource.update(status=flag.IGNORED_WHITESPACE_FILE)


def _map_dwarf_path_resource(
    to_resource, from_resources, from_resources_index, logger=None,
):
    """
    Map DWARF dwarf_paths found in the ``to_resource`` extra_data to
    dwarf_paths of the ``from_resources`` CodebaseResource queryset using the
    precomputed ``from_resources_index`` path index.
    """
    dwarf_source_paths = to_resource.extra_data.get("dwarf_source_paths") or {}
    compiled_paths = dwarf_source_paths.get("compiled_paths") or []
    included_paths = dwarf_source_paths.get("included_paths") or []
    dwarf_paths_and_map_type = [
        (compiled_paths, "dwarf_compiled_paths"),
        (included_paths, "dwarf_included_paths"),
    ]

    dpnm = to_resource.extra_data["dwarf_paths_not_mapped"] = []
    relations = {}

    for dwarf_paths, map_type in dwarf_paths_and_map_type:
        for dwarf_path in dwarf_paths:

            match = pathmap.find_paths(dwarf_path, from_resources_index)
            if not match:
                dpnm.append(dwarf_path)
                continue

            # short dwarf path matched more than once is treated as not mapped for now
            matched_path_length = match.matched_path_length

            if matched_path_length == 1 and len(match.resource_ids) != 1:
                dpnm.append(dwarf_path)
                continue

            # Sort match by most similar to the From/ side dwarf_path e.g. if we match
            # some/foo/bar/baz.c and this/other/foo/bar/baz.c and the From is
            # that/foo/bar/baz.c, some/foo/bar/baz.c has the most segments
            # matched wins, e.g., the shortest From/ path wins.
            matched_from_resources = [
                from_resources.get(id=rid) for rid in match.resource_ids
            ]
            matched_from_resources.sort(key=lambda res: (len(res.path.strip("/").split("/")), res.path))
            winning_from_resource = matched_from_resources[0]

            # Do not count the "to/" segment as it is not "matchable"
            # always strip leading segment ("to" or from" first segment)
            dwarf_path_length = len(dwarf_path.strip("/").split("/")) - 1

            extra_data = {
                "path_score": f"{matched_path_length}/{dwarf_path_length}",
                "dwarf_path": dwarf_path,
            }

            rel_key = (winning_from_resource.path, to_resource.path, map_type)
            if rel_key not in relations:
                relation = CodebaseRelation(
                    project=winning_from_resource.project,
                    from_resource=winning_from_resource,
                    to_resource=to_resource,
                    map_type=map_type,
                    extra_data=extra_data,
                )
                relations[rel_key] = relation

    if relations:
        rels = CodebaseRelation.objects.bulk_create(relations.values())
        if logger:
            logger(f"Created {len(rels)} mapping using DWARF for: {to_resource.path!r}")
    else:
        if logger:
            logger(f"No mapping using DWARF for: {to_resource.path!r}")

    if dpnm:
        # save the "dwarf dwarf_paths not mapped"
        to_resource.save()
        if logger:
            logger(f"WARNING: DWARF paths NOT mapped for: {to_resource.path!r}: " + ", ".join(map(repr, dpnm)))


def map_dwarf_path(project, logger=None):
    """Map DWARF paths using similarities of path suffixes."""
    project_files = project.codebaseresources.files().no_status()
    from_resources = project_files.from_codebase()
    to_resources = project_files.to_codebase().has_no_relation()
    to_resources = to_resources.filter(extra_data__has_key="dwarf_source_paths")
    resource_count = to_resources.count()

    if logger:
        logger(
            f"Mapping {resource_count:,d} to/ resources using DWARF paths "
            f"with {from_resources.count():,d} from/ resources."
        )

    from_resources_index = pathmap.build_index(
        from_resources.values_list("id", "path"), with_subpaths=True
    )

    if logger:
        logger(
            f"Done building from/ resources index."
        )

    resource_iterator = to_resources.iterator(chunk_size=2000)
    last_percent = 0
    start_time = timer()
    for resource_index, to_resource in enumerate(resource_iterator):
        last_percent = pipes.log_progress(
            logger,
            resource_index,
            resource_count,
            last_percent,
            increment_percent=10,
            start_time=start_time,
        )
        if logger:
            logger(
                f"Mapping to/ resource: {to_resource.path!r} using DWARF paths."
            )

        _map_dwarf_path_resource(
            to_resource,
            from_resources,
            from_resources_index,
            logger=logger,
        )
