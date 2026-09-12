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

import re
from collections import Counter
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from re import match as regex_match

from django.contrib.postgres.aggregates.general import ArrayAgg
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import F
from django.db.models import Q
from django.db.models import Value
from django.db.models.expressions import Subquery
from django.db.models.functions import Concat
from django.template.defaultfilters import pluralize

from binary_inspector.binary import collect_and_parse_macho_symbols
from binary_inspector.binary import collect_and_parse_winpe_symbols
from commoncode.paths import common_prefix
from elf_inspector.binary import collect_and_parse_elf_symbols
from elf_inspector.dwarf import get_dwarf_paths
from extractcode import EXTRACT_SUFFIX
from go_inspector.plugin import collect_and_parse_symbols
from packagedcode.npm import NpmPackageJsonHandler
from rust_inspector.binary import collect_and_parse_rust_symbols
from summarycode.classify import LEGAL_STARTS_ENDS

from aboutcode.pipeline import LoopProgress
from scanpipe import pipes
from scanpipe.models import CodebaseRelation
from scanpipe.models import CodebaseResource
from scanpipe.models import convert_glob_to_django_regex
from scanpipe.pipes import d2d_config
from scanpipe.pipes import flag
from scanpipe.pipes import get_resource_diff_ratio
from scanpipe.pipes import js
from scanpipe.pipes import jvm
from scanpipe.pipes import pathmap
from scanpipe.pipes import purldb
from scanpipe.pipes import resolve
from scanpipe.pipes import scancode
from scanpipe.pipes import stringmap
from scanpipe.pipes import symbolmap
from scanpipe.pipes import symbols

FROM = "from/"
TO = "to/"


def get_inputs(project):
    """
    Locate the ``from`` and ``to`` input files in project inputs/ directory.
    The input source can be flagged using a "from-" / "to-" prefix in the filename or
    by adding a "#from" / "#to" fragment at the end of the download URL.
    """
    from_files = list(project.inputs("from*"))
    from_files.extend([input.path for input in project.inputsources.filter(tag="from")])

    to_files = list(project.inputs("to*"))
    to_files.extend([input.path for input in project.inputsources.filter(tag="to")])

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


def _map_jvm_to_class_resource(
    to_resource, from_resources, from_classes_index, jvm_lang: jvm.JvmLanguage
):
    """
    Map the ``to_resource`` .class file Resource with a Resource in
    ``from_resources`` source files, using the ``from_classes_index`` index of
    from/ fully qualified binary files.
    """
    for extension in jvm_lang.source_extensions:
        # Perform basic conversion from .class to source file path
        source_path = jvm_lang.get_source_path(
            path=to_resource.path, extension=extension
        )
        # Perform basic mapping without normalization for scenarios listed in
        # https://github.com/aboutcode-org/scancode.io/issues/1873
        match = pathmap.find_paths(path=source_path, index=from_classes_index)

        if not match:
            normalized_path = jvm_lang.get_normalized_path(
                path=to_resource.path, extension=extension
            )
            match = pathmap.find_paths(path=normalized_path, index=from_classes_index)
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
                map_type=jvm_lang.binary_map_type,
                extra_data={"from_source_root": f"{from_source_root}/"},
            )


def map_jvm_to_class(project, jvm_lang: jvm.JvmLanguage, logger=None):
    """
    Map to/ compiled Jvm's binary files to from/ using Jvm language's fully
    qualified paths and indexing from/ Jvm lang's source files.
    """
    project_files = project.codebaseresources.files()
    # Collect all files from "from_codebase", even if they already have a
    # status or are mapped. This is necessary because the deploy codebase
    # may contain sources that match "from_codebase" via checksum. If those
    # checksum-matched files are excluded from mapping, it can result in
    # .class files failing to resolve. See
    # https://github.com/aboutcode-org/scancode.io/issues/1854#issuecomment-3273472895
    from_resources = project_files.from_codebase()
    to_resources = project_files.to_codebase().no_status().has_no_relation()

    has_source_pkg_attr_name = {
        f"extra_data__{jvm_lang.source_package_attribute_name}__isnull": False
    }

    to_resources_binary_extension = to_resources.filter(
        extension__in=jvm_lang.binary_extensions
    )
    from_resources_source_extension = (
        from_resources.filter(extension__in=jvm_lang.source_extensions)
        # The source_package_attribute_name extra_data value
        # is set during the `find_jvm_package`,
        # it is required to build the index.
        .filter(**has_source_pkg_attr_name)
    )
    to_resource_count = to_resources_binary_extension.count()
    from_resource_count = from_resources_source_extension.count()

    if not from_resource_count:
        logger(f"No {jvm_lang.source_extensions} resources to map.")
        return

    if logger:
        logger(
            f"Mapping {to_resource_count:,d} .class (or other deployed file) "
            f"resources to {from_resource_count:,d} {jvm_lang.source_extensions}"
        )

    # build an index using from-side fully qualified class file names
    # built from the source_package_attribute_name and file name
    indexables = jvm_lang.get_indexable_qualified_paths(from_resources_source_extension)

    # we do not index subpath since we want to match only fully qualified names
    from_classes_index = pathmap.build_index(indexables, with_subpaths=False)

    resource_iterator = to_resources_binary_extension.iterator(chunk_size=2000)
    progress = LoopProgress(to_resource_count, logger)

    for to_resource in progress.iter(resource_iterator):
        _map_jvm_to_class_resource(
            to_resource=to_resource,
            from_resources=from_resources,
            from_classes_index=from_classes_index,
            jvm_lang=jvm_lang,
        )


def find_jvm_packages(project, jvm_lang: jvm.JvmLanguage, logger=None):
    """
    Collect the JVM packages of source files for a ``project``.

    Multiprocessing is enabled by default on this pipe, the number of processes
    can be controlled through the SCANCODEIO_PROCESSES setting.

    Note: we use the same API as the ScanCode scans by design
    """
    resources = project.codebaseresources.files().no_status().from_codebase()

    from_jvm_resources = resources.filter(extension__in=jvm_lang.source_extensions)

    if logger:
        logger(
            f"Finding {jvm_lang.name} packages for {from_jvm_resources.count():,d} "
            f"{jvm_lang.source_extensions} resources."
        )

    scancode.scan_resources(
        resource_qs=from_jvm_resources,
        scan_func=jvm_lang.scan_for_source_package,
        save_func=save_jvm_package_scan_results,
        progress_logger=logger,
    )


def save_jvm_package_scan_results(codebase_resource, scan_results, scan_errors):
    """
    Save the resource Jvm package scan results in the database as Resource.extra_data.
    Create project errors if any occurred during the scan.
    """
    # The status is only updated in case of errors.
    if scan_errors:
        codebase_resource.add_errors(scan_errors)
        codebase_resource.update(status=flag.SCANNED_WITH_ERROR)
    else:
        codebase_resource.update_extra_data(scan_results)


def _map_jar_to_jvm_source_resource(
    jar_resource, to_resources, from_resources, jvm_lang: jvm.JvmLanguage
):
    jar_extracted_path = get_extracted_path(jar_resource)
    jar_extracted_dot_class_files = list(
        to_resources.filter(
            extension__in=jvm_lang.binary_extensions,
            path__startswith=jar_extracted_path,
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
    jvm_binary_map_type_extra_data_list = CodebaseRelation.objects.filter(
        to_resource__in=dot_class_file_ids, map_type=jvm_lang.binary_map_type
    ).values_list("extra_data", flat=True)

    from_source_roots = [
        extra_data.get("from_source_root", "")
        for extra_data in jvm_binary_map_type_extra_data_list
    ]
    if len(set(from_source_roots)) != 1:
        # Could not determine a common root directory for the binary_map_type files
        return

    common_source_root = from_source_roots[0].rstrip("/")
    if common_from_resource := from_resources.get_or_none(path=common_source_root):
        pipes.make_relation(
            from_resource=common_from_resource,
            to_resource=jar_resource,
            map_type="jar_to_source",
        )


def map_jar_to_jvm_source(project, jvm_lang: jvm.JvmLanguage, logger=None):
    """Map .jar files to their related source directory."""
    project_files = project.codebaseresources.files()
    # Include the directories to map on the common source
    from_resources = project.codebaseresources.from_codebase().has_no_relation()
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
        _map_jar_to_jvm_source_resource(
            jar_resource, to_resources, from_resources, jvm_lang=jvm_lang
        )


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
            # directories under `foo/bar/` that start with 1, such as
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
            if not (resources and package_data):
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
    containing an empty defaultdict(list), the number of matches and the number
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
        if (
            to_resource.path.endswith(".map")
            and "json" in to_resource.file_type.lower()
        ):
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


@dataclass
class AboutFileIndexes:
    """
    About file indexes are used to create packages from
    About files and map the resources described in them
    to the respective packages created, using regex path
    patterns and other About file data.
    """

    # Mapping of About file paths and the regex pattern
    # string for the files documented
    regex_by_about_path: dict
    # Mapping of About file paths and a list of path pattern
    # strings, for the files to be ignored
    ignore_regex_by_about_path: dict
    # Resource objects for About files present in the codebase,
    # by their path
    about_resources_by_path: dict
    # mapping of package data present in the About file, by path
    about_pkgdata_by_path: dict
    # List of mapped resources for each About file, by path
    mapped_resources_by_aboutpath: dict

    @classmethod
    def create_indexes(cls, project, from_about_files, logger=None):
        """
        Return an ABOUT file index, containing path pattern mappings,
        package data, and resources, created from `from_about_files`,
        the About file resources.
        """
        about_pkgdata_by_path = {}
        regex_by_about_path = {}
        ignore_regex_by_about_path = {}
        about_resources_by_path = {}
        mapped_resources_by_aboutpath = {}

        count_indexed_about_files = 0

        for about_file_resource in from_about_files:
            package_data = resolve.resolve_about_package(
                input_location=str(about_file_resource.location_path)
            )
            error_message_details = {"package_data": package_data}
            if not package_data:
                project.add_error(
                    description="Cannot create package from ABOUT file",
                    model="map_about_files",
                    details=error_message_details,
                    object_instance=about_file_resource,
                )
                continue

            about_pkgdata_by_path[about_file_resource.path] = package_data
            files_pattern = package_data.get("filename")
            if not files_pattern:
                # Cannot map anything without the about_resource value.
                project.add_error(
                    description="ABOUT file does not have about_resource",
                    model="map_about_files",
                    details=error_message_details,
                    object_instance=about_file_resource,
                )
                continue
            else:
                count_indexed_about_files += 1
                regex = convert_glob_to_django_regex(files_pattern)
                regex_by_about_path[about_file_resource.path] = regex

            if extra_data := package_data.get("extra_data"):
                ignore_regex = []
                for pattern in extra_data.get("ignored_resources", []):
                    ignore_regex.append(convert_glob_to_django_regex(pattern))
                if ignore_regex:
                    ignore_regex_by_about_path[about_file_resource.path] = ignore_regex

            about_resources_by_path[about_file_resource.path] = about_file_resource
            mapped_resources_by_aboutpath[about_file_resource.path] = []

        if logger:
            logger(
                f"Created mapping index from {count_indexed_about_files:,d} .ABOUT "
                f"files in the from/ codebase."
            )

        return cls(
            about_pkgdata_by_path=about_pkgdata_by_path,
            regex_by_about_path=regex_by_about_path,
            ignore_regex_by_about_path=ignore_regex_by_about_path,
            about_resources_by_path=about_resources_by_path,
            mapped_resources_by_aboutpath=mapped_resources_by_aboutpath,
        )

    def get_matched_about_path(self, to_resource):
        """
        Map `to_resource` using the about file index, and if
        mapped, return the path string to the About file it
        was mapped to, and if not mapped or ignored, return
        None.
        """
        resource_mapped = False
        for about_path, regex_pattern in self.regex_by_about_path.items():
            if regex_match(pattern=regex_pattern, string=to_resource.path):
                resource_mapped = True
                break

        if not resource_mapped:
            return

        ignore_regex_patterns = self.ignore_regex_by_about_path.get(about_path, [])
        ignore_resource = False
        for ignore_regex_pattern in ignore_regex_patterns:
            if regex_match(pattern=ignore_regex_pattern, string=to_resource.path):
                ignore_resource = True
                break

        if ignore_resource:
            return

        return about_path

    def map_deployed_to_devel_using_about(self, to_resources):
        """
        Return mapped resources which are mapped using the
        path patterns in About file indexes. Resources are
        mapped for each About file in the index, and
        their status is updated accordingly.
        """
        mapped_to_resources = []

        for to_resource in to_resources:
            about_path = self.get_matched_about_path(to_resource)
            if not about_path:
                continue

            mapped_resources_about = self.mapped_resources_by_aboutpath.get(about_path)
            if mapped_resources_about:
                mapped_resources_about.append(to_resource)
            else:
                self.mapped_resources_by_aboutpath[about_path] = [to_resource]
            mapped_to_resources.append(to_resource)
            to_resource.update(status=flag.ABOUT_MAPPED)

        return mapped_to_resources

    def get_about_file_companions(self, about_path):
        """
        Given an ``about_path`` path string to an About file,
        get CodebaseResource objects for the companion license
        and notice files.
        """
        about_file_resource = self.about_resources_by_path.get(about_path)
        about_file_extra_data = self.about_pkgdata_by_path.get(about_path).get(
            "extra_data"
        )

        about_file_companion_names = [
            about_file_extra_data.get("license_file"),
            about_file_extra_data.get("notice_file"),
        ]
        about_file_companions = about_file_resource.siblings().filter(
            name__in=about_file_companion_names
        )
        return about_file_companions

    def create_about_packages_relations(self, project):
        """
        Create packages using About file package data, if the About file
        has mapped resources on the to/ codebase and creates the mappings
        for the package created and mapped resources.
        """
        about_purls = set()
        mapped_about_resources = []

        for about_path, mapped_resources in self.mapped_resources_by_aboutpath.items():
            about_file_resource = self.about_resources_by_path[about_path]
            package_data = self.about_pkgdata_by_path[about_path]

            if not mapped_resources:
                error_message_details = {
                    "resource_path": about_path,
                    "package_data": package_data,
                }
                project.add_warning(
                    description=(
                        "Resource paths listed at about_resource is not found"
                        " in the to/ codebase"
                    ),
                    model="map_about_files",
                    details=error_message_details,
                )
                continue

            # Create the Package using .ABOUT data and assign related codebase_resources
            about_package = pipes.update_or_create_package(
                project=project,
                package_data=package_data,
                codebase_resources=mapped_resources,
            )
            about_purls.add(about_package.purl)
            mapped_about_resources.append(about_file_resource)

            # Map the .ABOUT file resource to all related resources in the ``to/`` side.
            for mapped_resource in mapped_resources:
                pipes.make_relation(
                    from_resource=about_file_resource,
                    to_resource=mapped_resource,
                    map_type="about_file",
                )

            about_file_resource.update(status=flag.ABOUT_MAPPED)

            about_file_companions = self.get_about_file_companions(about_path)
            about_file_companions.update(status=flag.ABOUT_MAPPED)

        return about_purls, mapped_about_resources


def map_about_files(project, logger=None):
    """Map ``from/`` .ABOUT files to their related ``to/`` resources."""
    project_resources = project.codebaseresources
    from_about_files = (
        project_resources.files().from_codebase().filter(extension=".ABOUT")
    )
    if not from_about_files.exists():
        return

    if logger:
        logger(
            f"Mapping {from_about_files.count():,d} .ABOUT files found in the from/ "
            f"codebase."
        )

    indexes = AboutFileIndexes.create_indexes(
        project=project, from_about_files=from_about_files
    )

    # Ignoring empty or ignored files as they are not relevant anyway
    to_resources = project_resources.to_codebase().no_status()
    mapped_to_resources = indexes.map_deployed_to_devel_using_about(
        to_resources=to_resources,
    )
    if logger:
        logger(
            f"Mapped {len(mapped_to_resources):,d} resources from the "
            f"to/ codebase to the About files in the from. codebase."
        )

    about_purls, mapped_about_resources = indexes.create_about_packages_relations(
        project=project,
    )
    if logger:
        logger(
            f"Created {len(about_purls):,d} new packages from "
            f"{len(mapped_about_resources):,d} About files which "
            f"were mapped to resources in the to/ side."
        )


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


def flag_generated_file(project):
    """Flag generated files based on path patterns or bytecode markers."""
    to_resources = (
        project.codebaseresources.all()
        .to_codebase()
        .no_status()
        .has_no_relation()
        .path_pattern("*.class")
    )
    for resource in to_resources:
        reason = None
        path_segments = resource.location.split("/")
        if any(
            seg.lower() == "generated"
            or seg.lower().startswith("generated-")
            or seg.lower().startswith("generated_")
            for seg in path_segments
        ):
            reason = "Path pattern matches generated directory convention"
        else:
            try:
                data = Path(resource.location).read_bytes()
                reason = is_generated_code(data)
            except Exception as e:
                print(f"Could not process {resource}: {e}")
        if reason:
            resource.update(status=flag.GENERATED)
            resource.update_extra_data({"Generated code": reason})


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
            "copyright": "\n".join(Counter(copyrights).keys()),
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


def ignore_unmapped_resources_from_config(project, patterns_to_ignore, logger=None):
    """Ignore unmapped resources for a project using `patterns_to_ignore`."""
    ignored_resources_count = flag.flag_ignored_patterns(
        codebaseresources=project.codebaseresources.to_codebase().no_status(),
        patterns=patterns_to_ignore,
        status=flag.IGNORED_FROM_CONFIG,
    )
    if logger:
        logger(
            f"Ignoring {ignored_resources_count:,d} to/ resources with "
            "ecosystem specific configurations."
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


def scan_ignored_to_files(project, logger=None):
    """
    Scan status="ignored-from-config" ``to/`` files for copyrights, licenses,
    emails, and urls.
    """
    scan_files = (
        project.codebaseresources.files()
        .to_codebase()
        .filter(status=flag.IGNORED_FROM_CONFIG)
    )

    # Capture the specific files id
    scan_file_ids = list(scan_files.values_list("id", flat=True))

    if not scan_file_ids:
        return

    scancode.scan_for_files(project, scan_files, progress_logger=logger)

    # Revert to the original status value
    project.codebaseresources.filter(id__in=scan_file_ids, status=flag.SCANNED).update(
        status=flag.IGNORED_FROM_CONFIG
    )


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

    # Capture the specific files id
    scan_file_ids = list(scan_files.values_list("id", flat=True))

    if not scan_file_ids:
        return

    scancode.scan_for_files(project, scan_files, progress_logger=logger)

    # Revert to the original status value
    project.codebaseresources.filter(id__in=scan_file_ids, status=flag.SCANNED).update(
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
        with open(resource.location, "rb") as f:
            binary_data = f.read()
        binary_set = set(binary_data)
        non_whitespace_bytes = binary_set - whitespace_set

        # If resource contains only whitespace characters.
        if not non_whitespace_bytes:
            resource.update(status=flag.IGNORED_WHITESPACE_FILE)


def match_purldb_resources_post_process(project, logger=None):
    """Choose the best package for PurlDB matched resources."""
    to_extract_directories = (
        project.codebaseresources.directories()
        .to_codebase()
        .filter(path__regex=r"^.*-extract$")
    )

    to_resources = project.codebaseresources.files().filter(
        status=flag.MATCHED_TO_PURLDB_RESOURCE
    )

    resource_count = to_extract_directories.count()

    if logger:
        logger(
            f"Refining matching for {resource_count:,d} "
            f"{flag.MATCHED_TO_PURLDB_RESOURCE} archives."
        )

    resource_iterator = to_extract_directories.iterator(chunk_size=2000)
    progress = LoopProgress(resource_count, logger)
    map_count = 0

    for directory in progress.iter(resource_iterator):
        map_count += _match_purldb_resources_post_process(directory, to_resources)

    logger(f"{map_count:,d} resource processed")


def _match_purldb_resources_post_process(directory, to_resources):
    # Escape special character in directory path
    escaped_directory_path = re.escape(directory.path)

    # Exclude the content of nested archive.
    interesting_codebase_resources = (
        to_resources.filter(path__startswith=directory.path)
        .filter(status=flag.MATCHED_TO_PURLDB_RESOURCE)
        .exclude(path__regex=rf"^{escaped_directory_path}.*-extract\/.*$")
    )

    if not interesting_codebase_resources:
        return 0

    packages_map = {}

    for resource in interesting_codebase_resources:
        for package in resource.discovered_packages.all():
            if package in packages_map:
                packages_map[package].append(resource)
            else:
                packages_map[package] = [resource]

    # Rank the packages by most number of matched resources.
    ranked_packages = dict(
        sorted(packages_map.items(), key=lambda item: len(item[1]), reverse=True)
    )

    for resource in interesting_codebase_resources:
        resource.discovered_packages.clear()

    for package, resources in ranked_packages.items():
        unmapped_resources = [
            resource
            for resource in resources
            if not resource.discovered_packages.exists()
        ]
        if unmapped_resources:
            package.add_resources(unmapped_resources)

    return interesting_codebase_resources.count()


def map_paths_resource(
    to_resource, from_resources, from_resources_index, map_types, logger=None
):
    """
    Map paths found in the ``to_resource`` extra_data to paths of the ``from_resources``
    CodebaseResource queryset using the precomputed ``from_resources_index`` path index.
    """
    # Accumulate unique relation objects for bulk creation
    relations_to_create = {}

    for map_type in map_types:
        # These are of type string
        paths_in_binary = to_resource.extra_data.get(map_type, [])
        paths_not_mapped = to_resource.extra_data[f"{map_type}_not_mapped"] = []
        for item in process_paths_in_binary(
            to_resource=to_resource,
            from_resources=from_resources,
            from_resources_index=from_resources_index,
            map_type=map_type,
            paths_in_binary=paths_in_binary,
        ):
            if isinstance(item, str):
                paths_not_mapped.append(item)
            else:
                rel_key, relation = item
                if rel_key not in relations_to_create:
                    relations_to_create[rel_key] = relation
        if paths_not_mapped:
            to_resource.status = flag.REQUIRES_REVIEW
            logger(
                f"WARNING: #{len(paths_not_mapped)} {map_type} paths NOT mapped for: "
                f"{to_resource.path!r}"
            )
        to_resource.save()

    if relations_to_create:
        rels = CodebaseRelation.objects.bulk_create(relations_to_create.values())
        logger(
            f"Created {len(rels)} mappings using "
            f"{', '.join(map_types)} for: {to_resource.path!r}"
        )
    else:
        logger(f"No mappings using {', '.join(map_types)} for: {to_resource.path!r}")


def process_paths_in_binary(
    to_resource,
    from_resources,
    from_resources_index,
    map_type,
    paths_in_binary,
):
    """
    Process list of paths in binary and Yield either:
    - a tuple of (unique key for a relationship, ``CodebaseRelation`` object)
    - Or a path if it was not mapped
    """
    for path in paths_in_binary:
        match = pathmap.find_paths(path, from_resources_index)
        if not match:
            yield path
            continue

        matched_path_length = match.matched_path_length
        if is_invalid_match(match, matched_path_length):
            yield path
            continue

        matched_from_resources = [
            from_resources.get(id=rid) for rid in match.resource_ids
        ]
        matched_from_resources = sort_matched_from_resources(matched_from_resources)
        winning_from_resource = matched_from_resources[0]

        path_length = count_path_segments(path) - 1
        extra_data = {
            "path_score": f"{matched_path_length}/{path_length}",
            map_type: path,
        }

        rel_key = (winning_from_resource.path, to_resource.path, map_type)
        relation = CodebaseRelation(
            project=winning_from_resource.project,
            from_resource=winning_from_resource,
            to_resource=to_resource,
            map_type=map_type,
            extra_data=extra_data,
        )
        yield rel_key, relation


def count_path_segments(path):
    """Return the number of path segments in POSIX ``path`` string"""
    return len(path.strip("/").split("/"))


def sort_matched_from_resources(matched_from_resources):
    """
    Return the sorted list of ``matched_from_resources``
    based on path length and path.
    """

    def sorter(res):
        return count_path_segments(res.path), res.path

    return sorted(matched_from_resources, key=sorter)


def is_invalid_match(match, matched_path_length):
    """
    Check if the match is invalid based on the ``matched_path_length`` and the number
    of resource IDs.
    """
    return matched_path_length == 1 and len(match.resource_ids) != 1


def is_generated_code(class_bytes):
    """
    Return a reason indicating why the file was identified as generated.
    None otherwise.
    """
    generated_code_markers = {
        #  @Generated annotations
        # https://docs.oracle.com/javase/8/docs/api/javax/annotation/Generated.html
        # https://docs.oracle.com/en/java/javase/11/docs/api/java.compiler/javax/annotation/processing/Generated.html
        # https://jakarta.ee/specifications/annotations/2.1/apidocs/jakarta.annotation/jakarta/annotation/generated
        b"Ljavax/annotation/Generated;": "@Generated annotation detected",
        b"Ljavax/annotation/processing/Generated;": "@Generated annotation detected",
        b"Ljakarta/annotation/Generated;": "@Generated annotation detected",
        b"Ljakarta/annotation/processing/Generated;": "@Generated annotation detected",
        # Protobuf
        # https://protobuf.dev/reference/java/api-docs/com/google/protobuf/GeneratedMessage.html
        b"Lcom/google/protobuf/GeneratedMessageV3;": "Google Protocol Buffers",
        b"Lcom/google/protobuf/GeneratedMessage;": "Google Protocol Buffers",
        # Apache Thrift
        # https://javadoc.io/doc/org.apache.thrift/libthrift/latest/org/apache/thrift/TBase.html
        b"Lorg/apache/thrift/TBase;": "Apache Thrift IDL compiler",
        # Apache Avro
        # https://avro.apache.org/docs/current/api/java/org/apache/avro/specific/SpecificRecord.html
        # https://avro.apache.org/docs/current/api/java/org/apache/avro/specific/SpecificRecordBase.html
        b"Lorg/apache/avro/specific/SpecificRecordBase;": "Apache Avro schema compiler",
        # JAXB (ObjectFactory)
        # https://docs.oracle.com/javase/8/docs/api/javax/xml/bind/annotation/XmlRegistry.html
        b"Ljavax/xml/bind/annotation/XmlRegistry;": "JAXB XmlRegistry",
        b"Ljakarta/xml/bind/annotation/XmlRegistry;": "JAXB XmlRegistry",
        # JAX-WS Stubs
        # https://docs.oracle.com/javase/8/docs/api/javax/xml/ws/WebServiceClient.html
        b"Ljavax/xml/ws/WebServiceClient;": "JAX-WS client stub",
        b"Ljakarta/xml/ws/WebServiceClient;": "JAX-WS client stub",
        # gRPC Stubs
        # https://grpc.github.io/grpc-java/javadoc/io/grpc/stub/annotations/GrpcGenerated.html
        b"Lio/grpc/stub/annotations/GrpcGenerated;": "gRPC compiler stub",
        # Others
        # Immutables - https://github.com/immutables/immutables/issues/756
        b"Lorg/immutables/value/Generated;": "Immutables Generated",
    }

    for marker, reason in generated_code_markers.items():
        if marker in class_bytes:
            return reason

    # The JAXB compiler (xjc) mechanically applies both @XmlType and
    # @XmlAccessorType together on every generated class
    javax_jaxb_cluster = [
        b"Ljavax/xml/bind/annotation/XmlAccessorType;",
        b"Ljavax/xml/bind/annotation/XmlType;",
    ]
    jakarta_jaxb_cluster = [
        b"Ljakarta/xml/bind/annotation/XmlAccessorType;",
        b"Ljakarta/xml/bind/annotation/XmlType;",
    ]

    if all(marker in class_bytes for marker in javax_jaxb_cluster):
        return "JAXB schema compiler cluster (@XmlAccessorType + @XmlType)"

    if all(marker in class_bytes for marker in jakarta_jaxb_cluster):
        return "Jakarta JAXB schema compiler cluster (@XmlAccessorType + @XmlType)"

    return None


def map_elfs_with_dwarf_paths(project, logger=None):
    """Map ELF binaries to their sources in ``project``."""
    from_resources = project.codebaseresources.files().from_codebase()
    to_resources = (
        project.codebaseresources.files().to_codebase().has_no_relation().elfs()
    )
    for resource in to_resources:
        try:
            paths = get_elf_file_dwarf_paths(resource.location_path)
            resource.update_extra_data(paths)
        except Exception as exception:
            project.add_warning(
                exception=exception,
                object_instance=resource,
                description=f"Cannot parse binary at {resource.path}",
                model="map_elfs",
                details={"path": resource.path},
            )

    if logger:
        logger(
            f"Mapping {to_resources.count():,d} to/ resources using paths "
            f"with {from_resources.count():,d} from/ resources."
        )

    from_resources_index = pathmap.build_index(
        from_resources.values_list("id", "path"), with_subpaths=True
    )

    if logger:
        logger("Done building from/ resources index.")

    resource_iterator = to_resources.iterator(chunk_size=2000)
    progress = LoopProgress(to_resources.count(), logger)
    for to_resource in progress.iter(resource_iterator):
        map_paths_resource(
            to_resource,
            from_resources,
            from_resources_index,
            map_types=["dwarf_compiled_paths", "dwarf_included_paths"],
            logger=logger,
        )


def get_elf_file_dwarf_paths(location):
    """Retrieve dwarf paths for ELF files."""
    paths = get_dwarf_paths(location)
    compiled_paths = paths.get("compiled_paths") or []
    included_paths = paths.get("included_paths") or []
    dwarf_paths = {}
    if compiled_paths:
        dwarf_paths["dwarf_compiled_paths"] = compiled_paths
    if included_paths:
        dwarf_paths["dwarf_included_paths"] = included_paths
    return dwarf_paths


def get_go_file_paths(location):
    """Retrieve Go file paths."""
    go_symbols = (
        collect_and_parse_symbols(location, check_type=False).get("go_symbols") or {}
    )
    file_paths = {}
    go_file_paths = go_symbols.get("file_paths") or []
    if go_file_paths:
        file_paths["go_file_paths"] = go_file_paths
    return file_paths


def map_go_paths(project, logger=None):
    """Map Go binaries to their source in ``project``."""
    from_resources = project.codebaseresources.files().from_codebase()
    to_resources = (
        project.codebaseresources.files()
        .to_codebase()
        .has_no_relation()
        .executable_binaries()
    )
    for resource in to_resources:
        try:
            paths = get_go_file_paths(resource.location_path)
            resource.update_extra_data(paths)
        except Exception as exception:
            project.add_warning(
                exception=exception,
                object_instance=resource,
                description=f"Cannot parse binary at {resource.path}",
                model="map_go_paths",
                details={"path": resource.path},
            )

    if logger:
        logger(
            f"Mapping {to_resources.count():,d} to/ resources using paths "
            f"with {from_resources.count():,d} from/ resources."
        )

    from_resources_index = pathmap.build_index(
        from_resources.values_list("id", "path"), with_subpaths=True
    )

    if logger:
        logger("Done building from/ resources index.")

    resource_iterator = to_resources.iterator(chunk_size=2000)
    progress = LoopProgress(to_resources.count(), logger)
    for to_resource in progress.iter(resource_iterator):
        map_paths_resource(
            to_resource,
            from_resources,
            from_resources_index,
            map_types=["go_file_paths"],
            logger=logger,
        )


RUST_BINARY_OPTIONS = ["Rust"]
ELF_BINARY_OPTIONS = ["Python", "Go", "Elf"]
MACHO_BINARY_OPTIONS = ["Rust", "Go", "MacOS"]
WINPE_BINARY_OPTIONS = ["Windows"]


def extract_binary_symbols(project, options, logger=None):
    """
    Extract binary symbols for all Elf, Mach0 and Winpe binaries
    found in the ``project`` resources, based on selected
    ecosystem ``options`` so that these symbols can be mapped to
    extracted source symbols.
    """
    to_resources = project.codebaseresources.files().to_codebase().has_no_relation()
    if any([option in ELF_BINARY_OPTIONS for option in options]):
        to_binaries = to_resources.elfs()
        extract_binary_symbols_from_resources(
            resources=to_binaries,
            binary_symbols_func=collect_and_parse_elf_symbols,
            logger=logger,
        )

    if any([option in RUST_BINARY_OPTIONS for option in options]):
        to_binaries = to_resources.executable_binaries()
        extract_binary_symbols_from_resources(
            resources=to_binaries,
            binary_symbols_func=collect_and_parse_rust_symbols,
            logger=logger,
        )

    if any([option in MACHO_BINARY_OPTIONS for option in options]):
        to_binaries = to_resources.macho_binaries()
        extract_binary_symbols_from_resources(
            resources=to_binaries,
            binary_symbols_func=collect_and_parse_macho_symbols,
            logger=logger,
        )

    if any([option in WINPE_BINARY_OPTIONS for option in options]):
        to_binaries = to_resources.win_exes()
        extract_binary_symbols_from_resources(
            resources=to_binaries,
            binary_symbols_func=collect_and_parse_winpe_symbols,
            logger=logger,
        )


def map_rust_binaries_with_symbols(project, logger=None):
    """Map Rust binaries to their source using symbols in ``project``."""
    from_resources = project.codebaseresources.files().from_codebase()
    to_binaries = (
        project.codebaseresources.files()
        .to_codebase()
        .has_no_relation()
        .executable_binaries()
    )

    # Collect source symbols from rust source files
    rust_config = d2d_config.get_ecosystem_config(ecosystem="Rust")
    rust_from_resources = from_resources.filter(
        extension__in=rust_config.source_symbol_extensions
    )

    map_binaries_with_symbols(
        project=project,
        from_resources=rust_from_resources,
        to_resources=to_binaries,
        map_types=["rust_symbols", "elf_symbols", "macho_symbols"],
        logger=logger,
    )


def map_go_binaries_with_symbols(project, logger=None):
    """Map Go binaries to their source using symbols in ``project``."""
    from_resources = project.codebaseresources.files().from_codebase()
    to_binaries = (
        project.codebaseresources.files()
        .to_codebase()
        .has_no_relation()
        .executable_binaries()
    )

    # Collect source symbols from rust source files
    go_config = d2d_config.get_ecosystem_config(ecosystem="Go")
    go_from_resources = from_resources.filter(
        extension__in=go_config.source_symbol_extensions
    )

    map_binaries_with_symbols(
        project=project,
        from_resources=go_from_resources,
        to_resources=to_binaries,
        map_types=["elf_symbols", "macho_symbols"],
        logger=logger,
    )


def map_elfs_binaries_with_symbols(project, logger=None):
    """Map Elf binaries to their source using symbols in ``project``."""
    from_resources = project.codebaseresources.files().from_codebase()
    elf_binaries = (
        project.codebaseresources.files().to_codebase().has_no_relation().elfs()
    )

    # Collect source symbols from elf related source files
    elf_config = d2d_config.get_ecosystem_config(ecosystem="Elf")
    elf_from_resources = from_resources.filter(
        extension__in=elf_config.source_symbol_extensions
    )

    map_binaries_with_symbols(
        project=project,
        from_resources=elf_from_resources,
        to_resources=elf_binaries,
        map_types=["elf_symbols"],
        logger=logger,
    )


def map_macho_binaries_with_symbols(project, logger=None):
    """Map macho binaries to their source using symbols in ``project``."""
    from_resources = project.codebaseresources.files().from_codebase()
    macho_binaries = (
        project.codebaseresources.files()
        .to_codebase()
        .has_no_relation()
        .macho_binaries()
    )

    # Collect source symbols from macos related source files
    macos_config = d2d_config.get_ecosystem_config(ecosystem="MacOS")
    mac_from_resources = from_resources.filter(
        extension__in=macos_config.source_symbol_extensions,
    )

    map_binaries_with_symbols(
        project=project,
        from_resources=mac_from_resources,
        to_resources=macho_binaries,
        map_types=["macho_symbols"],
        logger=logger,
    )


def map_winpe_binaries_with_symbols(project, logger=None):
    """Map winpe binaries to their source using symbols in ``project``."""
    from_resources = project.codebaseresources.files().from_codebase()
    winexe_binaries = (
        project.codebaseresources.files().to_codebase().has_no_relation().win_exes()
    )

    # Collect source symbols from windows related source files
    windows_config = d2d_config.get_ecosystem_config(ecosystem="Windows")
    windows_from_resources = from_resources.filter(
        extension__in=windows_config.source_symbol_extensions,
    )

    map_binaries_with_symbols(
        project=project,
        from_resources=windows_from_resources,
        to_resources=winexe_binaries,
        map_types=["winpe_symbols"],
        logger=logger,
    )


def get_binary_symbols(resource, map_types):
    """
    Return the map_type and binary symbols from `resource` for different kind of
    binary `map_types`.
    """
    for map_type in map_types:
        symbols = resource.extra_data.get(map_type)
        if symbols:
            return map_type, symbols

    return None, []


def map_binaries_with_symbols(
    project,
    from_resources,
    to_resources,
    map_types,
    logger=None,
):
    """Map Binaries to their source using symbols in ``project``."""
    symbols.collect_and_store_tree_sitter_symbols_and_strings(
        project=project,
        logger=logger,
        project_files=from_resources,
    )

    if logger:
        logger(
            f"Mapping {to_resources.count():,d} to/ resources using symbols "
            f"with {from_resources.count():,d} from/ resources."
        )

    resource_iterator = to_resources.iterator(chunk_size=2000)
    progress = LoopProgress(to_resources.count(), logger)
    for to_resource in progress.iter(resource_iterator):
        map_type, binary_symbols = get_binary_symbols(
            resource=to_resource,
            map_types=map_types,
        )
        if not binary_symbols:
            continue

        if logger:
            logger(f"Mapping source files to binary at {to_resource.path}")

        symbolmap.map_resources_with_symbols(
            project=project,
            to_resource=to_resource,
            from_resources=from_resources,
            binary_symbols=binary_symbols,
            map_type=map_type,
            logger=logger,
        )


def extract_binary_symbols_from_resources(resources, binary_symbols_func, logger):
    """
    Extract binary symbols from ``resources`` using the ecosystem specific
    symbol extractor function ``binary_symbols_func``.
    """
    for resource in resources:
        try:
            binary_symbols = binary_symbols_func(resource.location)
            resource.update_extra_data(binary_symbols)
        except Exception as e:
            logger(f"Error parsing binary symbols at: {resource.location_path!r} {e!r}")


def map_javascript_symbols(project, logger=None):
    """Map deployed JavaScript, TypeScript to its sources using symbols."""
    project_files = project.codebaseresources.files()

    js_config = d2d_config.get_ecosystem_config(ecosystem="JavaScript")
    javascript_to_resources = (
        project_files.to_codebase()
        .has_no_relation()
        .filter(extension__in=js_config.source_symbol_extensions)
    )

    javascript_from_resources = (
        project_files.from_codebase()
        .exclude(path__contains="/test/")
        .filter(extension__in=js_config.source_symbol_extensions)
    )

    if not (javascript_from_resources.exists() and javascript_to_resources.exists()):
        return

    symbols.collect_and_store_tree_sitter_symbols_and_strings(
        project=project,
        logger=logger,
        project_files=javascript_from_resources,
    )

    symbols.collect_and_store_tree_sitter_symbols_and_strings(
        project=project,
        logger=logger,
        project_files=javascript_to_resources,
    )

    javascript_from_resources_withsymbols = javascript_from_resources.exclude(
        extra_data={}
    )
    javascript_to_resources_withsymbols = javascript_to_resources.exclude(extra_data={})

    javascript_from_resources_count = javascript_from_resources_withsymbols.count()
    javascript_to_resources_count = javascript_to_resources_withsymbols.count()
    if logger:
        logger(
            f"Mapping {javascript_to_resources_count:,d} JavaScript resources using"
            f" symbols against {javascript_from_resources_count:,d} from/ codebase."
        )

    resource_iterator = javascript_to_resources_withsymbols.iterator(chunk_size=2000)
    progress = LoopProgress(javascript_to_resources_count, logger)

    resource_mapped = 0
    for to_resource in progress.iter(resource_iterator):
        resource_mapped += _map_javascript_symbols(
            to_resource, javascript_from_resources_withsymbols, logger
        )

    if logger:
        logger(f"{resource_mapped:,d} resource mapped using symbols")


def _map_javascript_symbols(to_resource, javascript_from_resources, logger):
    """
    Map a deployed JavaScript resource to its source using symbols and
    return 1 if match is found otherwise return 0.
    """
    to_symbols = to_resource.extra_data.get("source_symbols")

    if not to_symbols or symbolmap.is_decomposed_javascript(to_symbols):
        return 0

    best_matching_score = 0
    best_match = None
    for source_js in javascript_from_resources:
        from_symbols = source_js.extra_data.get("source_symbols")
        if not from_symbols:
            continue

        is_match, similarity = symbolmap.match_javascript_source_symbols_to_deployed(
            source_symbols=from_symbols,
            deployed_symbols=to_symbols,
        )

        if is_match and similarity > best_matching_score:
            best_matching_score = similarity
            best_match = source_js

    if best_match:
        pipes.make_relation(
            from_resource=best_match,
            to_resource=to_resource,
            map_type="javascript_symbols",
            extra_data={"jsd_similarity_score": similarity},
        )
        to_resource.update(status=flag.MAPPED)
        return 1
    return 0


def map_javascript_strings(project, logger=None):
    """Map deployed JavaScript, TypeScript to its sources using string literals."""
    project_files = project.codebaseresources.files()

    javascript_to_resources = (
        project_files.to_codebase()
        .has_no_relation()
        .filter(extension__in=[".ts", ".js"])
        .exclude(extra_data={})
    )

    javascript_from_resources = (
        project_files.from_codebase()
        .exclude(path__contains="/test/")
        .filter(extension__in=[".ts", ".js"])
        .exclude(extra_data={})
    )

    if not (javascript_from_resources.exists() and javascript_to_resources.exists()):
        return

    javascript_from_resources_count = javascript_from_resources.count()
    javascript_to_resources_count = javascript_to_resources.count()
    if logger:
        logger(
            f"Mapping {javascript_to_resources_count:,d} JavaScript resources"
            f" using string literals against {javascript_from_resources_count:,d}"
            " from/ resources."
        )

    resource_iterator = javascript_to_resources.iterator(chunk_size=2000)
    progress = LoopProgress(javascript_to_resources_count, logger)

    resource_mapped = 0
    for to_resource in progress.iter(resource_iterator):
        resource_mapped += _map_javascript_strings(
            to_resource, javascript_from_resources, logger
        )
    if logger:
        logger(f"{resource_mapped:,d} resource mapped using strings")


def _map_javascript_strings(to_resource, javascript_from_resources, logger):
    """
    Map a deployed JavaScript resource to its source using string literals and
    return 1 if match is found otherwise return 0.
    """
    ignoreable_string_threshold = 5
    to_strings = to_resource.extra_data.get("source_strings")
    to_strings_set = set(to_strings)

    if not to_strings or len(to_strings_set) < ignoreable_string_threshold:
        return 0

    best_matching_score = 0
    best_match = None
    for source_js in javascript_from_resources:
        from_strings = source_js.extra_data.get("source_strings")
        from_strings_set = set(from_strings)
        if not from_strings or len(from_strings_set) < ignoreable_string_threshold:
            continue

        is_match, similarity = stringmap.match_source_strings_to_deployed(
            source_strings=from_strings,
            deployed_strings=to_strings,
        )

        if is_match and similarity > best_matching_score:
            best_matching_score = similarity
            best_match = source_js

    if best_match:
        pipes.make_relation(
            from_resource=best_match,
            to_resource=to_resource,
            map_type="javascript_strings",
            extra_data={"js_string_map_score": similarity},
        )
        to_resource.update(status=flag.MAPPED)
        return 1
    return 0


def map_python_pyx_to_binaries(project, logger=None):
    """Map Cython source to their compiled binaries in ``project``."""
    from source_inspector.symbols_tree_sitter import get_tree_and_language_info

    python_config = d2d_config.get_ecosystem_config(ecosystem="Python")
    from_resources = (
        project.codebaseresources.files()
        .from_codebase()
        .filter(extension__in=python_config.source_symbol_extensions)
    )
    to_resources = (
        project.codebaseresources.files().to_codebase().has_no_relation().elfs()
    )

    for resource in from_resources:
        # Open Cython source file, create AST, parse it for function definitions
        # and save them in a list
        tree, _ = get_tree_and_language_info(resource.location)
        function_definitions = [
            node
            for node in tree.root_node.children
            if node.type == "function_definition"
        ]
        identifiers = []
        for node in function_definitions:
            for child in node.children:
                if child.type == "identifier":
                    identifiers.append(child.text.decode())

        # Find matching to/ resource by checking to see which to/ resource's
        # extra_data field contains function definitions found from Cython
        # source files
        identifiers_qs = Q()
        for identifier in identifiers:
            identifiers_qs |= Q(extra_data__icontains=identifier)
        matching_elfs = to_resources.filter(identifiers_qs)
        for matching_elf in matching_elfs:
            pipes.make_relation(
                from_resource=resource,
                to_resource=matching_elf,
                map_type="python_pyx_match",
            )


def map_python_protobuf_files(project, logger=None):
    """Map protobuf-generated .py/.pyi files to their source .proto files."""
    from_resources = (
        project.codebaseresources.files().from_codebase().filter(extension=".proto")
    )
    to_resources = (
        project.codebaseresources.files()
        .to_codebase()
        .has_no_relation()
        .filter(extension__in=[".py", ".pyi"])
    )
    to_resources_count = to_resources.count()
    from_resources_count = from_resources.count()

    if not from_resources_count or not to_resources_count:
        return

    proto_index = {}
    for proto_resource in from_resources:
        base_name = proto_resource.name.replace(".proto", "")
        proto_index[base_name] = proto_resource

    mapped_count = 0
    for to_resource in to_resources:
        base_name = extract_protobuf_base_name(to_resource.name)
        if base_name and base_name in proto_index:
            from_resource = proto_index[base_name]
            pipes.make_relation(
                from_resource=from_resource,
                to_resource=to_resource,
                map_type="protobuf_mapping",
                extra_data={"protobuf_base_name": base_name},
            )
            mapped_count += 1


def extract_protobuf_base_name(filename):
    """Extract the base name from a protobuf-generated filename."""
    name_without_ext = filename.rsplit(".", 1)[0]
    protobuf_pattern = r"^(.+)_pb[23]$"
    match = re.match(protobuf_pattern, name_without_ext)
    if match:
        return match.group(1)
