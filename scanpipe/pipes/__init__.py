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

import difflib
import logging
import sys
import time
import uuid
from contextlib import suppress
from datetime import datetime
from itertools import islice
from pathlib import Path
from timeit import default_timer as timer

from django.db.models import Count

from scanpipe import humanize_time
from scanpipe.models import AbstractTaskFieldsModel
from scanpipe.models import CodebaseRelation
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredPackage
from scanpipe.pipes import scancode

logger = logging.getLogger("scanpipe.pipes")


def make_codebase_resource(project, location, save=True, **extra_fields):
    """
    Create a CodebaseResource instance in the database for the given ``project``.

    The provided ``location`` is the absolute path of this resource.
    It must be rooted in `project.codebase_path` as only the relative path within the
    project codebase/ directory is stored in the database.

    Extra fields can be provided as keywords arguments to this function call::

        make_codebase_resource(
            project=project,
            location=resource.location,
            rootfs_path=resource.path,
            tag=layer_tag,
        )

    In this example, ``rootfs_path`` is an optional path relative to a rootfs root
    within an Image/VM filesystem context. e.g.: "/var/log/file.log"

    All paths use the POSIX separators.

    If a CodebaseResource already exists in the ``project`` with the same path,
    the error raised on save() is not stored in the database and the creation is
    skipped.
    """
    relative_path = Path(location).relative_to(project.codebase_path)
    resource_data = scancode.get_resource_info(location=str(location))

    if extra_fields:
        resource_data.update(**extra_fields)

    codebase_resource = CodebaseResource(
        project=project,
        path=relative_path,
        **resource_data,
    )

    if save:
        codebase_resource.save(save_error=False)
    return codebase_resource


def get_resource_codebase_root(project, resource_path):
    """Return "to" or "from" depending on the resource location in the codebase."""
    relative_path = Path(resource_path).relative_to(project.codebase_path)
    first_part = relative_path.parts[0]
    if first_part in ["to", "from"]:
        return first_part
    return ""


def yield_resources_from_codebase(project):
    """
    Yield CodebaseResource instances, including their ``info`` data, ready to be
    inserted in the database using ``save()`` or ``bulk_create()``.
    """
    for resource_path in project.walk_codebase_path():
        yield make_codebase_resource(
            project=project,
            location=resource_path,
            save=False,
            tag=get_resource_codebase_root(project, resource_path),
        )


def collect_and_create_codebase_resources(project, batch_size=5000):
    """
    Collect and create codebase resources including the "to/" and "from/" context using
    the resource tag field.

    The default ``batch_size`` can be overriden, although the benefits of a value
    greater than 5000 objects are usually not significant.
    """
    model_class = CodebaseResource
    objs = yield_resources_from_codebase(project)

    while True:
        batch = list(islice(objs, batch_size))
        if not batch:
            break
        model_class.objects.bulk_create(batch, batch_size)


def update_or_create_resource(project, resource_data):
    """Get, update or create a CodebaseResource then return it."""
    for_packages = resource_data.pop("for_packages", None) or []

    resource = CodebaseResource.objects.get_or_none(
        project=project,
        path=resource_data.get("path"),
    )

    if resource:
        resource.update_from_data(resource_data)
    else:
        resource = CodebaseResource.create_from_data(project, resource_data)

    for package_uid in for_packages:
        package = project.discoveredpackages.get(package_uid=package_uid)
        resource.add_package(package)

    return resource


def _clean_package_data(package_data):
    """Clean provided `package_data` to make it compatible with the model."""
    package_data = package_data.copy()
    if release_date := package_data.get("release_date"):
        if type(release_date) is str:
            if release_date.endswith("Z"):
                release_date = release_date[:-1]
            package_data["release_date"] = datetime.fromisoformat(release_date).date()

    # Strip leading "codebase/" to make path compatible with
    # paths stored in resource database
    cleaned_datafile_paths = [
        path.removeprefix("codebase/")
        for path in package_data.get("datafile_paths", [])
    ]
    package_data["datafile_paths"] = cleaned_datafile_paths
    return package_data


def update_or_create_package(
    project,
    package_data,
    codebase_resources=None,
    is_virtual=False,
):
    """
    Get, update or create a DiscoveredPackage then return it.
    Use the `project` and `package_data` mapping to lookup and creates the
    DiscoveredPackage using its Package URL and package_uid as a unique key.
    The package can be associated to `codebase_resources` providing a list or queryset
    of resources.
    """
    purl_data = DiscoveredPackage.extract_purl_data(package_data)
    package_data = _clean_package_data(package_data)
    # No values for package_uid requires to be empty string for proper queryset lookup
    package_uid = package_data.get("package_uid") or ""
    datasource_id = package_data.get("datasource_id") or ""

    package = DiscoveredPackage.objects.get_or_none(
        project=project,
        package_uid=package_uid,
        **purl_data,
    )

    if package:
        package.update_from_data(package_data)
    else:
        package = DiscoveredPackage.create_from_data(project, package_data)

    if package:
        if datasource_id and datasource_id not in package.datasource_ids:
            datasource_ids = package.datasource_ids.copy()
            datasource_ids.append(datasource_id)
            package.update(datasource_ids=datasource_ids)

        if codebase_resources:
            package.add_resources(codebase_resources)

    return package


def create_local_files_package(project, defaults, codebase_resources=None):
    """Create a local-files package using provided ``defaults`` data."""
    package_data = {
        "type": "local-files",
        "namespace": project.slug,
        "name": str(uuid.uuid4()),
    }
    package_data.update(defaults)
    return update_or_create_package(project, package_data, codebase_resources)


def ignore_dependency_scope(project, dependency_data):
    """
    Return True if the dependency should be ignored, i.e.: not created.
    The ignored scopes are defined on the project ``ignored_dependency_scopes`` setting
    field.
    """
    ignored_scope_index = project.ignored_dependency_scopes_index
    if not ignored_scope_index:
        return False

    dependency_package_type = dependency_data.get("package_type")
    dependency_scope = dependency_data.get("scope")
    if dependency_package_type and dependency_scope:
        if dependency_scope in ignored_scope_index.get(dependency_package_type, []):
            return True  # Ignore this dependency entry.

    return False


def update_or_create_dependency(
    project,
    dependency_data,
    for_package=None,
    resolved_to_package=None,
    datafile_resource=None,
    datasource_id=None,
    strip_datafile_path_root=False,
):
    """
    Get, update or create a DiscoveredDependency then returns it.
    Use the `project` and `dependency_data` mapping to lookup and creates the
    DiscoveredDependency using its dependency_uid and for_package_uid as a unique key.

    If `strip_datafile_path_root` is True, then
    `DiscoveredDependency.create_from_data()` will strip the root path segment
    from the `datafile_path` of `dependency_data` before looking up the
    corresponding CodebaseResource for `datafile_path`. This is used in the case
    where Dependency data is imported from a scancode-toolkit scan, where the
    root path segments are not stripped for `datafile_path`.
    If the dependency is resolved and a resolved package is created, we have the
    corresponding package_uid at `resolved_to`.
    """
    if ignore_dependency_scope(project, dependency_data):
        return  # Do not create the DiscoveredDependency record.

    dependencies = get_dependencies(project, dependency_data)

    for dependency in dependencies:
        is_for_new_package = (
            for_package
            and dependency.for_package
            and dependency.for_package != for_package
        )
        if is_for_new_package:
            DiscoveredDependency.populate_dependency_uuid(dependency_data)
            dependency = DiscoveredDependency.create_from_data(
                project,
                dependency_data,
                for_package=for_package,
                resolved_to_package=resolved_to_package,
                datafile_resource=datafile_resource,
                datasource_id=datasource_id,
                strip_datafile_path_root=strip_datafile_path_root,
            )
            break

        elif dependency:
            dependency.update_from_data(dependency_data)
            if resolved_to_package and not dependency.resolved_to_package:
                dependency.update(resolved_to_package=resolved_to_package)
            if for_package and not dependency.for_package:
                dependency.update(for_package=for_package)

    if not dependencies:
        DiscoveredDependency.populate_dependency_uuid(dependency_data)
        dependency = DiscoveredDependency.create_from_data(
            project,
            dependency_data,
            for_package=for_package,
            resolved_to_package=resolved_to_package,
            datafile_resource=datafile_resource,
            datasource_id=datasource_id,
            strip_datafile_path_root=strip_datafile_path_root,
        )

    return dependency


def get_dependencies(project, dependency_data):
    """
    Given a `dependency_data` mapping, get a list of DiscoveredDependency objects
    for that `project` with similar dependency data.
    """
    dependency_uid = dependency_data.get("dependency_uid")
    extracted_requirement = dependency_data.get("extracted_requirement") or ""

    dependencies = []
    if not dependency_uid:
        purl_data = DiscoveredDependency.extract_purl_data(dependency_data)
        dependencies = DiscoveredDependency.objects.filter(
            project=project,
            extracted_requirement=extracted_requirement,
            **purl_data,
        )
    else:
        dependency = DiscoveredDependency.objects.get_or_none(
            project=project,
            dependency_uid=dependency_uid,
        )
        if dependency:
            dependencies.append(dependency)

    return dependencies


def get_or_create_relation(project, relation_data):
    """
    Get  or create a CodebaseRelation then return it.
    The support for update is not useful as there is no fields on the model that
    could be updated.
    """
    from_resource_path = relation_data.get("from_resource")
    to_resource_path = relation_data.get("to_resource")
    resource_qs = project.codebaseresources

    codebase_relation, _ = CodebaseRelation.objects.get_or_create(
        project=project,
        from_resource=resource_qs.get(path=from_resource_path),
        to_resource=resource_qs.get(path=to_resource_path),
        map_type=relation_data.get("map_type"),
    )

    return codebase_relation


def make_relation(from_resource, to_resource, map_type, **extra_fields):
    return CodebaseRelation.objects.create(
        project=from_resource.project,
        from_resource=from_resource,
        to_resource=to_resource,
        map_type=map_type,
        **extra_fields,
    )


def normalize_path(path):
    """Return a normalized path from a `path` string."""
    return "/" + path.strip("/")


def strip_root(location):
    """Return the provided `location` without the root directory."""
    return "/".join(str(location).strip("/").split("/")[1:])


def filename_now(sep="-"):
    """Return the current date and time in iso format suitable for filename."""
    now = datetime.now().isoformat(sep=sep, timespec="seconds")
    return now.replace(":", sep)


def count_group_by(queryset, field_name):
    """
    Return a summary of all existing values for the provided `field_name` on the
    `queryset`, including the count of each entry, as a dictionary.
    """
    counts = (
        queryset.values(field_name)
        .annotate(count=Count(field_name))
        .order_by(field_name)
    )

    return {entry.get(field_name): entry.get("count") for entry in counts}


def get_bin_executable(filename):
    """Return the location of the `filename` executable binary."""
    return str(Path(sys.executable).parent / filename)


class LoopProgress:
    """
    A context manager for logging progress in loops.

    Usage::

        total_iterations = 100
        logger = print  # Replace with your actual logger function

        progress = LoopProgress(total_iterations, logger, progress_step=10)
        for item in progress.iter(iterator):
            "Your processing logic here"

        with LoopProgress(total_iterations, logger, progress_step=10) as progress:
            for item in progress.iter(iterator):
                "Your processing logic here"
    """

    def __init__(self, total_iterations, logger, progress_step=10):
        self.total_iterations = total_iterations
        self.logger = logger
        self.progress_step = progress_step
        self.start_time = timer()
        self.last_logged_progress = 0
        self.current_iteration = 0

    def get_eta(self, current_progress):
        run_time = timer() - self.start_time
        return round(run_time / current_progress * (100 - current_progress))

    @property
    def current_progress(self):
        return int((self.current_iteration / self.total_iterations) * 100)

    @property
    def eta(self):
        run_time = timer() - self.start_time
        return round(run_time / self.current_progress * (100 - self.current_progress))

    def log_progress(self):
        reasons_to_skip = [
            not self.logger,
            not self.current_iteration > 0,
            self.total_iterations <= self.progress_step,
        ]
        if any(reasons_to_skip):
            return

        if self.current_progress >= self.last_logged_progress + self.progress_step:
            msg = (
                f"Progress: {self.current_progress}% "
                f"({self.current_iteration}/{self.total_iterations})"
            )
            if eta := self.eta:
                msg += f" ETA: {humanize_time(eta)}"

            self.logger(msg)
            self.last_logged_progress = self.current_progress

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def iter(self, iterator):
        for item in iterator:
            self.current_iteration += 1
            self.log_progress()
            yield item


def get_text_str_diff_ratio(str_a, str_b):
    """
    Return a similarity ratio as a float between 0 and 1 by comparing the
    text content of the ``str_a`` and ``str_b``.

    Return None if any of the two resources str is empty.
    """
    if not (str_a and str_b):
        return

    if not isinstance(str_a, str) or not isinstance(str_b, str):
        raise ValueError("Values must be str")

    matcher = difflib.SequenceMatcher(a=str_a.splitlines(), b=str_b.splitlines())
    return matcher.quick_ratio()


def get_resource_diff_ratio(resource_a, resource_b):
    """
    Return a similarity ratio as a float between 0 and 1 by comparing the
    text content of the CodebaseResource ``resource_a`` and ``resource_b``.

    Return None if any of the two resources are not readable as text.
    """
    with suppress(IOError):
        return get_text_str_diff_ratio(
            str_a=resource_a.file_content,
            str_b=resource_b.file_content,
        )


def poll_until_success(check, sleep=10, **kwargs):
    """
    Given a function `check`, which returns the status of a run, return True
    when the run instance has completed successfully.

    Return False when the run instance has failed, stopped, or gone stale.

    The arguments for `check` need to be provided as keyword argument into this
    function.
    """
    run_status = AbstractTaskFieldsModel.Status
    # Continue looping if the run instance has the following statuses
    CONTINUE_STATUSES = [
        run_status.NOT_STARTED,
        run_status.QUEUED,
        run_status.RUNNING,
    ]
    # Return False if the run instance has the following statuses
    FAIL_STATUSES = [
        run_status.FAILURE,
        run_status.STOPPED,
        run_status.STALE,
    ]

    while True:
        status = check(**kwargs)
        if status == run_status.SUCCESS:
            return True

        if status in CONTINUE_STATUSES:
            continue

        if status in FAIL_STATUSES:
            return False

        time.sleep(sleep)
