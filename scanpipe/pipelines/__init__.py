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

import inspect
import logging
import traceback
from contextlib import contextmanager
from functools import wraps
from pathlib import Path

from pyinstrument import Profiler

from pipeline import BasePipeline
from pipeline import BasePipelineRun

logger = logging.getLogger(__name__)


class InputFilesError(Exception):
    """InputFile is missing or cannot be downloaded."""

    def __init__(self, error_tracebacks):
        self.error_tracebacks = error_tracebacks
        super().__init__(self._generate_message())

    def _generate_message(self):
        message = "InputFilesError encountered with the following issues:\n"
        for index, (error, tb) in enumerate(self.error_tracebacks, start=1):
            message += f"\nError {index}: {str(error)}\n\n{tb}"
        return message


class CommonStepsMixin:
    """Common steps available on all project pipelines."""

    def flag_empty_files(self):
        """Flag empty files."""
        from scanpipe.pipes import flag

        flag.flag_empty_files(self.project)

    def flag_ignored_resources(self):
        """Flag ignored resources based on Project ``ignored_patterns`` setting."""
        from scanpipe.pipes import flag

        if ignored_patterns := self.env.get("ignored_patterns"):
            flag.flag_ignored_patterns(self.project, patterns=ignored_patterns)

    def extract_archive(self, location, target):
        """Extract archive at `location` to `target`. Save errors as messages."""
        from scanpipe.pipes import scancode

        extract_errors = scancode.extract_archive(location, target)

        for resource_location, errors in extract_errors.items():
            resource_path = Path(resource_location)

            if resource_path.is_relative_to(self.project.codebase_path):
                resource_path = resource_path.relative_to(self.project.codebase_path)
                details = {"resource_path": str(resource_path)}
            elif resource_path.is_relative_to(self.project.input_path):
                resource_path = resource_path.relative_to(self.project.input_path)
                details = {"path": f"input/{str(resource_path)}"}
            else:
                details = {"filename": str(resource_path.name)}

            self.project.add_error(
                description="\n".join(errors),
                model="extract_archive",
                details=details,
            )

    def extract_archives(self, location=None):
        """Extract archives located in the codebase/ directory with extractcode."""
        from scanpipe.pipes import scancode

        if not location:
            location = self.project.codebase_path

        extract_errors = scancode.extract_archives(location=location, recurse=True)

        for resource_path, errors in extract_errors.items():
            self.project.add_error(
                description="\n".join(errors),
                model="extract_archives",
                details={"resource_path": resource_path},
            )

        # Reload the project env post-extraction as the scancode-config.yml file
        # may be located in one of the extracted archives.
        self.env = self.project.get_env()


class ProjectPipelineRun(BasePipelineRun):
    def __init__(self, run_instance):
        """Load the Pipeline execution context from a Run database object."""
        self.run = run_instance
        self.project = run_instance.project
        self.env = self.project.get_env()

        self.pipeline_class = run_instance.pipeline_class
        self.pipeline_name = run_instance.pipeline_name

        self.selected_groups = run_instance.selected_groups
        self.selected_steps = run_instance.selected_steps

    def append_to_log(self, message):
        self.run.append_to_log(message)

    def set_current_step(self, message):
        self.run.set_current_step(message)


class Pipeline(CommonStepsMixin, BasePipeline, ProjectPipelineRun):
    """Main class for all project related pipelines including common steps methods."""

    # Project wrapper ProjectPipelineRun class
    # run_class = ProjectPipelineRun

    # Flag specifying whether to download missing inputs as an initial step.
    download_inputs = True

    # Optional URL that targets a view of the results relative to this Pipeline.
    # This URL may contain dictionary-style string formatting, which will be
    # interpolated against the project's field attributes.
    # For example, you could use results_url="/project/{slug}/packages/?filter=value"
    # to target the Package list view with an active filtering.
    results_url = ""

    @classmethod
    def get_steps(cls, groups=None):
        """Inject the ``download_inputs`` step if enabled."""
        steps = super().get_steps(groups)

        if cls.download_inputs:
            steps = (cls.download_missing_inputs,) + steps

        return steps

    def download_missing_inputs(self):
        """
        Download any InputSource missing on disk.
        Raise an error if any of the uploaded files is not available or not reachable.
        """
        error_tracebacks = []

        for input_source in self.project.inputsources.all():
            if input_source.exists():
                continue

            if input_source.is_uploaded:
                msg = f"Uploaded file {input_source} not available."
                self.log(msg)
                error_tracebacks.append((msg, "No traceback available."))
                continue

            self.log(f"Fetching input from {input_source.download_url}")
            try:
                input_source.fetch()
            except Exception as error:
                traceback_str = traceback.format_exc()
                logger.error(traceback_str)
                self.log(f"{input_source.download_url} could not be fetched.")
                error_tracebacks.append((str(error), traceback_str))

        if error_tracebacks:
            raise InputFilesError(error_tracebacks)

    def add_error(self, exception, resource=None):
        """Create a ``ProjectMessage`` ERROR record on the current `project`."""
        self.project.add_error(
            model=self.pipeline_name,
            exception=exception,
            resource=resource,
        )

    @contextmanager
    def save_errors(self, *exceptions, **kwargs):
        """
        Context manager to save specified exceptions as ``ProjectMessage`` in the
        database.

        - Example in a Pipeline step::

        with self.save_errors(rootfs.DistroNotFound):
            rootfs.scan_rootfs_for_system_packages(self.project, rfs)

        - Example when iterating over resources::

        for resource in self.project.codebaseresources.all():
            with self.save_errors(Exception, resource=resource):
                analyse(resource)
        """
        try:
            yield
        except exceptions as error:
            self.add_error(exception=error, **kwargs)


def is_pipeline(obj):
    """
    Return True if the `obj` is a subclass of `Pipeline` except for the
    `Pipeline` class itself.
    """
    return inspect.isclass(obj) and issubclass(obj, Pipeline) and obj is not Pipeline


def profile(step):
    """
    Profile a Pipeline step and save the results as HTML file in the project output
    directory.

    Usage:
        @profile
        def step(self):
            pass
    """

    @wraps(step)
    def wrapper(*arg, **kwargs):
        pipeline_instance = arg[0]
        project = pipeline_instance.project

        with Profiler() as profiler:
            result = step(*arg, **kwargs)

        output_file = project.get_output_file_path("profile", "html")
        output_file.write_text(profiler.output_html())

        pipeline_instance.log(f"Profiling results at {output_file.resolve()}")

        return result

    return wrapper
