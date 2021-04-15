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

import re
import shutil
import uuid
from contextlib import suppress
from pathlib import Path
from traceback import format_tb

from django.apps import apps
from django.core import checks
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.db import transaction
from django.db.models import Q
from django.db.models.functions import Lower
from django.forms import model_to_dict
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

from celery.result import AsyncResult
from packageurl import normalize_qualifiers

from scancodeio import WORKSPACE_LOCATION
from scanpipe import tasks
from scanpipe.packagedb_models import AbstractPackage
from scanpipe.packagedb_models import AbstractResource

scanpipe_app = apps.get_app_config("scanpipe")


class UUIDPKModel(models.Model):
    uuid = models.UUIDField(
        verbose_name=_("UUID"),
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        db_index=True,
    )

    class Meta:
        abstract = True

    def __str__(self):
        return str(self.uuid)

    @property
    def short_uuid(self):
        return str(self.uuid)[0:8]


class AbstractTaskFieldsModel(models.Model):
    task_id = models.UUIDField(
        blank=True,
        null=True,
        editable=False,
    )
    task_start_date = models.DateTimeField(
        blank=True,
        null=True,
        editable=False,
    )
    task_end_date = models.DateTimeField(
        blank=True,
        null=True,
        editable=False,
    )
    task_exitcode = models.IntegerField(
        null=True,
        blank=True,
        editable=False,
    )
    task_output = models.TextField(
        blank=True,
        editable=False,
    )

    class Meta:
        abstract = True

    def task_state(self):
        """
        Possible values includes:
        - PENDING
            The task is waiting for execution.
        - STARTED
            The task has been started.
        - RETRY
            The task is to be retried, possibly because of failure.
        - FAILURE
            The task raised an exception, or has exceeded the retry limit.
            The result attribute then contains the exception raised by the task.
        - SUCCESS
            The task executed successfully. The result attribute then contains
            the tasks return value.
        """
        return AsyncResult(str(self.task_id)).state

    @property
    def execution_time(self):
        if self.task_end_date and self.task_start_date:
            total_seconds = (self.task_end_date - self.task_start_date).total_seconds()
            return int(total_seconds)

    @property
    def execution_time_for_display(self):
        execution_time = self.execution_time
        if execution_time:
            message = f"{execution_time} seconds"
            if execution_time > 3600:
                message += f" ({execution_time / 3600:.1f} hours)"
            elif execution_time > 60:
                message += f" ({execution_time / 60:.1f} minutes)"
            return message

    def reset_task_values(self):
        """
        Reset all task related fields to their initial null value.
        """
        self.task_id = None
        self.task_start_date = None
        self.task_end_date = None
        self.task_exitcode = None
        self.task_output = ""

    def set_task_started(self, task_id):
        """
        Set the `task_id` and `task_start_date` before the task execution.
        """
        self.task_id = task_id
        self.task_start_date = timezone.now()
        self.save()

    def set_task_ended(self, exitcode, output, refresh_first=True):
        """
        Set the task related fields after the task execution.

        An optional `refresh_first`, enabled by default, force the refresh of
        the instance with the latest data from the database before saving.
        This prevent loosing values saved on the instance during the task
        execution.
        """
        if refresh_first:
            self.refresh_from_db()

        self.task_exitcode = exitcode
        self.task_output = output
        self.task_end_date = timezone.now()
        self.save()


def get_project_work_directory(project):
    """
    Return the work directory location for the provided `project`.
    The `project` name is "slugified" to generate a nicer directory path, without any
    whitespace or special characters.
    A short version of the `project` uuid is added as suffix to ensure uniqueness of
    the work directory location.
    """
    return f"{WORKSPACE_LOCATION}/projects/{slugify(project.name)}-{project.short_uuid}"


class Project(UUIDPKModel, models.Model):
    """
    The Project encapsulate all analysis processing.
    Multiple analysis pipelines can be run on the project.
    """

    created_date = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text=_("Creation date for this project."),
    )
    name = models.CharField(
        unique=True,
        db_index=True,
        max_length=100,
        help_text=_("Name for this project."),
    )
    WORK_DIRECTORIES = ["input", "output", "codebase", "tmp"]
    work_directory = models.CharField(
        max_length=2048,
        editable=False,
        help_text=_("Project work directory location."),
    )
    input_sources = models.JSONField(default=dict, blank=True, editable=False)
    extra_data = models.JSONField(default=dict, editable=False)

    class Meta:
        ordering = ["-created_date"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        """
        Setup the workspace directories on project creation.
        """
        if not self.work_directory:
            self.work_directory = get_project_work_directory(self)
            self.setup_work_directory()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """
        Delete the `work_directory` along all the project related data in the database.
        """
        shutil.rmtree(self.work_directory, ignore_errors=True)
        return super().delete(*args, **kwargs)

    def setup_work_directory(self):
        """
        Create all the work_directory structure, skip existing.
        """
        for subdirectory in self.WORK_DIRECTORIES:
            Path(self.work_directory, subdirectory).mkdir(parents=True, exist_ok=True)

    @property
    def work_path(self):
        return Path(self.work_directory)

    @property
    def input_path(self):
        return Path(self.work_path / "input")

    @property
    def output_path(self):
        return Path(self.work_path / "output")

    @property
    def codebase_path(self):
        return Path(self.work_path / "codebase")

    @property
    def tmp_path(self):
        return Path(self.work_path / "tmp")

    def clear_tmp_directory(self):
        """
        Delete the whole tmp/ directory content.
        This is call at the end of each Pipelines Run, do not store content
        that is needed for further processing in following Pipelines.
        """
        shutil.rmtree(self.tmp_path, ignore_errors=True)
        self.tmp_path.mkdir(exist_ok=True)

    def inputs(self, pattern="**/*"):
        """
        Yield all the files and directories path of the input/ directory matching the
        provided `pattern`.
        The default "**/*" pattern means: "this directory and all subdirectories,
        recursively".
        Use the "*" pattern to list the root content only.
        """
        return self.input_path.glob(pattern)

    @property
    def input_files(self):
        """
        Return the list of all files relative path in the input/ directory,
        recursively.
        """
        return [
            str(path.relative_to(self.input_path))
            for path in self.inputs()
            if path.is_file()
        ]

    @staticmethod
    def get_root_content(directory):
        """
        Return the list of all files and directories of the `directory`.
        Only the first level children are listed.
        """
        return [str(path.relative_to(directory)) for path in directory.glob("*")]

    @property
    def input_root(self):
        """
        Return the list of all files and directories of the input/ directory.
        Only the first level children are listed.
        """
        return self.get_root_content(self.input_path)

    @property
    def inputs_with_source(self):
        """
        Return the list of inputs including the source, type, and size data.
        Return the `missing_inputs` defined in the `input_sources` field but not
        available in the input/ directory.
        Only the first level children are listed.
        """
        input_path = self.input_path
        input_sources = dict(self.input_sources)

        inputs = []
        for path in input_path.glob("*"):
            inputs.append(
                {
                    "name": path.name,
                    "is_file": path.is_file(),
                    "size": path.stat().st_size,
                    "source": input_sources.pop(path.name, "not_found"),
                }
            )

        missing_inputs = input_sources
        return inputs, missing_inputs

    @property
    def output_root(self):
        """
        Return the list of all files and directories of the output/ directory.
        Only the first level children are listed.
        """
        return self.get_root_content(self.output_path)

    def get_output_file_path(self, name, extension):
        """
        Return a crafted file path in the project output/ directory using
        the provided `name` and `extension`.
        The current date and time string is added to the filename.
        """
        from scanpipe.pipes import filename_now

        filename = f"{name}-{filename_now()}.{extension}"
        return self.output_path / filename

    @cached_property
    def can_add_input(self):
        """
        Return True until one pipeline has started to execute on this project.
        """
        return not self.runs.started().exists()

    def add_input_source(self, filename, source, save=False):
        """
        Add the provided `filename` and `source` on this project `input_sources` field.
        """
        self.input_sources[filename] = source
        if save:
            self.save()

    def write_input_file(self, file_object):
        """
        Write the provided `file_object` to this project input/ directory.
        """
        filename = file_object.name
        file_path = Path(self.input_path / filename)

        with open(file_path, "wb+") as f:
            for chunk in file_object.chunks():
                f.write(chunk)

    def copy_input_from(self, input_location):
        """
        Copy the file at `input_location` to this project input/ directory.
        """
        from scanpipe.pipes.input import copy_inputs

        copy_inputs([input_location], self.input_path)

    def move_input_from(self, input_location):
        """
        Move the file at `input_location` to this project input/ directory.
        """
        from scanpipe.pipes.input import move_inputs

        move_inputs([input_location], self.input_path)

    def add_downloads(self, downloads):
        """
        Move the provided `downloads` to this project input/ directory and add the
        `input_source` for each entry.
        """
        for downloaded in downloads:
            self.move_input_from(downloaded.path)
            self.add_input_source(downloaded.filename, downloaded.uri)
        self.save()

    def add_uploads(self, uploads):
        """
        Write the provided `uploads` to this project input/ directory and add the
        `input_source` for each entry.
        """
        for uploaded in uploads:
            self.write_input_file(uploaded)
            self.add_input_source(filename=uploaded.name, source="uploaded")
        self.save()

    def add_pipeline(self, pipeline_name, execute_now=False):
        """
        Create a new Run instance with the provided `pipeline` on this project.

        If `execute_now` is True, the pipeline task is created.
        The on_commit() is used to postpone the task creation after the transaction is
        successfully committed.
        If there isn’t an active transaction, the callback will be executed immediately.
        """
        pipeline_class = scanpipe_app.pipelines.get(pipeline_name)
        run = Run.objects.create(
            project=self,
            pipeline_name=pipeline_name,
            description=pipeline_class.get_doc(),
        )
        if execute_now:
            transaction.on_commit(run.execute_task_async)
        return run

    def get_next_run(self):
        """
        Return the next non-executed Run instance assigned to this project.
        """
        with suppress(ObjectDoesNotExist):
            return self.runs.not_started().earliest("created_date")

    def get_latest_failed_run(self):
        """
        Return the latest failed Run instance of this project.
        """
        with suppress(ObjectDoesNotExist):
            return self.runs.failed().latest("created_date")

    def add_error(self, error, model, details=None):
        """
        Create a ProjectError record from the provided `error` Exception for this
        project.
        """
        traceback = ""
        if hasattr(error, "__traceback__"):
            traceback = "".join(format_tb(error.__traceback__))

        return ProjectError.objects.create(
            project=self,
            model=model,
            details=details or {},
            message=str(error),
            traceback=traceback,
        )

    def get_absolute_url(self):
        return reverse("project_detail", args=[self.uuid])

    @cached_property
    def resource_count(self):
        return self.codebaseresources.count()

    @cached_property
    def file_count(self):
        return self.codebaseresources.files().count()

    @cached_property
    def file_in_package_count(self):
        return self.codebaseresources.files().in_package().count()

    @cached_property
    def file_not_in_package_count(self):
        return self.codebaseresources.files().not_in_package().count()

    @cached_property
    def package_count(self):
        return self.discoveredpackages.count()

    @cached_property
    def error_count(self):
        return self.projecterrors.count()


class ProjectRelatedQuerySet(models.QuerySet):
    def project(self, project):
        return self.filter(project=project)


class ProjectRelatedModel(models.Model):
    """
    Base model for all models that are related to a Project.
    """

    project = models.ForeignKey(
        Project, related_name="%(class)ss", on_delete=models.CASCADE, editable=False
    )

    objects = ProjectRelatedQuerySet.as_manager()

    class Meta:
        abstract = True

    @classmethod
    def model_fields(cls):
        return [field.name for field in cls._meta.get_fields()]


class ProjectError(UUIDPKModel, ProjectRelatedModel):
    """
    Store errors and exceptions raised during a pipeline run.
    """

    created_date = models.DateTimeField(auto_now_add=True, editable=False)
    model = models.CharField(max_length=100, help_text=_("Name of the model class."))
    details = models.JSONField(
        default=dict, blank=True, help_text=_("Data that caused the error.")
    )
    message = models.TextField(blank=True, help_text=_("Error message."))
    traceback = models.TextField(blank=True, help_text=_("Exception traceback."))

    class Meta:
        ordering = ["created_date"]


class SaveProjectErrorMixin:
    """
    Use `SaveProjectErrorMixin` on a model to create a ProjectError entry
    from a raised exception during `save()` in place of stopping the analysis
    process.
    The creation of ProjectError can be skipped providing False for the `save_error`
    argument.
    """

    def save(self, *args, save_error=True, **kwargs):
        try:
            super().save(*args, **kwargs)
        except Exception as error:
            if save_error:
                self.add_error(error)

    @classmethod
    def check(cls, **kwargs):
        errors = super().check(**kwargs)
        errors += [*cls._check_project_field(**kwargs)]
        return errors

    @classmethod
    def _check_project_field(cls, **kwargs):
        """
        Check if `project` field is declared on the model.
        """

        fields = [f.name for f in cls._meta.local_fields]
        if "project" not in fields:
            return [
                checks.Error(
                    "'project' field is required when using SaveProjectErrorMixin.",
                    obj=cls,
                    id="scanpipe.models.E001",
                )
            ]

        return []

    def add_error(self, error):
        """
        Create a ProjectError record from the provided `error` Exception.instance.
        """
        return self.project.add_error(
            error=error,
            model=self.__class__.__name__,
            details=model_to_dict(self),
        )

    def add_errors(self, errors):
        """
        Create ProjectError records from the provided `errors` Exception list.
        """
        for error in errors:
            self.add_error(error)


class RunQuerySet(ProjectRelatedQuerySet):
    def started(self):
        return self.filter(task_start_date__isnull=False)

    def not_started(self):
        return self.filter(task_start_date__isnull=True)

    def executed(self):
        return self.filter(task_end_date__isnull=False)

    def succeed(self):
        return self.filter(task_exitcode=0)

    def failed(self):
        return self.filter(task_exitcode__gt=0)


class Run(UUIDPKModel, ProjectRelatedModel, AbstractTaskFieldsModel):
    """
    The Database representation of a Pipeline execution.
    """

    pipeline_name = models.CharField(
        max_length=256,
        help_text=_("Identify a registered Pipeline class."),
    )
    created_date = models.DateTimeField(auto_now_add=True, db_index=True)
    description = models.TextField(blank=True)
    log = models.TextField(blank=True, editable=False)

    objects = RunQuerySet.as_manager()

    class Meta:
        ordering = ["created_date"]

    def __str__(self):
        return f"{self.pipeline_name}"

    def execute_task_async(self):
        tasks.execute_pipeline_task.apply_async(args=[self.pk])

    @property
    def pipeline_class(self):
        return scanpipe_app.pipelines.get(self.pipeline_name)

    def make_pipeline_instance(self):
        return self.pipeline_class(self)

    @property
    def task_succeeded(self):
        """
        Return True if the pipeline task was successfully executed.
        """
        return self.task_exitcode == 0

    def append_to_log(self, message, save=False):
        """
        Append the `message` string to the `log` field of this Run instance.
        """
        message = message.strip()
        if any(lf in message for lf in ("\n", "\r")):
            raise ValueError("message cannot contain line returns (either CR or LF).")

        self.log = self.log + message + "\n"
        if save:
            self.save()

    def profile(self, print_results=False):
        """
        Return computed execution times for each steps of this Run.

        If `print_results` is provided, the results are printed to stdout.
        """
        if not self.task_succeeded:
            return

        pattern = re.compile(r"Step \[(?P<step>.+)] completed in (?P<time>.+) seconds")

        profiler = {}
        for line in self.log.split("\n"):
            match = pattern.search(line)
            if match:
                step, runtime = match.groups()
                profiler[step] = float(runtime)

        if not print_results or not profiler:
            return profiler

        total_runtime = sum(profiler.values())
        padding = max(len(name) for name in profiler.keys()) + 1
        for step, runtime in profiler.items():
            percent = round(runtime * 100 / total_runtime, 1)
            output_str = f"{step:{padding}} {runtime:>3} seconds {percent}%"
            if percent > 50:
                print("\033[41;37m" + output_str + "\033[m")
            else:
                print(output_str)


class CodebaseResourceQuerySet(ProjectRelatedQuerySet):
    def status(self, status=None):
        if status:
            return self.filter(status=status)
        return self.filter(~Q(status=""))

    def no_status(self):
        return self.filter(status="")

    def empty(self):
        return self.filter(Q(size__isnull=True) | Q(size=0))

    def in_package(self):
        return self.filter(discovered_packages__isnull=False)

    def not_in_package(self):
        return self.filter(discovered_packages__isnull=True)

    def files(self):
        return self.filter(type=self.model.Type.FILE)

    def directories(self):
        return self.filter(type=self.model.Type.DIRECTORY)

    def symlinks(self):
        return self.filter(type=self.model.Type.SYMLINK)

    def without_symlinks(self):
        return self.filter(~Q(type=self.model.Type.SYMLINK))

    def has_licenses(self):
        return self.filter(~Q(licenses=[]))

    def has_no_licenses(self):
        return self.filter(licenses=[])


class ScanFieldsModelMixin(models.Model):
    """
    Fields returned by ScanCode-toolkit scans.
    """

    copyrights = models.JSONField(
        blank=True,
        default=list,
        help_text=_(
            "List of detected copyright statements (and related detection details)."
        ),
    )
    holders = models.JSONField(
        blank=True,
        default=list,
        help_text=_(
            "List of detected copyright holders (and related detection details)."
        ),
    )
    authors = models.JSONField(
        blank=True,
        default=list,
        help_text=_("List of detected authors (and related detection details)."),
    )
    licenses = models.JSONField(
        blank=True,
        default=list,
        help_text=_("List of license detection details."),
    )
    license_expressions = models.JSONField(
        blank=True,
        default=list,
        help_text=_("List of detected license expressions."),
    )
    emails = models.JSONField(
        blank=True,
        default=list,
        help_text=_("List of detected emails (and related detection details)."),
    )
    urls = models.JSONField(
        blank=True,
        default=list,
        help_text=_("List of detected URLs (and related detection details)."),
    )

    class Meta:
        abstract = True

    @classmethod
    def scan_fields(cls):
        return [field.name for field in ScanFieldsModelMixin._meta.get_fields()]

    def set_scan_results(self, scan_results, save=False):
        """
        Set the values from `scan_results` on this instance scan related fields.
        """
        scan_fields = self.scan_fields()
        for field_name, value in scan_results.items():
            if value and field_name in scan_fields:
                setattr(self, field_name, value)

        if save:
            self.save()

    def copy_scan_results(self, from_instance, save=False):
        """
        Copy the scan related fields values from `from_instance`to this instance.
        """
        for field_name in self.scan_fields():
            value_from_instance = getattr(from_instance, field_name)
            setattr(self, field_name, value_from_instance)

        if save:
            self.save()


class CodebaseResource(
    ProjectRelatedModel, ScanFieldsModelMixin, SaveProjectErrorMixin, AbstractResource
):
    rootfs_path = models.CharField(
        max_length=2000,
        blank=True,
        help_text=_(
            "Path relative to some root filesystem root directory. "
            "Useful when working on disk images, docker images, and VM images."
            'Eg.: "/usr/bin/bash" for a path of "tarball-extract/rootfs/usr/bin/bash"'
        ),
    )
    status = models.CharField(
        blank=True,
        max_length=30,
        help_text=_("Analysis status for this resource."),
    )

    class Type(models.TextChoices):
        FILE = "file"
        DIRECTORY = "directory"
        SYMLINK = "symlink"

    type = models.CharField(
        max_length=10,
        choices=Type.choices,
        help_text=_(
            "Type of this resource as one of: {}".format(", ".join(Type.values))
        ),
    )
    extra_data = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Optional mapping of extra data key/values."),
    )
    name = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("File or directory name of this resource."),
    )
    extension = models.CharField(
        max_length=100,
        blank=True,
        help_text=_(
            "File extension for this resource (directories do not have an extension)."
        ),
    )
    programming_language = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Programming language of this resource if this is a code file."),
    )
    mime_type = models.CharField(
        max_length=100,
        blank=True,
        help_text=_(
            "MIME type (aka. media type) for this resource. "
            "See https://en.wikipedia.org/wiki/Media_type"
        ),
    )
    file_type = models.CharField(
        max_length=1024,
        blank=True,
        help_text=_("Descriptive file type for this resource."),
    )

    class Compliance(models.TextChoices):
        OK = "ok"
        WARNING = "warning"
        ERROR = "error"
        MISSING = "missing"

    compliance_alert = models.CharField(
        max_length=10,
        blank=True,
        choices=Compliance.choices,
        editable=False,
        help_text=_(
            "Indicates how the detected licenses in a codebase resource complies with "
            "provided policies."
        ),
    )

    objects = CodebaseResourceQuerySet.as_manager()

    class Meta:
        unique_together = (("project", "path"),)
        ordering = ("project", "path")

    def __str__(self):
        return self.path

    @classmethod
    def from_db(cls, db, field_names, values):
        """
        Store the `licenses` field on creating this instance from the database value.
        The cached value is then used to detected changes on `save()`.
        """
        new = super().from_db(db, field_names, values)

        if "licenses" in field_names:
            new._loaded_licenses = values[field_names.index("licenses")]

        return new

    def save(self, *args, **kwargs):
        """
        Inject policies if the feature is enabled when the `licenses` field value is
        changed.
        """
        if scanpipe_app.policies_enabled:
            loaded_licenses = getattr(self, "loaded_licenses", [])
            if self.licenses != loaded_licenses:
                self.inject_licenses_policy(scanpipe_app.license_policies_index)
                self.compliance_alert = self.compute_compliance_alert()

        super().save(*args, **kwargs)

    def inject_licenses_policy(self, policies_index):
        """
        Inject license policies from the `policies_index` into the `licenses` field.
        """
        for license_data in self.licenses:
            key = license_data.get("key")
            license_data["policy"] = policies_index.get(key, None)

    @property
    def location_path(self):
        # strip the leading / to allow joining this with the codebase_path
        path = Path(str(self.path).strip("/"))
        return self.project.codebase_path / path

    @property
    def location(self):
        return str(self.location_path)

    @property
    def filename(self):
        return f"{self.name}{self.extension}"

    @property
    def is_file(self):
        return self.type == self.Type.FILE

    @property
    def is_dir(self):
        return self.type == self.Type.DIRECTORY

    @property
    def is_symlink(self):
        return self.type == self.Type.SYMLINK

    def compute_compliance_alert(self):
        """
        Compute and return the compliance_alert value from the `licenses` policies.
        """
        if not self.licenses:
            return ""

        ok = self.Compliance.OK
        error = self.Compliance.ERROR
        warning = self.Compliance.WARNING
        missing = self.Compliance.MISSING

        alerts = []
        for license_data in self.licenses:
            policy = license_data.get("policy")
            if policy:
                alerts.append(policy.get("compliance_alert") or ok)
            else:
                alerts.append(missing)

        if error in alerts:
            return error
        elif warning in alerts:
            return warning
        elif missing in alerts:
            return missing
        return ok

    @property
    def unique_license_expressions(self):
        return sorted(set(self.license_expressions))

    def descendants(self):
        """
        Return a QuerySet of descendant CodebaseResource objects using a
        Database query on this CodebaseResource `path`.
        The current CodebaseResource is not included.
        """
        return self.project.codebaseresources.filter(path__startswith=f"{self.path}/")

    def children(self, codebase=None):
        """
        Return a QuerySet of direct children CodebaseResource objects using a
        Database query on this CodebaseResource `path`.

        Paths are returned in lower-cased sorted path order to reflect the
        behavior of `commoncode.resource.Resource.children()`
        https://github.com/nexB/commoncode/blob/76a03d9c1cd2a582dcec4351c768c3ef646e1b31/src/commoncode/resource.py#L1199

        `codebase` is not used in this context but required for compatibility
        with the commoncode.resource.VirtualCodebase class API.
        """
        exactly_one_sub_directory = "[^/]+$"
        children_regex = rf"^{self.path}/{exactly_one_sub_directory}"
        return (
            self.descendants()
            .filter(path__regex=children_regex)
            .order_by(Lower("path"))
        )

    def walk(self, topdown=True):
        """
        Yield all descendant Resources of this Resource. Does not include self.

        Walk the tree top-down, depth-first if `topdown` is True, otherwise walk
        bottom-up.
        """
        for child in self.children().iterator():
            if topdown:
                yield child
            for subchild in child.walk(topdown=topdown):
                yield subchild
            if not topdown:
                yield child

    def get_absolute_url(self):
        return reverse("resource_detail", args=[self.project_id, self.pk])

    @property
    def file_content(self):
        """
        Return the content of this Resource file using TextCode utilities for
        optimal compatibility.
        """
        from textcode.analysis import numbered_text_lines

        numbered_lines = numbered_text_lines(self.location)

        # ScanCode-toolkit is not providing the "\n" suffix when reading binary files.
        # The following is a workaround until the issue is fixed in the toolkit.
        lines = (l if l.endswith("\n") else l + "\n" for _, l in numbered_lines)

        return "".join(lines)

    def create_and_add_package(self, package_data):
        """
        Create a DiscoveredPackage instance using the `package_data` and assign
        it to this CodebaseResource instance.
        """
        created_package = DiscoveredPackage.create_from_data(self.project, package_data)
        if created_package:
            self.discovered_packages.add(created_package)
            return created_package

    @property
    def for_packages(self):
        return [str(package) for package in self.discovered_packages.all()]


class DiscoveredPackage(ProjectRelatedModel, SaveProjectErrorMixin, AbstractPackage):
    codebase_resources = models.ManyToManyField(
        "CodebaseResource", related_name="discovered_packages"
    )
    missing_resources = models.JSONField(default=list, blank=True)
    modified_resources = models.JSONField(default=list, blank=True)

    # AbstractPackage overrides:
    keywords = models.JSONField(default=list, blank=True)
    source_packages = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["uuid"]

    def __str__(self):
        return self.package_url or str(self.uuid)

    @property
    def purl(self):
        return self.package_url

    @classmethod
    def create_from_data(cls, project, package_data):
        """
        Create and return a DiscoveredPackage for `project` from the `package_data`.
        If one of the required fields value is not available, a ProjectError is create
        in place of the DiscoveredPackage instance.
        """
        required_fields = ["type", "name", "version"]
        required_values = [package_data.get(field) for field in required_fields]

        if not all(required_values):
            message = (
                f"One or more of the required fields have no value: "
                f"{', '.join(required_fields)}"
            )
            project.add_error(error=message, model=cls.__name__, details=package_data)
            return

        qualifiers = package_data.get("qualifiers")
        if qualifiers:
            package_data["qualifiers"] = normalize_qualifiers(qualifiers, encode=True)

        cleaned_package_data = {
            field_name: value
            for field_name, value in package_data.items()
            if field_name in DiscoveredPackage.model_fields() and value
        }

        return cls.objects.create(project=project, **cleaned_package_data)
