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
import json
import logging
import re
import shutil
import uuid
from collections import Counter
from contextlib import suppress
from itertools import groupby
from operator import itemgetter
from pathlib import Path
from traceback import format_tb
from urllib.parse import urlparse

from django.apps import apps
from django.conf import settings
from django.core import checks
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import EMPTY_VALUES
from django.db import models
from django.db import transaction
from django.db.models import Count
from django.db.models import IntegerField
from django.db.models import OuterRef
from django.db.models import Prefetch
from django.db.models import Q
from django.db.models import Subquery
from django.db.models import TextField
from django.db.models.functions import Cast
from django.db.models.functions import Lower
from django.dispatch import receiver
from django.forms import model_to_dict
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.text import slugify
from django.utils.translation import gettext_lazy as _

import django_rq
import redis
import requests
import saneyaml
from commoncode.fileutils import parent_directory
from cyclonedx import model as cyclonedx_model
from cyclonedx.model import component as cyclonedx_component
from cyclonedx.model import license as cyclonedx_license
from extractcode import EXTRACT_SUFFIX
from licensedcode.cache import build_spdx_license_expression
from licensedcode.cache import get_licensing
from matchcode_toolkit.fingerprinting import IGNORED_DIRECTORY_FINGERPRINTS
from packageurl import PackageURL
from packageurl import normalize_qualifiers
from packageurl.contrib.django.models import PackageURLMixin
from packageurl.contrib.django.models import PackageURLQuerySetMixin
from rest_framework.authtoken.models import Token
from rq.command import send_stop_job_command
from rq.exceptions import NoSuchJobError
from rq.job import Job
from rq.job import JobStatus
from taggit.managers import TaggableManager
from taggit.models import GenericUUIDTaggedItemBase
from taggit.models import TaggedItemBase

import scancodeio
from scanpipe import humanize_time
from scanpipe import tasks

logger = logging.getLogger(__name__)
scanpipe_app = apps.get_app_config("scanpipe")


class RunInProgressError(Exception):
    """Run are in progress or queued on this project."""


class RunNotAllowedToStart(Exception):
    """Previous Runs have not completed yet."""


# PackageURL._fields
PURL_FIELDS = ("type", "namespace", "name", "version", "qualifiers", "subpath")


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


class HashFieldsMixin(models.Model):
    """
    The hash fields are not indexed by default, use the `indexes` in Meta as needed:

    class Meta:
        indexes = [
            models.Index(fields=['md5']),
            models.Index(fields=['sha1']),
            models.Index(fields=['sha256']),
            models.Index(fields=['sha512']),
        ]
    """

    md5 = models.CharField(
        _("MD5"),
        max_length=32,
        blank=True,
        help_text=_("MD5 checksum hex-encoded, as in md5sum."),
    )
    sha1 = models.CharField(
        _("SHA1"),
        max_length=40,
        blank=True,
        help_text=_("SHA1 checksum hex-encoded, as in sha1sum."),
    )
    sha256 = models.CharField(
        _("SHA256"),
        max_length=64,
        blank=True,
        help_text=_("SHA256 checksum hex-encoded, as in sha256sum."),
    )
    sha512 = models.CharField(
        _("SHA512"),
        max_length=128,
        blank=True,
        help_text=_("SHA512 checksum hex-encoded, as in sha512sum."),
    )

    class Meta:
        abstract = True


class AbstractTaskFieldsModel(models.Model):
    """
    Base model including all the fields and methods to synchronize tasks in the
    database with their related RQ Job.

    Specify ``update_fields`` during each ``save()`` to force a SQL UPDATE in order to
    avoid any data loss when the model fields are updated during the task execution.
    """

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
    log = models.TextField(blank=True, editable=False)

    class Meta:
        abstract = True

    def delete(self, *args, **kwargs):
        """
        Before deletion of the Run instance, try to stop the task if currently running
        or to remove it from the queue if currently queued.

        Note that projects with queued or running pipeline runs cannot be deleted.
        See the `_raise_if_run_in_progress` method.
        The following if statements should not be triggered unless the `.delete()`
        method is directly call from a instance of this class.
        """
        with suppress(redis.exceptions.ConnectionError, AttributeError):
            if self.status == self.Status.RUNNING:
                self.stop_task()
            elif self.status == self.Status.QUEUED:
                self.delete_task(delete_self=False)

        return super().delete(*args, **kwargs)

    @staticmethod
    def get_job(job_id):
        with suppress(NoSuchJobError):
            return Job.fetch(job_id, connection=django_rq.get_connection())

    @property
    def job(self):
        """None if the job could not be found in the queues registries."""
        return self.get_job(str(self.task_id))

    @property
    def job_status(self):
        job = self.job
        if job:
            return self.job.get_status()

    @property
    def task_succeeded(self):
        """Return True if the task was successfully executed."""
        return self.task_exitcode == 0

    @property
    def task_failed(self):
        """Return True if the task failed."""
        return self.task_exitcode and self.task_exitcode > 0

    @property
    def task_stopped(self):
        """Return True if the task was stopped."""
        return self.task_exitcode == 99

    @property
    def task_staled(self):
        """Return True if the task staled."""
        return self.task_exitcode == 88

    class Status(models.TextChoices):
        """List of Run status."""

        NOT_STARTED = "not_started"
        QUEUED = "queued"
        RUNNING = "running"
        SUCCESS = "success"
        FAILURE = "failure"
        STOPPED = "stopped"
        STALE = "stale"

    @property
    def status(self):
        """Return the task current status."""
        status = self.Status

        if self.task_succeeded:
            return status.SUCCESS

        elif self.task_staled:
            return status.STALE

        elif self.task_stopped:
            return status.STOPPED

        elif self.task_failed:
            return status.FAILURE

        elif self.task_start_date:
            return status.RUNNING

        elif self.task_id:
            return status.QUEUED

        return status.NOT_STARTED

    @property
    def execution_time(self):
        if self.task_staled:
            return

        elif self.task_end_date and self.task_start_date:
            total_seconds = (self.task_end_date - self.task_start_date).total_seconds()
            return int(total_seconds)

    @property
    def execution_time_for_display(self):
        """Return the ``execution_time`` formatted for display."""
        execution_time = self.execution_time
        if execution_time:
            return humanize_time(execution_time)

    def reset_task_values(self):
        """Reset all task-related fields to their initial null value."""
        self.task_id = None
        self.task_start_date = None
        self.task_end_date = None
        self.task_exitcode = None
        self.task_output = ""
        self.save(
            update_fields=[
                "task_id",
                "task_start_date",
                "task_end_date",
                "task_exitcode",
                "task_output",
            ]
        )

    def set_task_started(self, task_id):
        """Set the `task_id` and `task_start_date` fields before executing the task."""
        self.task_id = task_id
        self.task_start_date = timezone.now()
        self.save(update_fields=["task_id", "task_start_date"])

    def set_task_ended(self, exitcode, output=""):
        """Set the task-related fields after the task execution."""
        self.task_exitcode = exitcode
        self.task_output = output
        self.task_end_date = timezone.now()
        self.save(update_fields=["task_exitcode", "task_output", "task_end_date"])

    def set_task_queued(self):
        """
        Set the task as "queued" by updating the ``task_id`` from ``None`` to this
        instance ``pk``.
        """
        if self.task_id:
            raise ValueError("task_id is already set")

        self.task_id = self.pk
        self.save(update_fields=["task_id"])

    def set_task_staled(self):
        """Set the task as "stale" using a special 88 exitcode value."""
        self.set_task_ended(exitcode=88)

    def set_task_stopped(self):
        """Set the task as "stopped" using a special 99 exitcode value."""
        self.set_task_ended(exitcode=99)

    def stop_task(self):
        """Stop a "running" task."""
        self.append_to_log("Stop task requested")

        if not settings.SCANCODEIO_ASYNC:
            self.set_task_stopped()
            return

        job_status = self.job_status

        if not job_status:
            self.set_task_staled()
            return

        if self.job_status == JobStatus.FAILED:
            self.set_task_ended(
                exitcode=1,
                output=f"Killed from outside, latest_result={self.job.latest_result()}",
            )
            return

        send_stop_job_command(
            connection=django_rq.get_connection(), job_id=str(self.task_id)
        )
        self.set_task_stopped()

    def delete_task(self, delete_self=True):
        """Delete a "not started" or "queued" task."""
        if settings.SCANCODEIO_ASYNC and self.task_id:
            job = self.job
            if job:
                self.job.delete()

        if delete_self:
            self.delete()

    def append_to_log(self, message):
        """Append the ``message`` string to the ``log`` field of this instance."""
        message = message.strip()
        if any(lf in message for lf in ("\n", "\r")):
            raise ValueError("message cannot contain line returns (either CR or LF).")

        self.log = self.log + message + "\n"
        self.save(update_fields=["log"])


class ExtraDataFieldMixin(models.Model):
    """Add the `extra_data` field and helper methods."""

    extra_data = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Optional mapping of extra data key/values."),
    )

    def update_extra_data(self, data):
        """Update the `extra_data` field with the provided `data` dict."""
        if not isinstance(data, dict):
            raise ValueError("Argument `data` value must be a dict()")

        self.extra_data.update(data)
        self.save(update_fields=["extra_data"])

    class Meta:
        abstract = True


class UpdateMixin:
    """
    Provide a ``update()`` method to trigger a save() on the object with the
    ``update_fields`` automatically set to force a SQL UPDATE.
    """

    def update(self, **kwargs):
        """
        Update this resource with the provided ``kwargs`` values.
        The full ``save()`` process will be triggered, including signals, and the
        ``update_fields`` is automatically set.
        """
        for field_name, value in kwargs.items():
            setattr(self, field_name, value)

        self.save(update_fields=list(kwargs.keys()))


def get_project_slug(project):
    """
    Return a "slug" value for the provided ``project`` based on the slugify name
    attribute combined with the ``short_uuid`` to ensure its uniqueness.
    """
    return f"{slugify(project.name)}-{project.short_uuid}"


def get_project_work_directory(project):
    """
    Return the work directory location for a given `project`.
    The `project` name is "slugified" to generate a nicer directory path without
    any whitespace or special characters.
    A short version of the `project` uuid is added as a suffix to ensure
    uniqueness of the work directory location.
    """
    project_workspace_id = get_project_slug(project)
    return f"{scanpipe_app.workspace_path}/projects/{project_workspace_id}"


class ProjectQuerySet(models.QuerySet):
    def with_counts(self, *fields):
        """
        Annotate the QuerySet with counts of provided relational `fields`.
        Using `Subquery` in place of the `Count` aggregate function as it results in
        poor query performances when combining multiple counts.

        Usage:
            project_queryset.with_counts("codebaseresources", "discoveredpackages")
        """
        annotations = {}
        for field_name in fields:
            count_label = f"{field_name}_count"
            subquery_qs = self.model.objects.annotate(
                **{count_label: Count(field_name)}
            ).filter(pk=OuterRef("pk"))

            annotations[count_label] = Subquery(
                subquery_qs.values(count_label),
                output_field=IntegerField(),
            )

        return self.annotate(**annotations)


class UUIDTaggedItem(GenericUUIDTaggedItemBase, TaggedItemBase):
    class Meta:
        verbose_name = _("Label")
        verbose_name_plural = _("Labels")


class Project(UUIDPKModel, ExtraDataFieldMixin, UpdateMixin, models.Model):
    """
    The Project encapsulates all analysis processing.
    Multiple analysis pipelines can be run on the same project.
    """

    created_date = models.DateTimeField(
        auto_now_add=True,
        help_text=_("Creation date for this project."),
    )
    name = models.CharField(
        unique=True,
        max_length=100,
        help_text=_("Name for this project."),
    )
    slug = models.SlugField(
        unique=True,
        max_length=110,  # enough for name.max_length + len(short_uuid)
    )
    WORK_DIRECTORIES = ["input", "output", "codebase", "tmp"]
    work_directory = models.CharField(
        max_length=2048,
        editable=False,
        help_text=_("Project work directory location."),
    )
    is_archived = models.BooleanField(
        default=False,
        editable=False,
        help_text=_(
            "Archived projects cannot be modified anymore and are not displayed by "
            "default in project lists. Multiple levels of data cleanup may have "
            "happened during the archive operation."
        ),
    )
    notes = models.TextField(blank=True)
    settings = models.JSONField(default=dict, blank=True)
    labels = TaggableManager(through=UUIDTaggedItem)

    objects = ProjectQuerySet.as_manager()

    class Meta:
        ordering = ["-created_date"]
        indexes = [
            models.Index(fields=["-created_date"]),
            models.Index(fields=["is_archived"]),
            models.Index(fields=["name"]),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        """
        Save this project instance.
        The workspace directories are set up during project creation.
        """
        if not self.slug:
            self.slug = get_project_slug(project=self)

        if not self.work_directory:
            self.work_directory = get_project_work_directory(project=self)
            self.setup_work_directory()

        super().save(*args, **kwargs)

    def archive(self, remove_input=False, remove_codebase=False, remove_output=False):
        """
        Set the project `is_archived` field to True.

        The `remove_input`, `remove_codebase`, and `remove_output` can be provided
        during the archive operation to delete the related work directories.

        The project cannot be archived if one of its related run is queued or already
        running.
        """
        self._raise_if_run_in_progress()

        if remove_input:
            # Delete the file on disk but keep the InputSource entries for reference.
            shutil.rmtree(self.input_path, ignore_errors=True)

        if remove_codebase:
            shutil.rmtree(self.codebase_path, ignore_errors=True)

        if remove_output:
            shutil.rmtree(self.output_path, ignore_errors=True)

        shutil.rmtree(self.tmp_path, ignore_errors=True)
        self.setup_work_directory()

        self.is_archived = True
        self.save(update_fields=["is_archived"])

    def delete_related_objects(self):
        """
        Delete all related object instances using the private `_raw_delete` model API.
        This bypass the objects collection, cascade deletions, and signals.
        It results in a much faster objects deletion, but it needs to be applied in the
        correct models order as the cascading event will not be triggered.
        Note that this approach is used in Django's `fast_deletes` but the scanpipe
        models are cannot be fast-deleted as they have cascades and relations.
        """
        # Use default `delete()` on the DiscoveredPackage model, as the
        # `codebase_resources (ManyToManyField)` records need to collected and
        # properly deleted first.
        # Since this `ManyToManyField` has an implicit model table, we cannot directly
        # run the `_raw_delete()` on its QuerySet.
        _, deleted_counter = self.discoveredpackages.all().delete()

        # Removes all tags from this project by deleting the UUIDTaggedItem instances.
        self.labels.clear()

        relationships = [
            self.projectmessages,
            self.codebaserelations,
            self.discovereddependencies,
            self.discoveredlicenses,
            self.codebaseresources,
            self.runs,
        ]

        for qs in relationships:
            count = qs.all()._raw_delete(qs.db)
            deleted_counter[qs.model._meta.label] = count

        return deleted_counter

    def delete(self, *args, **kwargs):
        """Delete the `work_directory` along project-related data in the database."""
        self._raise_if_run_in_progress()

        shutil.rmtree(self.work_directory, ignore_errors=True)

        # Start with the optimized deletion of the related objects before calling the
        # full `delete()` process.
        self.delete_related_objects()

        return super().delete(*args, **kwargs)

    def reset(self, keep_input=True):
        """
        Reset the project by deleting all related database objects and all work
        directories except the input directory—when the `keep_input` option is True.
        """
        self._raise_if_run_in_progress()

        self.delete_related_objects()

        work_directories = [
            self.codebase_path,
            self.output_path,
            self.tmp_path,
        ]

        if not keep_input:
            work_directories.append(self.input_path)
            self.inputsources.all().delete()

        self.extra_data = {}
        self.save()

        for path in work_directories:
            shutil.rmtree(path, ignore_errors=True)

        self.setup_work_directory()

    def clone(
        self,
        clone_name,
        copy_inputs=False,
        copy_pipelines=False,
        copy_settings=False,
        copy_subscriptions=False,
        execute_now=False,
    ):
        """Clone this project using the provided ``clone_name`` as new project name."""
        cloned_project = Project.objects.create(
            name=clone_name,
            settings=self.settings if copy_settings else {},
        )

        if labels := self.labels.names():
            cloned_project.labels.add(*labels)

        if copy_inputs:
            # Clone the InputSource instances
            for input_source in self.inputsources.all():
                input_source.pk = None
                input_source.project = cloned_project
                input_source.save()
            # Copy the files from the input work directory
            for input_location in self.inputs():
                cloned_project.copy_input_from(input_location)

        if copy_pipelines:
            for run in self.runs.all():
                cloned_project.add_pipeline(
                    run.pipeline_name, execute_now, selected_groups=run.selected_groups
                )

        if copy_subscriptions:
            for subscription in self.webhooksubscriptions.all():
                cloned_project.add_webhook_subscription(subscription.target_url)

        return cloned_project

    def _raise_if_run_in_progress(self):
        """
        Raise a `RunInProgressError` exception if one of the project related run is
        queued or running.
        """
        if self.runs.queued_or_running().exists():
            raise RunInProgressError(
                "Cannot execute this action until all associated pipeline runs are "
                "completed."
            )

    def setup_work_directory(self):
        """Create all the work_directory structure and skips if already existing."""
        for subdirectory in self.WORK_DIRECTORIES:
            Path(self.work_directory, subdirectory).mkdir(parents=True, exist_ok=True)

    @property
    def work_path(self):
        """Return the `work_directory` as a Path instance."""
        return Path(self.work_directory)

    @property
    def input_path(self):
        """Return the `input` directory as a Path instance."""
        return Path(self.work_path / "input")

    @property
    def output_path(self):
        """Return the `output` directory as a Path instance."""
        return Path(self.work_path / "output")

    @property
    def codebase_path(self):
        """Return the `codebase` directory as a Path instance."""
        return Path(self.work_path / "codebase")

    @property
    def tmp_path(self):
        """Return the `tmp` directory as a Path instance."""
        return Path(self.work_path / "tmp")

    def get_codebase_config_directory(self):
        """
        Return the ``.scancode`` config directory if available in the `codebase`
        directory.
        """
        config_directory = self.codebase_path / settings.SCANCODEIO_CONFIG_DIR
        if config_directory.exists():
            return config_directory

    def get_input_config_file(self):
        """
        Return the ``scancode-config.yml`` file from the input/ directory if
        available.
        """
        config_file = self.input_path / settings.SCANCODEIO_CONFIG_FILE
        if config_file.exists():
            return config_file

    def get_settings_as_yml(self):
        """Return the ``settings`` file content as yml, suitable for a config file."""
        return saneyaml.dump(self.settings)

    def get_enabled_settings(self):
        """Return the enabled settings with non-empty values."""
        return {
            option: value
            for option, value in self.settings.items()
            if value not in EMPTY_VALUES
        }

    def get_env(self, field_name=None):
        """
        Return the project environment loaded from the ``.scancode/config.yml`` config
        file, when available, and overriden by the ``settings`` model field.

        ``field_name`` can be provided to get a single entry from the env.
        """
        env = {}

        # 1. Load settings from config file when available.
        if config_file := self.get_input_config_file():
            with suppress(saneyaml.YAMLError):
                env = saneyaml.load(config_file.read_text())

        # 2. Update with defined values from the Project ``settings`` field.
        env.update(self.get_enabled_settings())

        if field_name:
            return env.get(field_name)

        return env

    def clear_tmp_directory(self):
        """
        Delete the whole content of the tmp/ directory.
        This is called at the end of each pipeline Run, and it doesn't store
        any content that might be needed for further processing in following
        pipeline Run.
        """
        shutil.rmtree(self.tmp_path, ignore_errors=True)
        self.tmp_path.mkdir(parents=True, exist_ok=True)

    def inputs(self, pattern="**/*", extensions=None):
        """
        Return all files and directories path of the input/ directory matching
        a given `pattern`.
        The default `**/*` pattern means "this directory and all subdirectories,
        recursively".
        Use the `*` pattern to only list the root content.
        The returned paths can be limited to the provided list of ``extensions``.
        """
        if not extensions:
            return self.input_path.glob(pattern)

        if not isinstance(extensions, (list, tuple)):
            raise TypeError("extensions should be a list or tuple")

        return (
            path
            for path in self.input_path.glob(pattern)
            if str(path).endswith(tuple(extensions))
        )

    @property
    def input_files(self):
        """Return list of files' relative paths in the input/ directory recursively."""
        return [
            str(path.relative_to(self.input_path))
            for path in self.inputs()
            if path.is_file()
        ]

    @staticmethod
    def get_root_content(directory):
        """
        Return a list of all files and directories of a given `directory`.
        Only the first level children will be listed.
        """
        return [str(path.relative_to(directory)) for path in directory.glob("*")]

    @property
    def input_root(self):
        """
        Return a list of all files and directories of the input/ directory.
        Only the first level children will be listed.
        """
        return self.get_root_content(self.input_path)

    @property
    def input_sources(self):
        return self.get_inputs_with_source()

    def get_inputs_with_source(self):
        """Return an input list including the filename, download_url, and size data."""
        input_sources = []
        seen_filenames = set()

        for input_source in self.inputsources.all():
            input_sources.append(
                {
                    # Fields
                    "uuid": str(input_source.uuid),
                    "filename": input_source.filename,
                    "download_url": input_source.download_url,
                    "is_uploaded": input_source.is_uploaded,
                    "tag": input_source.tag,
                    # Properties
                    "size": input_source.size,
                    "is_file": True,
                    # Methods
                    "exists": input_source.exists(),
                }
            )
            seen_filenames.add(input_source.filename)

        # Inputs located in `input_path` but without an input source.
        # Those are usually manually copied there.
        for path in self.input_path.glob("*"):
            if path.name not in seen_filenames:
                input_sources.append(
                    {
                        "filename": path.name,
                        "is_uploaded": False,
                        "is_file": path.is_file(),
                        "size": path.stat().st_size,
                        "exists": True,
                    }
                )

        # Sort by filename for consistency across systems
        sorted_input_sources = sorted(input_sources, key=itemgetter("filename"))
        return sorted_input_sources

    @property
    def output_root(self):
        """
        Return a list of all files and directories of the output/ directory.
        Only first level children will be listed.
        """
        return self.get_root_content(self.output_path)

    def get_output_files_info(self):
        """Return files form the output work directory including the name and size."""
        return [
            {
                "name": path.name,
                "size": path.stat().st_size,
            }
            for path in self.output_path.glob("*")
            if path.is_file()
        ]

    def get_output_file_path(self, name, extension):
        """
        Return a crafted file path in the project output/ directory using
        given `name` and `extension`.
        The current date and time strings are added to the filename.

        This method ensures the proper setup of the work_directory in case of
        a manual wipe and re-creates the missing pieces of the directory structure.
        """
        from scanpipe.pipes import filename_now

        self.setup_work_directory()

        filename = f"{name}-{filename_now()}.{extension}"
        return self.output_path / filename

    def get_latest_output(self, filename):
        """
        Return the latest output file with the "filename" prefix, for example
        "scancode-<timestamp>.json".
        """
        output_files = sorted(self.output_path.glob(f"*{filename}*.json"))
        if output_files:
            return output_files[-1]

    def walk_codebase_path(self):
        """Return files and directories path of the codebase/ directory recursively."""
        return self.codebase_path.rglob("*")

    @cached_property
    def can_change_inputs(self):
        """
        Return True until one pipeline run has started its execution on the project.
        Always return False when the project is archived.
        """
        return not self.is_archived and not self.runs.has_start_date().exists()

    def write_input_file(self, file_object):
        """Write the provided `file_object` to the project's input/ directory."""
        filename = file_object.name
        file_path = Path(self.input_path / filename)

        with open(file_path, "wb+") as f:
            for chunk in file_object.chunks():
                f.write(chunk)

    def copy_input_from(self, input_location):
        """
        Copy the file at `input_location` to the current project's input/
        directory.
        """
        from scanpipe.pipes.input import copy_input

        copy_input(input_location, self.input_path)

    def move_input_from(self, input_location):
        """
        Move the file at `input_location` to the current project's input/
        directory.
        """
        from scanpipe.pipes.input import move_input

        return move_input(input_location, self.input_path)

    def add_input_source(self, download_url="", filename="", is_uploaded=False, tag=""):
        """
        Create a InputFile entry for the current project, given a `download_url` or
        a `filename`.
        """
        if not download_url and not filename:
            raise Exception("Provide at least a value for download_url or filename.")

        # Add tag can be provided using the "#<fragment>" part of the URL
        if download_url:
            parsed_url = urlparse(download_url)
            tag = parsed_url.fragment or tag

        return InputSource.objects.create(
            project=self,
            download_url=download_url,
            filename=filename,
            is_uploaded=is_uploaded,
            tag=tag,
        )

    def add_downloads(self, downloads):
        """
        Move the given `downloads` to the current project's input/ directory and
        adds the `input_source` for each entry.
        """
        for downloaded in downloads:
            self.move_input_from(downloaded.path)
            self.add_input_source(
                download_url=downloaded.uri,
                filename=downloaded.filename,
            )

    def add_upload(self, uploaded_file, tag=""):
        """
        Write the given `upload` to the current project's input/ directory and
        adds the `input_source`.
        """
        self.write_input_file(uploaded_file)
        self.add_input_source(filename=uploaded_file.name, is_uploaded=True, tag=tag)

    def add_uploads(self, uploads):
        """
        Write the given `uploads` to the current project's input/ directory and
        adds the `input_source` for each entry.
        """
        for uploaded_file in uploads:
            self.add_upload(uploaded_file)

    def add_pipeline(self, pipeline_name, execute_now=False, selected_groups=None):
        """
        Create a new Run instance with the provided `pipeline` on the current project.

        If `execute_now` is True, the pipeline task is created.
        on_commit() is used to postpone the task creation after the transaction is
        successfully committed.
        If there isn’t any active transactions, the callback will be executed
        immediately.
        """
        pipeline_class = scanpipe_app.pipelines.get(pipeline_name)
        if not pipeline_class:
            raise ValueError(f"Unknown pipeline: {pipeline_name}")

        validate_none_or_list(selected_groups)

        run = Run.objects.create(
            project=self,
            pipeline_name=pipeline_name,
            description=pipeline_class.get_summary(),
            selected_groups=selected_groups,
        )

        # Do not start the pipeline execution, even if explicitly requested,
        # when the Run is not allowed to start yet.
        if execute_now and run.can_start:
            transaction.on_commit(run.start)

        return run

    def add_webhook_subscription(self, target_url):
        """
        Create a new WebhookSubscription instance with the provided `target_url` for
        the current project.
        """
        return WebhookSubscription.objects.create(project=self, target_url=target_url)

    @cached_property
    def can_start_pipelines(self):
        """
        Return True if at least one "not started" pipeline is assigned to this project
        and if no pipeline runs is currently "queued or running".
        "not started".
        Always return False when the project is archived.
        """
        runs = self.runs.all()
        # Using Run QuerySet only once to avoid extra DB queries.
        not_started_runs = [run for run in runs if run.status == run.Status.NOT_STARTED]
        queued_or_running_runs = [
            run for run in runs if run.status in (run.Status.QUEUED, run.Status.RUNNING)
        ]

        conditions = [
            not self.is_archived,
            not_started_runs,  # At least one run is "not started"
            not queued_or_running_runs,  # No runs are currently running or queued
        ]
        return all(conditions)

    def start_pipelines(self):
        """Start the next "not started" pipeline execution."""
        if next_not_started_run := self.get_next_run():
            return next_not_started_run.start()

    def get_next_run(self):
        """Return the next non-executed Run instance assigned to current project."""
        with suppress(ObjectDoesNotExist):
            return self.runs.not_started().earliest("created_date")

    def add_message(
        self,
        severity,
        description="",
        model="",
        details=None,
        exception=None,
        resource=None,
    ):
        """
        Create a ProjectMessage record for this Project.

        The ``model`` attribute can be provided as a string or as a Model class.
        A ``resource`` can be provided to keep track of the codebase resource that was
        analyzed when the error occurred.
        """
        if inspect.isclass(model):
            model = model.__name__

        traceback = ""
        if hasattr(exception, "__traceback__"):
            traceback = "".join(format_tb(exception.__traceback__))

        if exception and not description:
            description = str(exception)

        details = details or {}
        if resource:
            # Do not change this field name as it has special behavior in templates.
            details["resource_path"] = resource.path

        return ProjectMessage.objects.create(
            project=self,
            severity=severity,
            description=description,
            model=model,
            details=details,
            traceback=traceback,
        )

    def add_info(
        self,
        description="",
        model="",
        details=None,
        exception=None,
        resource=None,
    ):
        """Create an INFO ProjectMessage record for this project."""
        severity = ProjectMessage.Severity.INFO
        return self.add_message(
            severity, description, model, details, exception, resource
        )

    def add_warning(
        self,
        description="",
        model="",
        details=None,
        exception=None,
        resource=None,
    ):
        """Create a WARNING ProjectMessage record for this project."""
        severity = ProjectMessage.Severity.WARNING
        return self.add_message(
            severity, description, model, details, exception, resource
        )

    def add_error(
        self,
        description="",
        model="",
        details=None,
        exception=None,
        resource=None,
    ):
        """Create an ERROR ProjectMessage record using for this project."""
        severity = ProjectMessage.Severity.ERROR
        return self.add_message(
            severity, description, model, details, exception, resource
        )

    def get_absolute_url(self):
        """Return this project's details URL."""
        return reverse("project_detail", args=[self.slug])

    @cached_property
    def resource_count(self):
        """Return the number of resources related to this project."""
        return self.codebaseresources.count()

    @cached_property
    def file_count(self):
        """Return the number of **file** resources related to this project."""
        return self.codebaseresources.files().count()

    @cached_property
    def file_in_package_count(self):
        """
        Return the number of **file** resources **in a package** related to this
        project.
        """
        return self.codebaseresources.files().in_package().count()

    @cached_property
    def file_not_in_package_count(self):
        """
        Return the number of **file** resources **not in a package** related to this
        project.
        """
        return self.codebaseresources.files().not_in_package().count()

    @cached_property
    def package_count(self):
        """Return the number of packages related to this project."""
        return self.discoveredpackages.count()

    @cached_property
    def vulnerable_package_count(self):
        """Return the number of vulnerable packages related to this project."""
        return self.discoveredpackages.vulnerable().count()

    @cached_property
    def vulnerable_dependency_count(self):
        """Return the number of vulnerable dependencies related to this project."""
        return self.discovereddependencies.vulnerable().count()

    @cached_property
    def dependency_count(self):
        """Return the number of dependencies related to this project."""
        return self.discovereddependencies.count()

    @cached_property
    def license_detections_count(self):
        """Return the number of license detections in this project."""
        return self.discoveredlicenses.count()

    @cached_property
    def message_count(self):
        """Return the number of messages related to this project."""
        return self.projectmessages.count()

    @cached_property
    def relation_count(self):
        """Return the number of relations related to this project."""
        return self.codebaserelations.count()

    @cached_property
    def has_single_resource(self):
        """
        Return True if we only have a single CodebaseResource associated to this
        project, False otherwise.
        """
        return self.resource_count == 1


class GroupingQuerySetMixin:
    most_common_limit = settings.SCANCODEIO_MOST_COMMON_LIMIT

    def group_by(self, field_name):
        """
        Return a list of grouped values with their count, DESC ordered by count
        for the provided `field_name`.
        """
        return (
            self.values(field_name).annotate(count=Count(field_name)).order_by("-count")
        )

    def most_common_values(self, field_name, limit=most_common_limit):
        """
        Return a list of the most common values for the `field_name` ending at the
        provided `limit`.
        """
        return self.group_by(field_name)[:limit].values_list(field_name, flat=True)

    def less_common_values(self, field_name, limit=most_common_limit):
        """
        Return a list of the less common values for the `field_name` starting at the
        provided `limit`.
        """
        return self.group_by(field_name)[limit:].values_list(field_name, flat=True)

    def less_common(self, field_name, limit=most_common_limit):
        """
        Return a QuerySet filtered by the less common values for the provided
        `field_name` starting at the `limit`.
        """
        json_fields_mapping = {
            "copyrights": ("copyrights", "copyright"),
            "holders": ("holders", "holder"),
            "authors": ("authors", "author"),
        }

        if field_name in json_fields_mapping:
            field_name, data_field = json_fields_mapping.get(field_name)
            values_list = self.values_from_json_field(field_name, data_field)
            sorted_by_occurrence = list(dict(Counter(values_list).most_common()).keys())
            less_common_values = sorted_by_occurrence[limit:]
            return self.json_list_contains(field_name, data_field, less_common_values)

        less_common_values = self.less_common_values(field_name, limit)
        return self.filter(**{f"{field_name}__in": less_common_values})


class JSONFieldQuerySetMixin:
    def json_field_contains(self, field_name, value):
        """
        Filter the QuerySet looking for the `value` string in the `field_name` JSON
        field converted into text.
        Empty values are excluded as there's no need to cast those into text.
        """
        return (
            self.filter(~Q(**{field_name: []}))
            .annotate(**{f"{field_name}_as_text": Cast(field_name, TextField())})
            .filter(**{f"{field_name}_as_text__contains": value})
        )

    def json_list_contains(self, field_name, key, values):
        """
        Filter on the JSONField `field_name` that stores a list of dictionaries.

        json_list_contains("licenses", "name", ["MIT License", "Apache License 2.0"])
        """
        lookups = Q()

        for value in values:
            lookups |= Q(**{f"{field_name}__contains": [{key: value}]})

        return self.filter(lookups)

    def values_from_json_field(self, field_name, data_field):
        """
        Extract and return `data_field` values from each object of a JSONField
        `field_name` that stores a list of dictionaries.
        Empty value are kept in the return results as empty strings.
        """
        values = []

        for objects in self.values_list(field_name, flat=True):
            if not objects:
                values.append("")
            else:
                values.extend(
                    object_dict.get(data_field, "") for object_dict in objects
                )

        return values


class ProjectRelatedQuerySet(
    GroupingQuerySetMixin, JSONFieldQuerySetMixin, models.QuerySet
):
    def project(self, project):
        return self.filter(project=project)

    def get_or_none(self, *args, **kwargs):
        """Get the object from provided lookups or get None"""
        with suppress(self.model.DoesNotExist, ValidationError):
            return self.get(*args, **kwargs)


class ProjectRelatedModel(UpdateMixin, models.Model):
    """A base model for all models that are related to a Project."""

    project = models.ForeignKey(
        Project, related_name="%(class)ss", on_delete=models.CASCADE, editable=False
    )

    objects = ProjectRelatedQuerySet.as_manager()

    class Meta:
        abstract = True

    @classmethod
    def model_fields(cls):
        return [field.name for field in cls._meta.get_fields()]


class ProjectMessage(UUIDPKModel, ProjectRelatedModel):
    """Stores messages such as errors and exceptions raised during a pipeline run."""

    class Severity(models.TextChoices):
        INFO = "info"
        WARNING = "warning"
        ERROR = "error"

    severity = models.CharField(
        max_length=10,
        choices=Severity.choices,
        editable=False,
        help_text=_("Severity level of the message."),
    )
    description = models.TextField(blank=True, help_text=_("Description."))
    model = models.CharField(max_length=100, help_text=_("Name of the model class."))
    details = models.JSONField(
        default=dict,
        blank=True,
        encoder=DjangoJSONEncoder,
        help_text=_("Data that caused the error."),
    )
    traceback = models.TextField(blank=True, help_text=_("Exception traceback."))
    created_date = models.DateTimeField(auto_now_add=True, editable=False)

    class Meta:
        ordering = ["created_date"]
        indexes = [
            models.Index(fields=["severity"]),
            models.Index(fields=["model"]),
        ]

    def __str__(self):
        return f"[{self.pk}] {self.model}: {self.description}"


class SaveProjectMessageMixin:
    """
    Uses `SaveProjectMessageMixin` on a model to create a "ProjectMessage" entry
    from a raised exception during `save()` instead of stopping the analysis process.

    The creation of a "ProjectMessage" can be skipped providing False for the
    `save_error` argument. In that case, the error is not captured, it is re-raised.
    """

    def save(self, *args, save_error=True, capture_exception=True, **kwargs):
        try:
            super().save(*args, **kwargs)
        except Exception as error:
            if save_error:
                self.add_error(error)
            if not capture_exception:
                raise

    @classmethod
    def check(cls, **kwargs):
        errors = super().check(**kwargs)
        errors += [*cls._check_project_field(**kwargs)]
        return errors

    @classmethod
    def _check_project_field(cls, **kwargs):
        """Check if a `project` field is declared on the model."""
        fields = [f.name for f in cls._meta.local_fields]
        if "project" not in fields:
            return [
                checks.Error(
                    "'project' field is required when using SaveProjectMessageMixin.",
                    obj=cls,
                    id="scanpipe.models.E001",
                )
            ]

        return []

    def add_error(self, exception):
        """
        Create a ProjectMessage record using the provided ``exception`` Exception
        instance.
        """
        resource = None
        if isinstance(self, CodebaseResource):
            resource = self

        return self.project.add_error(
            model=self.__class__,
            details=model_to_dict(self),
            exception=exception,
            resource=resource,
        )

    def add_errors(self, exceptions):
        """
        Create ProjectMessage records suing the provided ``exceptions`` Exception
        list.
        """
        for exception in exceptions:
            self.add_error(exception)


class UpdateFromDataMixin:
    """Add a method to update an object instance from a `data` dict."""

    def update_from_data(self, data, override=False):
        """
        Update this object instance with the provided `data`.
        The `save()` is called only if at least one field was modified.
        """
        model_fields = self.model_fields()
        updated_fields = []

        for field_name, value in data.items():
            skip_reasons = [
                value in EMPTY_VALUES,
                field_name not in model_fields,
                field_name in PURL_FIELDS,
            ]
            if any(skip_reasons):
                continue

            current_value = getattr(self, field_name, None)
            if not current_value or (current_value != value and override):
                setattr(self, field_name, value)
                updated_fields.append(field_name)

        if updated_fields:
            self.save(update_fields=updated_fields)

        return updated_fields


class InputSource(UUIDPKModel, ProjectRelatedModel):
    """
    A model that represents an input file associated to a project.
    The file can either be "uploaded", or "fetched" from a provided `download_url`.
    """

    download_url = models.CharField(
        max_length=1024,
        blank=True,
        help_text=_("Download URL of the input file."),
    )
    filename = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("Name of the file as uploaded or downloaded from a source."),
    )
    is_uploaded = models.BooleanField(default=False)
    tag = models.CharField(blank=True, max_length=50)

    def __str__(self):
        if self.is_uploaded:
            return f"filename={self.filename} [uploaded]"
        elif self.filename:
            return f"filename={self.filename} [download_url={self.download_url}]"
        else:
            return self.download_url

    def save(self, *args, **kwargs):
        """Raise an error if download_url is not provided, except for uploaded files."""
        if not self.is_uploaded and not self.download_url:
            raise ValidationError("A `download_url` value is required.")

        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Delete the file on disk along the database entry."""
        self.delete_file()
        return super().delete(*args, **kwargs)

    @property
    def path(self):
        """
        Return the `Path` of the input source instance on disk when a
        `filename` is available.
        """
        if self.filename:
            return self.project.input_path / self.filename

    def exists(self):
        """Return True if the file is available on disk at the expected path."""
        path = self.path
        if path:
            return self.path.exists()
        return False

    def delete_file(self):
        """Delete the file on disk."""
        if path := self.path:
            path.unlink(missing_ok=True)

    @property
    def size(self):
        """Return file size in byte."""
        if self.exists():
            return self.path.stat().st_size

    def fetch(self):
        """Fetch the file from this instance ``download_url`` field."""
        from scanpipe.pipes.fetch import fetch_url

        if self.exists():
            logger.info("The input source file already exists.")
            return

        if not self.download_url:
            raise Exception("No `download_url` value to be fetched.")

        downloaded = fetch_url(url=self.download_url)
        destination = self.project.move_input_from(downloaded.path)

        # Force a commit to the database to ensure the file on disk is not rendered
        # as "manually uploaded" in the UI.
        with transaction.atomic():
            self.filename = downloaded.filename
            self.save()

        return destination


class RunQuerySet(ProjectRelatedQuerySet):
    def not_started(self):
        """Not in the execution queue, no `task_id` assigned."""
        return self.no_exitcode().no_start_date().filter(task_id__isnull=True)

    def queued(self):
        """In the execution queue with a `task_id` assigned but not running yet."""
        return self.no_exitcode().no_start_date().filter(task_id__isnull=False)

    def running(self):
        """Run the pipeline execution."""
        return self.no_exitcode().has_start_date().filter(task_end_date__isnull=True)

    def executed(self):
        """Pipeline execution completed, includes both succeed and failed runs."""
        return self.filter(task_end_date__isnull=False)

    def not_executed(self):
        """No `task_end_date` set. Its execution has not completed or started yet."""
        return self.filter(task_end_date__isnull=True)

    def succeed(self):
        """Pipeline execution completed with success."""
        return self.filter(task_exitcode=0)

    def failed(self):
        """Pipeline execution completed with failure."""
        return self.filter(task_exitcode__gt=0)

    def has_start_date(self):
        """Run has a `task_start_date` set. It can be running or executed."""
        return self.filter(task_start_date__isnull=False)

    def no_start_date(self):
        """Run has no `task_start_date` set."""
        return self.filter(task_start_date__isnull=True)

    def no_exitcode(self):
        """Run has no `task_exitcode` set."""
        return self.filter(task_exitcode__isnull=True)

    def queued_or_running(self):
        """Run is queued or currently running."""
        return self.filter(task_id__isnull=False, task_end_date__isnull=True)


def validate_none_or_list(value):
    if value is not None and not isinstance(value, list):
        raise ValidationError("Value must be a list.")


class Run(UUIDPKModel, ProjectRelatedModel, AbstractTaskFieldsModel):
    """The Database representation of a pipeline execution."""

    pipeline_name = models.CharField(
        max_length=256,
        help_text=_("Identify a registered Pipeline class."),
    )
    created_date = models.DateTimeField(auto_now_add=True, db_index=True)
    scancodeio_version = models.CharField(max_length=30, blank=True)
    description = models.TextField(blank=True)
    current_step = models.CharField(max_length=256, blank=True)
    selected_groups = models.JSONField(
        null=True, blank=True, validators=[validate_none_or_list]
    )

    objects = RunQuerySet.as_manager()

    class Meta:
        ordering = ["created_date"]

    def __str__(self):
        return f"{self.pipeline_name}"

    def get_previous_runs(self):
        """Return all the previous Run instances regardless of their status."""
        return self.project.runs.filter(created_date__lt=self.created_date)

    @property
    def can_start(self):
        """
        Return True if this Run is allowed to start its execution.

        Run are not allowed to start when any of their previous Run instances within
        the pipeline has not completed (not started, queued, or running).
        This is enforced to ensure the pipelines are run in a sequential order.
        """
        if self.status != self.Status.NOT_STARTED:
            return False

        if self.get_previous_runs().not_executed().exists():
            return False

        return True

    def start(self):
        """Start the pipeline execution when allowed or raised an exception."""
        if self.can_start:
            return self.execute_task_async()

        raise RunNotAllowedToStart(
            "Cannot execute this action until all previous pipeline runs are completed."
        )

    def execute_task_async(self):
        """Enqueues the pipeline execution task for an asynchronous execution."""
        run_pk = str(self.pk)

        # Bypass entirely the queue system and run the pipeline in the current thread.
        if not settings.SCANCODEIO_ASYNC:
            tasks.execute_pipeline_task(run_pk)
            return

        job = django_rq.enqueue(
            tasks.execute_pipeline_task,
            job_id=run_pk,
            run_pk=run_pk,
            on_failure=tasks.report_failure,
            job_timeout=settings.SCANCODEIO_TASK_TIMEOUT,
        )

        # In async mode, we want to set the status as "queued" **after** the job was
        # properly "enqueued".
        # In case the ``django_rq.enqueue()`` raise an exception (Redis server error),
        # we want to keep the Run status as "not started" rather than "queued".
        # Note that the Run will then be set as "running" at the start of
        # ``execute_pipeline_task()`` by calling the ``set_task_started()``.
        # There's no need to call the following in synchronous single thread mode as
        # the run will be directly set as "running".
        self.set_task_queued()

        return job

    def sync_with_job(self):
        """
        Synchronise this Run instance with its related RQ Job.
        This is required when a Run gets out of sync with its Job, this can happen
        when the worker or one of its processes is killed, the Run status is not
        properly updated and may stay in a Queued or Running state forever.
        In case the Run is out of sync of its related Job, the Run status will be
        updated accordingly. When the run was in the queue, it will be enqueued again.
        """
        RunStatus = self.Status

        if settings.SCANCODEIO_ASYNC:
            job_status = self.job_status
        else:
            job_status = None

        if not job_status:
            if self.status == RunStatus.QUEUED:
                logger.info(
                    f"No Job found for QUEUED Run={self.task_id}. "
                    f"Enqueueing a new Job in the worker registry."
                )
                # Reset the status to NOT_STARTED to allow the execution in `can_start`
                self.reset_task_values()
                self.start()

            elif self.status == RunStatus.RUNNING:
                logger.info(
                    f"No Job found for RUNNING Run={self.task_id}. "
                    f"Flagging this Run as STALE."
                )
                self.set_task_staled()

            return

        job_is_out_of_sync = any(
            [
                self.status == RunStatus.RUNNING and job_status != JobStatus.STARTED,
                self.status == RunStatus.QUEUED and job_status != JobStatus.QUEUED,
            ]
        )

        if job_is_out_of_sync:
            if job_status == JobStatus.STOPPED:
                logger.info(
                    f"Job found as {job_status} for RUNNING Run={self.task_id}. "
                    f"Flagging this Run as STOPPED."
                )
                self.set_task_stopped()

            elif job_status == JobStatus.FAILED:
                logger.info(
                    f"Job found as {job_status} for RUNNING Run={self.task_id}. "
                    f"Flagging this Run as FAILED."
                )
                self.set_task_ended(
                    exitcode=1,
                    output="Job was moved to the FailedJobRegistry during cleanup",
                )

            else:
                logger.info(
                    f"Job found as {job_status} for RUNNING Run={self.task_id}. "
                    f"Flagging this Run as STALE."
                )
                self.set_task_staled()

    def set_scancodeio_version(self):
        """Set the current ScanCode.io version on the ``scancodeio_version`` field."""
        if self.scancodeio_version:
            msg = f"Field scancodeio_version already set to {self.scancodeio_version}"
            raise ValueError(msg)

        self.update(scancodeio_version=scancodeio.__version__)

    def get_diff_url(self):
        """
        Return a GitHub diff URL between this Run commit at the time of execution
        and the current commit of the ScanCode.io app instance.
        The URL is only returned if both commit are available and if they differ.
        """
        if not (self.scancodeio_version and scancodeio.__version__):
            return

        run_commit = scancodeio.extract_short_commit(self.scancodeio_version)
        current_commit = scancodeio.extract_short_commit(scancodeio.__version__)

        if run_commit and current_commit and run_commit != current_commit:
            return f"{scancodeio.GITHUB_URL}/compare/{run_commit}..{current_commit}"

    def set_current_step(self, message):
        """
        Set the ``message`` value on the ``current_step`` field.
        Truncate the value at 256 characters.
        """
        self.update(current_step=message[:256])

    @property
    def pipeline_class(self):
        """Return this Run pipeline_class."""
        return scanpipe_app.pipelines.get(self.pipeline_name)

    def make_pipeline_instance(self):
        """Return a pipelines instance using this Run pipeline_class."""
        return self.pipeline_class(self)

    def deliver_project_subscriptions(self):
        """Triggers related project webhook subscriptions."""
        for subscription in self.project.webhooksubscriptions.all():
            subscription.deliver(pipeline_run=self)

    def profile(self, print_results=False):
        """
        Return computed execution times for each step in the current Run.

        If `print_results` is provided, the results are printed to stdout.
        """
        if not self.task_succeeded:
            return

        pattern = re.compile(r"Step \[(?P<step>.+)] completed in (?P<time>.+) seconds")

        profiler = {}
        for line in self.log.splitlines():
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


def convert_glob_to_django_regex(glob_pattern):
    """
    Convert a glob pattern to an equivalent django regex pattern
    compatible with the Django regex lookup.
    """
    escaped_pattern = re.escape(glob_pattern)
    escaped_pattern = escaped_pattern.replace(r"\*", ".*")  # Replace \* with .*
    escaped_pattern = escaped_pattern.replace(r"\?", ".")  # Replace \? with .
    escaped_pattern = f"^{escaped_pattern}$"  # Add start and end anchors
    return escaped_pattern


class CodebaseResourceQuerySet(ProjectRelatedQuerySet):
    def prefetch_for_serializer(self):
        """
        Optimized prefetching for a QuerySet to be consumed by the
        `CodebaseResourceSerializer`.
        Only the fields required by the serializer are fetched on the relations.
        """
        return self.prefetch_related(
            Prefetch(
                "discovered_packages",
                queryset=DiscoveredPackage.objects.only(
                    "package_uid", "uuid", *PURL_FIELDS
                ),
            ),
        )

    def status(self, status=None):
        if status:
            return self.filter(status=status)
        return self.filter(~Q(status=""))

    def no_status(self, status=None):
        """
        Filter for CodebaseResources without a status.

        If `status` is provided, then we filter for CodebaseResources whose
        status is not equal to `status`.
        """
        if status:
            return self.filter(~Q(status=status))
        return self.filter(status="")

    def empty(self):
        return self.filter(Q(size__isnull=True) | Q(size=0))

    def not_empty(self):
        return self.filter(size__gt=0)

    def in_package(self):
        return self.filter(discovered_packages__isnull=False).distinct()

    def not_in_package(self):
        return self.filter(discovered_packages__isnull=True)

    def files(self):
        return self.filter(type=self.model.Type.FILE)

    def directories(self):
        return self.filter(type=self.model.Type.DIRECTORY)

    def symlinks(self):
        return self.filter(type=self.model.Type.SYMLINK)

    def archives(self):
        return self.filter(is_archive=True)

    def without_symlinks(self):
        return self.filter(~Q(type=self.model.Type.SYMLINK))

    def has_license_detections(self):
        return self.filter(~Q(license_detections=[]))

    def has_no_license_detections(self):
        return self.filter(license_detections=[])

    def has_package_data(self):
        return self.filter(~Q(package_data=[]))

    def has_license_expression(self):
        return self.filter(~Q(detected_license_expression=""))

    def unknown_license(self):
        return self.filter(detected_license_expression__icontains="unknown")

    def from_codebase(self):
        """Resources in from/ directory"""
        return self.filter(tag="from")

    def to_codebase(self):
        """Resources in to/ directory"""
        return self.filter(tag="to")

    def has_relation(self):
        """Resources assigned to at least one CodebaseRelation"""
        return self.filter(Q(related_from__isnull=False) | Q(related_to__isnull=False))

    def has_many_relation(self):
        """Resources assigned to two or more CodebaseRelation"""
        return self.annotate(
            relation_count=Count("related_from") + Count("related_to")
        ).filter(relation_count__gte=2)

    def has_no_relation(self):
        """Resources not part of any CodebaseRelation"""
        return self.filter(related_from__isnull=True, related_to__isnull=True)

    def has_value(self, field_name):
        """Resources that have a value for provided `field_name`."""
        return self.filter(~Q((f"{field_name}__in", EMPTY_VALUES)))

    def path_pattern(self, pattern):
        """Resources with a path that match the provided glob ``pattern``."""
        return self.filter(path__regex=convert_glob_to_django_regex(pattern))

    def has_directory_content_fingerprint(self):
        """
        Resources that have the key `directory_content` set in the `extra_data`
        field and `directory_content` is not part of `IGNORED_DIRECTORY_FINGERPRINTS`.
        """
        return self.filter(
            ~Q(extra_data__directory_content="")
            and ~Q(extra_data__directory_content__in=IGNORED_DIRECTORY_FINGERPRINTS)
        )

    def elfs(self):
        """
        Resources that are ``files`` and their filetype starts with "ELF" and
        contains any of these "executable", "relocatable", "shared object".
        Keep sync with the content type implementation at ``typecode.contenttype``.
        """
        return (
            self.files()
            .filter(
                file_type__istartswith="ELF",
            )
            .filter(
                Q(file_type__icontains="executable")
                | Q(file_type__icontains="relocatable")
                | Q(file_type__icontains="shared object")
            )
        )


class ScanFieldsModelMixin(models.Model):
    """Fields returned by the ScanCode-toolkit scans."""

    detected_license_expression = models.TextField(
        blank=True,
        help_text=_(
            "The license expression summarizing the license info for this resource, "
            "combined from all the license detections"
        ),
    )
    detected_license_expression_spdx = models.TextField(
        blank=True,
        help_text=_(
            "The detected license expression for this file, with SPDX license keys"
        ),
    )
    license_detections = models.JSONField(
        blank=True,
        default=list,
        help_text=_("List of license detection details."),
    )
    license_clues = models.JSONField(
        blank=True,
        default=list,
        help_text=_(
            "List of license matches that are not proper detections and potentially "
            "just clues to licenses or likely false positives. Those are not included "
            "in computing the detected license expression for the resource."
        ),
    )
    percentage_of_license_text = models.FloatField(
        blank=True,
        null=True,
        help_text=_("Percentage of file words detected as license text or notice."),
    )
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

    def set_scan_results(self, scan_results, status=None):
        """
        Set the values of the current instance's scan-related fields using
        ``scan_results``.

        This instance status can be updated along the scan results by providing the
        optional ``status`` argument.
        """
        updated_fields = []
        for field_name, value in scan_results.items():
            if value and field_name in self.scan_fields():
                setattr(self, field_name, value)
                updated_fields.append(field_name)

        if status:
            self.status = status
            updated_fields.append("status")

        if updated_fields:
            self.save(update_fields=updated_fields)

    def copy_scan_results(self, from_instance):
        """
        Copy the scan-related fields values from ``from_instance`` to the current
        instance.
        """
        updated_fields = []
        for field_name in self.scan_fields():
            value_from_instance = getattr(from_instance, field_name)
            setattr(self, field_name, value_from_instance)
            updated_fields.append(field_name)

        if updated_fields:
            self.save(update_fields=updated_fields)


class ComplianceAlertMixin(models.Model):
    """
    Include the ``compliance_alert`` field and related code to compute its value.
    Add the db `indexes` in Meta of the concrete model:

    class Meta:
        indexes = [
            models.Index(fields=["compliance_alert"]),
        ]
    """

    license_expression_field = None

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
            "Indicates how the license expression complies with provided policies."
        ),
    )

    class Meta:
        abstract = True

    @classmethod
    def from_db(cls, db, field_names, values):
        """
        Store the ``license_expression_field`` on loading this instance from the
        database value.
        The cached value is then used to detect changes on `save()`.
        """
        new = super().from_db(db, field_names, values)

        if cls.license_expression_field in field_names:
            field_index = field_names.index(cls.license_expression_field)
            new._loaded_license_expression = values[field_index]

        return new

    def save(self, codebase=None, *args, **kwargs):
        """
        Injects policies, if the feature is enabled, when the
        ``license_expression_field`` field value has changed.

        `codebase` is not used in this context but required for compatibility
        with the commoncode.resource.Codebase class API.
        """
        if scanpipe_app.policies_enabled:
            loaded_license_expression = getattr(self, "_loaded_license_expression", "")
            license_expression = getattr(self, self.license_expression_field, "")
            if license_expression != loaded_license_expression:
                self.compliance_alert = self.compute_compliance_alert()
                if "update_fields" in kwargs:
                    kwargs["update_fields"].append("compliance_alert")

        super().save(*args, **kwargs)

    def compute_compliance_alert(self):
        """Compute and return the compliance_alert value from the licenses policies."""
        license_expression = getattr(self, self.license_expression_field, "")
        if not license_expression:
            return ""

        alerts = []
        policy_index = scanpipe_app.license_policies_index

        licensing = get_licensing()
        parsed = licensing.parse(license_expression, simple=True)
        license_keys = licensing.license_keys(parsed)

        for license_key in license_keys:
            if policy := policy_index.get(license_key):
                alerts.append(policy.get("compliance_alert") or self.Compliance.OK)
            else:
                alerts.append(self.Compliance.MISSING)

        compliance_ordered_by_severity = [
            self.Compliance.ERROR,
            self.Compliance.WARNING,
            self.Compliance.MISSING,
        ]

        for compliance_severity in compliance_ordered_by_severity:
            if compliance_severity in alerts:
                return compliance_severity

        return self.Compliance.OK


class CodebaseResource(
    ProjectRelatedModel,
    ScanFieldsModelMixin,
    ExtraDataFieldMixin,
    SaveProjectMessageMixin,
    UpdateFromDataMixin,
    HashFieldsMixin,
    ComplianceAlertMixin,
    models.Model,
):
    """
    A project Codebase Resources are records of its code files and directories.
    Each record is identified by its path under the project workspace.

    These model fields should be kept in line with `commoncode.resource.Resource`.
    """

    license_expression_field = "detected_license_expression"

    path = models.CharField(
        max_length=2000,
        help_text=_(
            "The full path value of a resource (file or directory) in the "
            "archive it is from."
        ),
    )
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
    size = models.BigIntegerField(
        blank=True,
        null=True,
        help_text=_("Size in bytes."),
    )
    tag = models.CharField(
        blank=True,
        max_length=50,
    )

    class Type(models.TextChoices):
        """List of CodebaseResource types."""

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
    name = models.CharField(
        max_length=255,
        blank=True,
        help_text=_("File or directory name of this resource with its extension."),
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
    is_binary = models.BooleanField(default=False)
    is_text = models.BooleanField(default=False)
    is_archive = models.BooleanField(default=False)
    is_key_file = models.BooleanField(default=False)
    is_media = models.BooleanField(default=False)
    package_data = models.JSONField(
        default=list,
        blank=True,
        help_text=_("List of Package data detected from this CodebaseResource"),
    )

    objects = CodebaseResourceQuerySet.as_manager()

    class Meta:
        indexes = [
            models.Index(fields=["path"]),
            models.Index(fields=["name"]),
            models.Index(fields=["extension"]),
            models.Index(fields=["status"]),
            models.Index(fields=["type"]),
            models.Index(fields=["size"]),
            models.Index(fields=["programming_language"]),
            models.Index(fields=["mime_type"]),
            models.Index(fields=["tag"]),
            models.Index(fields=["sha1"]),
            models.Index(fields=["detected_license_expression"]),
            models.Index(fields=["compliance_alert"]),
            models.Index(fields=["is_binary"]),
            models.Index(fields=["is_text"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "path"],
                name="%(app_label)s_%(class)s_unique_path_within_project",
            )
        ]
        ordering = ("project", "path")

    def __str__(self):
        return self.path

    @property
    def location_path(self):
        """Return the location of the resource as a Path instance."""
        # strip the leading / to allow joining this with the codebase_path
        path = Path(str(self.path).strip("/"))
        return self.project.codebase_path / path

    @property
    def name_without_extension(self):
        """Return the name of the resource without it's extension."""
        if self.extension:
            return self.name.rpartition(self.extension)[0]
        return self.name

    @property
    def location(self):
        """Return the location of the resource as a string."""
        return str(self.location_path)

    @property
    def is_file(self):
        """Return True, if the resource is a file."""
        return self.type == self.Type.FILE

    @property
    def is_dir(self):
        """Return True, if the resource is a directory."""
        return self.type == self.Type.DIRECTORY

    @property
    def is_symlink(self):
        """Return True, if the resource is a symlink."""
        return self.type == self.Type.SYMLINK

    def get_path_segments_with_subpath(self):
        """
        Return a list of path segment name along its subpath for this resource.

        Such as::

            [
                ('root', 'root'),
                ('subpath', 'root/subpath'),
                ('file.txt', 'root/subpath/file.txt'),
            ]
        """
        current_path = ""
        part_and_subpath = []

        for segment in Path(self.path).parts:
            if part_and_subpath:
                current_path += "/"
            current_path += segment

            if EXTRACT_SUFFIX in segment:
                is_extract = True
                base_segment = segment[: -len(EXTRACT_SUFFIX)]
                base_current_path = current_path[: -len(EXTRACT_SUFFIX)]
                part_and_subpath.append((base_segment, base_current_path, is_extract))
            else:
                is_extract = False
                part_and_subpath.append((segment, current_path, is_extract))

        return part_and_subpath

    def parent_path(self):
        """Return the parent path for this CodebaseResource or None."""
        return parent_directory(self.path, with_trail=False)

    def has_parent(self):
        """
        Return True if this CodebaseResource has a parent CodebaseResource or
        False otherwise.
        """
        parent_path = self.parent_path()
        if not parent_path:
            return False
        if self.project.codebaseresources.filter(path=parent_path).exists():
            return True
        return False

    def parent(self, codebase=None):
        """
        Return the parent CodebaseResource object for this CodebaseResource or
        None.

        `codebase` is not used in this context but required for compatibility
        with the commoncode.resource.Codebase class API.
        """
        parent_path = self.parent_path()
        return parent_path and self.project.codebaseresources.get(path=parent_path)

    def siblings(self, codebase=None):
        """
        Return a sequence of sibling Resource objects for this Resource
        or an empty sequence.

        `codebase` is not used in this context but required for compatibility
        with the commoncode.resource.Codebase class API.
        """
        if self.has_parent():
            return self.parent(codebase).children(codebase)
        return []

    def descendants(self):
        """
        Return a QuerySet of descendant CodebaseResource objects using a
        database query on the current CodebaseResource `path`.
        The current CodebaseResource is not included.
        """
        return self.project.codebaseresources.filter(path__startswith=f"{self.path}/")

    def children(self, codebase=None):
        """
        Return a QuerySet of direct children CodebaseResource objects using a
        database query on the current CodebaseResource `path`.

        Paths are returned in lower-cased sorted path order to reflect the
        behavior of the `commoncode.resource.Resource.children()`
        https://github.com/nexB/commoncode/blob/main/src/commoncode/resource.py

        `codebase` is not used in this context but required for compatibility
        with the commoncode.resource.VirtualCodebase class API.
        """
        exactly_one_sub_directory = "[^/]+$"
        escaped_path = re.escape(self.path)
        children_regex = rf"^{escaped_path}/{exactly_one_sub_directory}"
        return (
            self.descendants()
            .filter(path__regex=children_regex)
            .order_by(Lower("path"))
        )

    def walk(self, topdown=True):
        """
        Return all descendant Resources of the current Resource; does not include self.

        Traverses the tree top-down, depth-first if `topdown` is True; otherwise
        traverses the tree bottom-up.
        """
        for child in self.children().iterator():
            if topdown:
                yield child
            for subchild in child.walk(topdown=topdown):
                yield subchild
            if not topdown:
                yield child

    def get_absolute_url(self):
        return reverse("resource_detail", args=[self.project.slug, self.path])

    def get_raw_url(self):
        """Return the URL to access the RAW content of the resource."""
        return reverse("resource_raw", args=[self.project.slug, self.path])

    @property
    def file_content(self):
        """
        Return the content of the current Resource file using TextCode utilities
        for optimal compatibility.
        """
        from textcode.analysis import numbered_text_lines
        from typecode import get_type

        # When reading a map file, Textcode only provides the content inside
        # `sourcesContent`, which can be misleading during any kind of review.
        # This workaround ensures that the entire content of map files is displayed.
        file_type = get_type(self.location)
        if file_type.is_js_map:
            with open(self.location, "r") as file:
                content = json.load(file)

            return json.dumps(content, indent=2)

        numbered_lines = numbered_text_lines(self.location)
        numbered_lines = self._regroup_numbered_lines(numbered_lines)

        # ScanCode-toolkit is not providing the "\n" suffix when reading binary files.
        # The following is a workaround until the issue is fixed in the toolkit.
        lines = (
            line if line.endswith("\n") else line + "\n" for _, line in numbered_lines
        )

        return "".join(lines)

    @staticmethod
    def _regroup_numbered_lines(numbered_lines):
        """
        Yield (line number, text) given an iterator of (line number, line) where
        all text for the same line number is grouped and returned as a single text.

        This is a workaround ScanCode-toolkit breaking down long lines and creating an
        artificially higher number of lines, see:
        https://github.com/nexB/scancode.io/issues/292#issuecomment-901766139
        """
        for line_number, lines_group in groupby(numbered_lines, key=itemgetter(0)):
            yield line_number, "".join(line for _, line in lines_group)

    @classmethod
    def create_from_data(cls, project, resource_data):
        """
        Create and returns a DiscoveredPackage for a `project` from the `package_data`.
        If one of the values of the required fields is not available, a "ProjectMessage"
        is created instead of a new DiscoveredPackage instance.
        """
        resource_data = resource_data.copy()

        cleaned_data = {
            field_name: value
            for field_name, value in resource_data.items()
            if field_name in cls.model_fields() and value not in EMPTY_VALUES
        }

        return cls.objects.create(project=project, **cleaned_data)

    def add_package(self, discovered_package):
        """Assign the `discovered_package` to this `codebase_resource` instance."""
        self.discovered_packages.add(discovered_package)

    def create_and_add_package(self, package_data):
        """
        Create a DiscoveredPackage instance using the `package_data` and assigns
        it to the current CodebaseResource instance.

        Errors that may happen during the DiscoveredPackage creation are capture
        at this level, rather that in the DiscoveredPackage.create_from_data level,
        so resource data can be injected in the ProjectMessage record.
        """
        try:
            package = DiscoveredPackage.create_from_data(self.project, package_data)
        except Exception as exception:
            self.project.add_warning(
                model=DiscoveredPackage,
                details=package_data,
                exception=exception,
                resource=self,
            )
        else:
            self.add_package(package)
            return package

    @property
    def for_packages(self):
        """Return the list of all discovered packages associated to this resource."""
        return [
            package.package_uid or str(package)
            for package in self.discovered_packages.all()
        ]

    @property
    def spdx_id(self):
        return f"SPDXRef-scancodeio-{self._meta.model_name}-{self.id}"

    def get_spdx_types(self):
        spdx_types = []

        if self.is_binary:
            spdx_types.append("BINARY")
        if self.is_text:
            spdx_types.append("TEXT")
        if self.is_archive:
            spdx_types.append("ARCHIVE")

        return spdx_types

    def as_spdx(self):
        """Return this CodebaseResource as an SPDX Package entry."""
        from scanpipe.pipes import spdx

        copyrights = [copyright["copyright"] for copyright in self.copyrights]
        holders = [holder["holder"] for holder in self.holders]
        authors = [author["author"] for author in self.authors]

        return spdx.File(
            spdx_id=self.spdx_id,
            name=f"./{self.path}",
            checksums=[spdx.Checksum(algorithm="sha1", value=self.sha1)],
            license_concluded=self.detected_license_expression_spdx,
            copyright_text=", ".join(copyrights),
            contributors=list(set(holders + authors)),
            types=self.get_spdx_types(),
        )


class CodebaseRelation(
    UUIDPKModel,
    ProjectRelatedModel,
    ExtraDataFieldMixin,
    models.Model,
):
    """Relation between two CodebaseResource."""

    from_resource = models.ForeignKey(
        CodebaseResource,
        related_name="related_to",
        on_delete=models.CASCADE,
        editable=False,
    )
    to_resource = models.ForeignKey(
        CodebaseResource,
        related_name="related_from",
        on_delete=models.CASCADE,
        editable=False,
    )
    map_type = models.CharField(
        max_length=30,
    )

    class Meta:
        ordering = ["from_resource__path", "to_resource__path"]
        indexes = [
            models.Index(fields=["map_type"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["from_resource", "to_resource", "map_type"],
                name="%(app_label)s_%(class)s_unique_relation",
            ),
        ]

    def __str__(self):
        return f"{self.from_resource.pk} > {self.to_resource.pk} using {self.map_type}"

    @property
    def status(self):
        return self.to_resource.status

    @property
    def score(self):
        score = self.extra_data.get("path_score", "")
        if diff_ratio := self.extra_data.get("diff_ratio", ""):
            score += f" diff_ratio: {diff_ratio}"
        return score


class VulnerabilityMixin(models.Model):
    """Add the vulnerability related fields and methods."""

    affected_by_vulnerabilities = models.JSONField(blank=True, default=list)

    @property
    def is_vulnerable(self):
        """Returns True if this instance is affected by vulnerabilities."""
        return bool(self.affected_by_vulnerabilities)

    class Meta:
        abstract = True


class VulnerabilityQuerySetMixin:
    def vulnerable(self):
        return self.filter(~Q(affected_by_vulnerabilities__in=EMPTY_VALUES))


class DiscoveredPackageQuerySet(
    VulnerabilityQuerySetMixin, PackageURLQuerySetMixin, ProjectRelatedQuerySet
):
    def order_by_purl(self):
        """Order by Package URL fields."""
        return self.order_by("type", "namespace", "name", "version")

    def with_resources_count(self):
        count_subquery = Subquery(
            self.filter(pk=OuterRef("pk"))
            .annotate(resources_count=Count("codebase_resources"))
            .values("resources_count")[:1],
            output_field=IntegerField(),
        )
        return self.annotate(resources_count=count_subquery)

    def has_license_detections(self):
        return self.filter(~Q(license_detections=[]) | ~Q(other_license_detections=[]))

    def has_no_license_detections(self):
        return self.filter(Q(license_detections=[]) & Q(other_license_detections=[]))


class AbstractPackage(models.Model):
    """These fields should be kept in line with `packagedcode.models.PackageData`."""

    filename = models.CharField(
        max_length=255,
        blank=True,
        help_text=_(
            "File name of a Resource sometimes part of the URI proper"
            "and sometimes only available through an HTTP header."
        ),
    )
    primary_language = models.CharField(
        max_length=50,
        blank=True,
        help_text=_("Primary programming language."),
    )
    description = models.TextField(
        blank=True,
        help_text=_(
            "Description for this package. "
            "By convention the first line should be a summary when available."
        ),
    )
    release_date = models.DateField(
        blank=True,
        null=True,
        help_text=_(
            "The date that the package file was created, or when "
            "it was posted to its original download source."
        ),
    )
    homepage_url = models.CharField(
        _("Homepage URL"),
        max_length=1024,
        blank=True,
        help_text=_("URL to the homepage for this package."),
    )
    download_url = models.CharField(
        _("Download URL"),
        max_length=2048,
        blank=True,
        help_text=_("A direct download URL."),
    )
    size = models.BigIntegerField(
        blank=True,
        null=True,
        help_text=_("Size in bytes."),
    )
    bug_tracking_url = models.CharField(
        _("Bug tracking URL"),
        max_length=1024,
        blank=True,
        help_text=_("URL to the issue or bug tracker for this package."),
    )
    code_view_url = models.CharField(
        _("Code view URL"),
        max_length=1024,
        blank=True,
        help_text=_("a URL where the code can be browsed online."),
    )
    vcs_url = models.CharField(
        _("VCS URL"),
        max_length=1024,
        blank=True,
        help_text=_(
            "A URL to the VCS repository in the SPDX form of: "
            '"git", "svn", "hg", "bzr", "cvs", '
            "https://github.com/nexb/scancode-toolkit.git@405aaa4b3 "
            'See SPDX specification "Package Download Location" '
            "at https://spdx.org/spdx-specification-21-web-version#h.49x2ik5"
        ),
    )
    repository_homepage_url = models.CharField(
        _("Repository homepage URL"),
        max_length=1024,
        blank=True,
        help_text=_(
            "URL to the page for this package in its package repository. "
            "This is typically different from the package homepage URL proper."
        ),
    )
    repository_download_url = models.CharField(
        _("Repository download URL"),
        max_length=1024,
        blank=True,
        help_text=_(
            "Download URL to download the actual archive of code of this "
            "package in its package repository. "
            "This may be different from the actual download URL."
        ),
    )
    api_data_url = models.CharField(
        _("API data URL"),
        max_length=1024,
        blank=True,
        help_text=_(
            "API URL to obtain structured data for this package such as the "
            "URL to a JSON or XML api its package repository."
        ),
    )
    copyright = models.TextField(
        blank=True,
        help_text=_("Copyright statements for this package. Typically one per line."),
    )
    holder = models.TextField(
        blank=True,
        help_text=_("Holders for this package. Typically one per line."),
    )
    declared_license_expression = models.TextField(
        blank=True,
        help_text=_(
            "The license expression for this package typically derived "
            "from its extracted_license_statement or from some other type-specific "
            "routine or convention."
        ),
    )
    declared_license_expression_spdx = models.TextField(
        blank=True,
        help_text=_(
            "The SPDX license expression for this package converted "
            "from its declared_license_expression."
        ),
    )
    license_detections = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            "A list of LicenseDetection mappings typically derived "
            "from its extracted_license_statement or from some other type-specific "
            "routine or convention."
        ),
    )
    other_license_expression = models.TextField(
        blank=True,
        help_text=_(
            "The license expression for this package which is different from the "
            "declared_license_expression, (i.e. not the primary license) "
            "routine or convention."
        ),
    )
    other_license_expression_spdx = models.TextField(
        blank=True,
        help_text=_(
            "The other SPDX license expression for this package converted "
            "from its other_license_expression."
        ),
    )
    other_license_detections = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            "A list of LicenseDetection mappings which is different from the "
            "declared_license_expression, (i.e. not the primary license) "
            "These are detections for the detection for the license expressions "
            "in other_license_expression. "
        ),
    )
    extracted_license_statement = models.TextField(
        blank=True,
        help_text=_(
            "The license statement mention, tag or text as found in a "
            "package manifest and extracted. This can be a string, a list or dict of "
            "strings possibly nested, as found originally in the manifest."
        ),
    )
    notice_text = models.TextField(
        blank=True,
        help_text=_("A notice text for this package."),
    )
    datasource_ids = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            "The identifiers for the datafile handlers used to obtain this package."
        ),
    )
    datafile_paths = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            "A list of Resource paths for package datafiles which were "
            "used to assemble this pacakage."
        ),
    )
    file_references = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            "List of file paths and details for files referenced in a package "
            "manifest. These may not actually exist on the filesystem. "
            "The exact semantics and base of these paths is specific to a "
            "package type or datafile format."
        ),
    )
    parties = models.JSONField(
        default=list,
        blank=True,
        help_text=_("A list of parties such as a person, project or organization."),
    )

    class Meta:
        abstract = True


class DiscoveredPackage(
    ProjectRelatedModel,
    ExtraDataFieldMixin,
    SaveProjectMessageMixin,
    UpdateFromDataMixin,
    HashFieldsMixin,
    PackageURLMixin,
    VulnerabilityMixin,
    ComplianceAlertMixin,
    AbstractPackage,
):
    """
    A project's Discovered Packages are records of the system and application packages
    discovered in the code under analysis.
    Each record is identified by its Package URL.
    Package URL is a fundamental effort to create informative identifiers for software
    packages, such as Debian, RPM, npm, Maven, or PyPI packages.
    See https://github.com/package-url for more details.
    """

    license_expression_field = "declared_license_expression"

    uuid = models.UUIDField(
        verbose_name=_("UUID"), default=uuid.uuid4, unique=True, editable=False
    )
    codebase_resources = models.ManyToManyField(
        "CodebaseResource", related_name="discovered_packages"
    )
    missing_resources = models.JSONField(default=list, blank=True)
    modified_resources = models.JSONField(default=list, blank=True)
    package_uid = models.CharField(
        max_length=1024,
        blank=True,
        help_text=_("Unique identifier for this package."),
    )
    keywords = models.JSONField(default=list, blank=True)
    source_packages = models.JSONField(default=list, blank=True)
    tag = models.CharField(blank=True, max_length=50)

    objects = DiscoveredPackageQuerySet.as_manager()

    class Meta:
        ordering = ["uuid"]
        indexes = [
            models.Index(fields=["type"]),
            models.Index(fields=["namespace"]),
            models.Index(fields=["name"]),
            models.Index(fields=["version"]),
            models.Index(fields=["filename"]),
            models.Index(fields=["package_uid"]),
            models.Index(fields=["primary_language"]),
            models.Index(fields=["declared_license_expression"]),
            models.Index(fields=["other_license_expression"]),
            models.Index(fields=["size"]),
            models.Index(fields=["md5"]),
            models.Index(fields=["sha1"]),
            models.Index(fields=["sha256"]),
            models.Index(fields=["sha512"]),
            models.Index(fields=["compliance_alert"]),
            models.Index(fields=["tag"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "package_uid"],
                condition=~Q(package_uid=""),
                name="%(app_label)s_%(class)s_unique_package_uid_within_project",
            ),
        ]

    def __str__(self):
        return self.package_url or str(self.uuid)

    def get_absolute_url(self):
        return reverse("package_detail", args=[self.project.slug, self.uuid])

    @cached_property
    def resources(self):
        """Return the assigned codebase_resources QuerySet as a list."""
        return list(self.codebase_resources.all())

    @property
    def purl(self):
        """Return the Package URL."""
        return self.package_url

    @classmethod
    def extract_purl_data(cls, package_data):
        purl_data = {}

        for field_name in PURL_FIELDS:
            value = package_data.get(field_name)
            if field_name == "qualifiers":
                value = normalize_qualifiers(value, encode=True)
            purl_data[field_name] = value or ""

        return purl_data

    @classmethod
    def create_from_data(cls, project, package_data):
        """
        Create and returns a DiscoveredPackage for a `project` from the `package_data`.
        If one of the values of the required fields is not available, a "ProjectMessage"
        is created instead of a new DiscoveredPackage instance.
        """
        package_data = package_data.copy()
        required_fields = ["type", "name"]
        missing_values = [
            field_name
            for field_name in required_fields
            if not package_data.get(field_name)
        ]

        if missing_values:
            message = (
                f"No values for the following required fields: "
                f"{', '.join(missing_values)}"
            )

            project.add_warning(description=message, model=cls, details=package_data)
            return

        qualifiers = package_data.get("qualifiers")
        if qualifiers:
            package_data["qualifiers"] = normalize_qualifiers(qualifiers, encode=True)

        cleaned_data = {
            field_name: value
            for field_name, value in package_data.items()
            if field_name in cls.model_fields() and value not in EMPTY_VALUES
        }

        discovered_package = cls(project=project, **cleaned_data)
        # Using save_error=False to not capture potential errors at this level but
        # rather in the CodebaseResource.create_and_add_package method so resource data
        # can be injected in the ProjectMessage record.
        discovered_package.save(save_error=False, capture_exception=False)
        return discovered_package

    def add_resources(self, codebase_resources):
        """Assign the `codebase_resources` to this `discovered_package` instance."""
        self.codebase_resources.add(*codebase_resources)

    @classmethod
    def clean_data(cls, data):
        """
        Return the `data` dict keeping only entries for fields available in the
        model.
        """
        return {
            field_name: value
            for field_name, value in data.items()
            if field_name in cls.model_fields()
        }

    @property
    def spdx_id(self):
        return f"SPDXRef-scancodeio-{self._meta.model_name}-{self.uuid}"

    def get_declared_license_expression(self):
        """
        Return this package license expression.

        Use `declared_license_expression` when available or compute the expression
        from `declared_license_expression_spdx`.
        """
        from scanpipe.pipes.resolve import convert_spdx_expression

        if self.declared_license_expression:
            return self.declared_license_expression
        elif self.declared_license_expression_spdx:
            return convert_spdx_expression(self.declared_license_expression_spdx)
        return ""

    def get_declared_license_expression_spdx(self):
        """
        Return this package license expression using SPDX keys.

        Use `declared_license_expression_spdx` when available or compute the expression
        from `declared_license_expression`.
        """
        if self.declared_license_expression_spdx:
            return self.declared_license_expression_spdx
        elif self.declared_license_expression:
            return build_spdx_license_expression(self.declared_license_expression)
        return ""

    def as_spdx(self):
        """Return this DiscoveredPackage as an SPDX Package entry."""
        from scanpipe.pipes import spdx

        checksums = [
            spdx.Checksum(algorithm=algorithm, value=checksum_value)
            for algorithm in ["sha1", "md5"]
            if (checksum_value := getattr(self, algorithm))
        ]

        attribution_texts = []
        if self.notice_text:
            attribution_texts.append(self.notice_text)

        external_refs = []

        if package_url := self.package_url:
            external_refs.append(
                spdx.ExternalRef(
                    category="PACKAGE-MANAGER",
                    type="purl",
                    locator=package_url,
                )
            )

        return spdx.Package(
            name=self.name or self.filename,
            spdx_id=self.spdx_id,
            download_location=self.download_url,
            license_declared=self.get_declared_license_expression_spdx(),
            license_concluded=self.get_declared_license_expression_spdx(),
            copyright_text=self.copyright,
            version=self.version,
            homepage=self.homepage_url,
            filename=self.filename,
            description=self.description,
            release_date=str(self.release_date) if self.release_date else "",
            attribution_texts=attribution_texts,
            checksums=checksums,
            external_refs=external_refs,
        )

    def as_cyclonedx(self):
        """Return this DiscoveredPackage as an CycloneDX Component entry."""
        licenses = []
        if expression_spdx := self.get_declared_license_expression_spdx():
            # Using the LicenseExpression directly as the make_with_expression method
            # does not support the "LicenseRef-" keys.
            licenses = [cyclonedx_license.LicenseExpression(value=expression_spdx)]

        hash_fields = {
            "md5": cyclonedx_model.HashAlgorithm.MD5,
            "sha1": cyclonedx_model.HashAlgorithm.SHA_1,
            "sha256": cyclonedx_model.HashAlgorithm.SHA_256,
            "sha512": cyclonedx_model.HashAlgorithm.SHA_512,
        }
        hashes = [
            cyclonedx_model.HashType(alg=algorithm, content=hash_value)
            for field_name, algorithm in hash_fields.items()
            if (hash_value := getattr(self, field_name))
        ]

        # Those fields are not supported natively by CycloneDX but are required to
        # load the BOM without major data loss.
        # See https://github.com/nexB/aboutcode-cyclonedx-taxonomy
        property_prefix = "aboutcode"
        property_fields = [
            "filename",
            "primary_language",
            "download_url",
            "homepage_url",
            "notice_text",
        ]
        properties = [
            cyclonedx_model.Property(
                name=f"{property_prefix}:{field_name}", value=value
            )
            for field_name in property_fields
            if (value := getattr(self, field_name)) not in EMPTY_VALUES
        ]

        reference_type = cyclonedx_model.ExternalReferenceType
        url_field_to_cdx_type = {
            "api_data_url": reference_type.BOM,
            "bug_tracking_url": reference_type.ISSUE_TRACKER,
            "code_view_url": reference_type.OTHER,
            "download_url": reference_type.DISTRIBUTION,
            "homepage_url": reference_type.WEBSITE,
            "repository_download_url": reference_type.DISTRIBUTION,
            "repository_homepage_url": reference_type.WEBSITE,
            "vcs_url": reference_type.VCS,
        }
        external_references = [
            cyclonedx_model.ExternalReference(type=reference_type, url=url)
            for field_name, reference_type in url_field_to_cdx_type.items()
            if (url := getattr(self, field_name)) and field_name not in property_fields
        ]

        # Always use the package_uid when available to ensure having unique
        # package_url in the BOM when several instances of the same DiscoveredPackage
        # (i.e. same purl) are present in the project.
        try:
            package_url = PackageURL.from_string(self.package_uid)
        except ValueError:
            package_url = self.get_package_url()

        evidence = None
        if self.other_license_expression_spdx:
            evidence = cyclonedx_component.ComponentEvidence(
                licenses=[
                    cyclonedx_license.LicenseExpression(
                        value=self.other_license_expression_spdx
                    )
                ],
            )

        return cyclonedx_component.Component(
            name=self.name,
            version=self.version,
            bom_ref=str(package_url),
            purl=package_url,
            licenses=licenses,
            copyright=self.copyright,
            description=self.description,
            hashes=hashes,
            properties=properties,
            external_references=external_references,
            evidence=evidence,
        )


class DiscoveredDependencyQuerySet(
    PackageURLQuerySetMixin, VulnerabilityQuerySetMixin, ProjectRelatedQuerySet
):
    def prefetch_for_serializer(self):
        """
        Optimized prefetching for a QuerySet to be consumed by the
        `DiscoveredDependencySerializer`.
        Only the fields required by the serializer are fetched on the relations.
        """
        return self.prefetch_related(
            Prefetch(
                "for_package", queryset=DiscoveredPackage.objects.only("package_uid")
            ),
            Prefetch(
                "datafile_resource", queryset=CodebaseResource.objects.only("path")
            ),
        )


class DiscoveredDependency(
    ProjectRelatedModel,
    SaveProjectMessageMixin,
    UpdateFromDataMixin,
    VulnerabilityMixin,
    PackageURLMixin,
):
    """
    A project's Discovered Dependencies are records of the dependencies used by
    system and application packages discovered in the code under analysis.
    """

    # Overrides the `project` field from `ProjectRelatedModel` to set the proper
    # `related_name`.
    project = models.ForeignKey(
        Project,
        related_name="discovereddependencies",
        on_delete=models.CASCADE,
        editable=False,
    )
    dependency_uid = models.CharField(
        max_length=1024,
        help_text=_("The unique identifier of this dependency."),
    )
    for_package = models.ForeignKey(
        DiscoveredPackage,
        related_name="dependencies",
        on_delete=models.CASCADE,
        editable=False,
        blank=True,
        null=True,
    )
    datafile_resource = models.ForeignKey(
        CodebaseResource,
        related_name="dependencies",
        on_delete=models.CASCADE,
        editable=False,
        blank=True,
        null=True,
    )
    extracted_requirement = models.CharField(
        max_length=256,
        blank=True,
        help_text=_("The version requirements of this dependency."),
    )
    scope = models.CharField(
        max_length=64,
        blank=True,
        help_text=_("The scope of this dependency, how it is used in a project."),
    )
    datasource_id = models.CharField(
        max_length=64,
        blank=True,
        help_text=_(
            "The identifier for the datafile handler used to obtain this dependency."
        ),
    )
    is_runtime = models.BooleanField(default=False)
    is_optional = models.BooleanField(default=False)
    is_resolved = models.BooleanField(default=False)

    objects = DiscoveredDependencyQuerySet.as_manager()

    class Meta:
        verbose_name = "discovered dependency"
        verbose_name_plural = "discovered dependencies"
        ordering = [
            "-is_runtime",
            "-is_resolved",
            "is_optional",
            "dependency_uid",
            "for_package",
            "datafile_resource",
            "datasource_id",
        ]
        indexes = [
            models.Index(fields=["scope"]),
            models.Index(fields=["is_runtime"]),
            models.Index(fields=["is_optional"]),
            models.Index(fields=["is_resolved"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "dependency_uid"],
                condition=~Q(dependency_uid=""),
                name="%(app_label)s_%(class)s_unique_dependency_uid_within_project",
            ),
        ]

    def __str__(self):
        return self.dependency_uid

    def get_absolute_url(self):
        return reverse(
            "dependency_detail", args=[self.project.slug, self.dependency_uid]
        )

    @property
    def purl(self):
        return self.package_url

    @property
    def package_type(self):
        return self.type

    @cached_property
    def for_package_uid(self):
        if self.for_package:
            return self.for_package.package_uid

    @cached_property
    def datafile_path(self):
        if self.datafile_resource:
            return self.datafile_resource.path

    @classmethod
    def create_from_data(
        cls,
        project,
        dependency_data,
        for_package=None,
        datafile_resource=None,
        strip_datafile_path_root=False,
    ):
        """
        Create and returns a DiscoveredDependency for a `project` from the
        `dependency_data`.

        If `strip_datafile_path_root` is True, then `create_from_data()` will
        strip the root path segment from the `datafile_path` of
        `dependency_data` before looking up the corresponding CodebaseResource
        for `datafile_path`. This is used in the case where Dependency data is
        imported from a scancode-toolkit scan, where the root path segments are
        not stripped for `datafile_path`.
        """
        dependency_data = dependency_data.copy()
        required_fields = ["purl", "dependency_uid"]
        missing_values = [
            field_name
            for field_name in required_fields
            if not dependency_data.get(field_name)
        ]

        if missing_values:
            message = (
                f"No values for the following required fields: "
                f"{', '.join(missing_values)}"
            )

            project.add_warning(description=message, model=cls, details=dependency_data)
            return

        if not for_package:
            for_package_uid = dependency_data.get("for_package_uid")
            if for_package_uid:
                for_package = project.discoveredpackages.get(
                    package_uid=for_package_uid
                )

        if not datafile_resource:
            datafile_path = dependency_data.get("datafile_path")
            if datafile_path:
                if strip_datafile_path_root:
                    segments = datafile_path.split("/")
                    datafile_path = "/".join(segments[1:])
                datafile_resource = project.codebaseresources.get(path=datafile_path)

        # Set purl fields from `purl`
        purl = dependency_data.get("purl")
        purl_mapping = PackageURL.from_string(purl).to_dict()
        dependency_data.update(**purl_mapping)

        cleaned_data = {
            field_name: value
            for field_name, value in dependency_data.items()
            if field_name in cls.model_fields() and value not in EMPTY_VALUES
        }

        return cls.objects.create(
            project=project,
            for_package=for_package,
            datafile_resource=datafile_resource,
            **cleaned_data,
        )

    @property
    def spdx_id(self):
        return f"SPDXRef-scancodeio-{self._meta.model_name}-{self.dependency_uid}"

    def as_spdx(self):
        """Return this Dependency as an SPDX Package entry."""
        from scanpipe.pipes import spdx

        external_refs = []

        if package_url := self.package_url:
            external_refs.append(
                spdx.ExternalRef(
                    category="PACKAGE-MANAGER",
                    type="purl",
                    locator=package_url,
                )
            )

        return spdx.Package(
            name=self.name,
            spdx_id=self.spdx_id,
            version=self.version,
            external_refs=external_refs,
        )


class DiscoveredLicenseQuerySet(ProjectRelatedQuerySet):
    def order_by_count_and_expression(self):
        """Order by detection count and license expression (identifer) fields."""
        return self.order_by("-detection_count", "identifier")


class AbstractLicenseDetection(models.Model):
    """
    These fields should be kept in line with
    `licensedcode.detection.LicenseDetection`.
    """

    license_expression = models.TextField(
        blank=True,
        help_text=_(
            "A license expression string using the SPDX license expression"
            " syntax and ScanCode license keys, the effective license expression"
            " for this license detection."
        ),
    )

    license_expression_spdx = models.TextField(
        blank=True,
        help_text=_("SPDX license expression string with SPDX ids."),
    )

    matches = models.JSONField(
        _("Reference Matches"),
        default=list,
        blank=True,
        help_text=_("List of license matches combined in this detection."),
    )

    detection_log = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            "A list of detection DetectionRule explaining how "
            "this detection was created."
        ),
    )

    identifier = models.CharField(
        max_length=1024,
        blank=True,
        help_text=_(
            "An identifier unique for a license detection, containing the license "
            "expression and a UUID crafted from the match contents."
        ),
    )

    class Meta:
        abstract = True


class DiscoveredLicense(
    ProjectRelatedModel,
    SaveProjectMessageMixin,
    UpdateFromDataMixin,
    ComplianceAlertMixin,
    AbstractLicenseDetection,
):
    """
    A project's Discovered Licenses are the unique License Detection objects
    discovered in the code under analysis.

    """

    license_expression_field = "license_expression"

    # If this license was discovered in a extracted license statement
    # this is True, and False if this was discovered in a file.
    from_package = None

    detection_count = models.BigIntegerField(
        blank=True,
        null=True,
        help_text=_("Total number of this license detection discovered."),
    )

    file_regions = models.JSONField(
        _("Detection Locations"),
        default=list,
        blank=True,
        help_text=_(
            "A list of file regions with resource path, start and end line "
            "details for each place this license detection was discovered at. "
            "Also contains whether this license was discovered from a file or "
            "from package metadata."
        ),
    )

    objects = DiscoveredLicenseQuerySet.as_manager()

    class Meta:
        ordering = ["detection_count", "identifier"]
        indexes = [
            models.Index(fields=["identifier"]),
            models.Index(fields=["license_expression"]),
            models.Index(fields=["license_expression_spdx"]),
            models.Index(fields=["detection_count"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "identifier"],
                condition=~Q(identifier=""),
                name="%(app_label)s_%(class)s_unique_license_id_within_project",
            ),
        ]

    def __str__(self):
        return self.identifier

    @classmethod
    def create_from_data(cls, project, detection_data):
        """
        Create and returns a DiscoveredLicense for a `project` from the
        `detection_data`. If one of the values of the required fields is not
        available, a "ProjectMessage" is created instead of a new
        DiscoveredLicense instance.
        """
        detection_data = detection_data.copy()
        required_fields = ["license_expression", "identifier", "matches"]
        missing_values = [
            field_name
            for field_name in required_fields
            if not detection_data.get(field_name)
        ]

        if missing_values:
            message = (
                f"No values for the following required fields: "
                f"{', '.join(missing_values)}"
            )

            project.add_warning(
                description=message,
                model=cls,
                details=detection_data,
            )
            return

        cleaned_data = {
            field_name: value
            for field_name, value in detection_data.items()
            if field_name in cls.model_fields() and value not in EMPTY_VALUES
        }

        discovered_license = cls(project=project, **cleaned_data)
        # Using save_error=False to not capture potential errors at this level but
        # rather in the CodebaseResource.create_and_add_license_data method so
        # resource data can be injected in the ProjectMessage record.
        discovered_license.save(save_error=False, capture_exception=False)
        return discovered_license

    def update_with_file_region(self, file_region):
        """
        If the `file_region` is a new file region, include it in the
        `file_regions` list and increase the `detection_count` by 1.
        """
        file_region_data = file_region.to_dict()
        if file_region_data not in self.file_regions:
            self.file_regions.append(file_region_data)
            if not self.detection_count:
                self.detection_count = 1
            else:
                self.detection_count += 1
            self.save(update_fields=["detection_count", "file_regions"])


class WebhookSubscription(UUIDPKModel, ProjectRelatedModel):
    target_url = models.URLField(_("Target URL"), max_length=1024)
    created_date = models.DateTimeField(auto_now_add=True, editable=False)
    response_status_code = models.PositiveIntegerField(null=True, blank=True)
    response_text = models.TextField(blank=True)
    delivery_error = models.TextField(blank=True)

    def __str__(self):
        return str(self.uuid)

    def get_payload(self, pipeline_run):
        return {
            "project": {
                "uuid": self.project.uuid,
                "name": self.project.name,
                "input_sources": self.project.get_inputs_with_source(),
            },
            "run": {
                "uuid": pipeline_run.uuid,
                "pipeline_name": pipeline_run.pipeline_name,
                "status": pipeline_run.status,
                "scancodeio_version": pipeline_run.scancodeio_version,
            },
        }

    def deliver(self, pipeline_run):
        """Deliver this Webhook by sending a POST request to the `target_url`."""
        payload = self.get_payload(pipeline_run)

        logger.info(f"Sending Webhook uuid={self.uuid}.")
        try:
            response = requests.post(
                url=self.target_url,
                data=json.dumps(payload, cls=DjangoJSONEncoder),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
        except requests.exceptions.RequestException as exception:
            logger.info(exception)
            self.update(delivery_error=str(exception))
            return False

        self.update(
            response_status_code=response.status_code,
            response_text=response.text,
        )

        if self.success:
            logger.info(f"Webhook uuid={self.uuid} delivered and received.")
        else:
            logger.info(f"Webhook uuid={self.uuid} returned a {response.status_code}.")

        return True

    @property
    def delivered(self):
        return bool(self.response_status_code)

    @property
    def success(self):
        return self.response_status_code in (200, 201, 202)


@receiver(models.signals.post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    """Create an API key token on user creation, using the signal system."""
    if created:
        Token.objects.create(user_id=instance.pk)
