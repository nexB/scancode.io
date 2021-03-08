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

import hashlib
import json
import re
import shutil
import uuid
from collections import defaultdict
from contextlib import suppress
from pathlib import Path

from django.conf import settings
from django.core import validators
from django.core.mail import EmailMessage
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.template.defaultfilters import filesizeformat
from django.template.loader import render_to_string
from django.utils.translation import gettext_lazy as _

import requests

from scancodeio import WORKSPACE_LOCATION
from scanner.tasks import DOWNLOAD_SIZE_THRESHOLD
from scanner.tasks import download_and_scan
from scanpipe.models import AbstractTaskFieldsModel

generic_uri_validator = validators.RegexValidator(
    re.compile(r"^[\w+-_]+://[\S]+$"),
    message=_("Enter a valid URI."),
    code="invalid",
)


def load_json(file):
    with open(file) as opened_file:
        with suppress(json.JSONDecodeError):
            return json.load(opened_file)


def get_scan_work_directory(scan):
    """
    Return the work directory location for the provided `scan`.
    """
    uuid_str = str(scan.uuid)
    return f"{WORKSPACE_LOCATION}/scans/{uuid_str[0:2]}/{uuid_str}"


class ScanQuerySet(models.QuerySet):
    def small(self):
        return self.filter(size__lte=DOWNLOAD_SIZE_THRESHOLD)

    def large(self):
        return self.filter(size__gt=DOWNLOAD_SIZE_THRESHOLD)

    def not_started(self):
        return self.filter(task_start_date__isnull=True)

    def started(self):
        return self.filter(task_start_date__isnull=False, task_end_date__isnull=True)

    def completed(self):
        return self.filter(task_end_date__isnull=False)

    def succeed(self):
        return self.filter(task_exitcode=0)

    def failed(self):
        return self.filter(task_exitcode__gt=0)

    def scan_failed(self):
        return self.filter(task_exitcode__in=[1, 2])

    def task_failed(self):
        return self.filter(task_exitcode=3)

    def task_timeout(self):
        return self.filter(task_exitcode=4)

    def download_failed(self):
        return self.filter(task_exitcode=404)


class Scan(AbstractTaskFieldsModel, models.Model):
    uuid = models.UUIDField(
        verbose_name=_("UUID"),
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        db_index=True,
    )
    uri = models.CharField(
        verbose_name=_("URI"),
        max_length=2048,
        unique=True,
        db_index=True,
        validators=[generic_uri_validator],
    )
    output_file = models.FileField(max_length=350, null=True)
    scancode_version = models.CharField(
        max_length=50,
        db_index=True,
        blank=True,
    )
    filename = models.CharField(
        db_index=True,
        blank=True,
        null=True,
        max_length=255,  # 255 is the maximum on most filesystems
    )
    sha1 = models.CharField(
        verbose_name="SHA1",
        max_length=40,
        blank=True,
        null=True,
        db_index=True,
        help_text="SHA1 checksum hex-encoded, as in sha1sum.",
    )
    md5 = models.CharField(
        verbose_name="MD5",
        max_length=32,
        blank=True,
        null=True,
        db_index=True,
        help_text="MD5 checksum hex-encoded, as in md5sum.",
    )
    size = models.BigIntegerField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Size in bytes.",
    )
    created_date = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )
    created_by = models.UUIDField(
        null=True,
        blank=True,
        serialize=False,
    )
    summary = models.JSONField(
        default=dict,
        blank=True,
        help_text=_("Summary data extracted from the Scan results."),
    )

    objects = ScanQuerySet.as_manager()

    class Meta:
        ordering = ["-created_date"]

    def __str__(self):
        return self.uri

    def save(self, *args, **kwargs):
        self.setup_work_directory()
        super().save(*args, **kwargs)

    def setup_work_directory(self):
        """
        Create the work_directory structure, skip existing.
        """
        work_path = self.work_path
        if not work_path.exists():
            work_path.mkdir(parents=True, exist_ok=True)

    def delete(self, *args, **kwargs):
        """
        Remove the `self.output_path` directory from the filesystem
        after deleting the Scan object from the database.
        """
        deleted = super().delete(*args, **kwargs)

        output_path = self.output_path
        if output_path and output_path.exists():
            shutil.rmtree(output_path, ignore_errors=True)

        return deleted

    @property
    def status(self) -> str:
        if self.task_exitcode and self.task_exitcode > 0:
            if "Scanning done." in self.task_output:
                return "completed with issues"
            if self.task_exitcode == 404:
                return "download failed"
            return "scan failed"

        if not self.task_start_date:
            return "not started yet"

        if not self.task_end_date:
            return "in progress"

        return "completed"

    @property
    def filesize(self):
        if self.size:
            return f"{self.size} ({filesizeformat(self.size)})"

    @property
    def work_path(self):
        return Path(get_scan_work_directory(self))

    @property
    def output_path(self):
        """
        Return the Scan output directory as a `Path` instance.
        """
        if self.has_output_file:
            return Path(self.output_file.name).parent

    @property
    def has_output_file(self):
        """
        Return True if the output_file field is defined on the model and
        if the file path exists on the drive.
        """
        if self.output_file and Path(self.output_file.name).exists():
            return True
        return False

    @property
    def data(self):
        """
        Return the decoded Scan results data.
        """
        if not self.has_output_file:
            return

        return load_json(self.output_file.name)

    def get_summary_from_output(self):
        """
        Extract selected sections of the Scan results, such as the `summary`
        `license_clarity_score`, and `license_matches` related data.
        The `key_files` content is also collected and injected in the
        `summary` output.
        """
        scan_data = self.data

        if not scan_data:
            return

        summary = scan_data.get("summary")

        # Inject the `license_clarity_score` entry in the summary
        summary["license_clarity_score"] = scan_data.get("license_clarity_score")

        # Inject the generated `license_matches` in the summary
        summary["license_matches"] = self.get_license_matches_data()

        # Inject the `key_files` and their content in the summary
        key_files = []
        with suppress(FileNotFoundError, json.JSONDecodeError):
            with open(self.key_files_output_file) as f:
                key_files = json.load(f)
        summary["key_files"] = key_files

        if key_files:
            key_files_packages = []
            for key_file in key_files:
                key_files_packages.extend(key_file.get("packages", []))
            summary["key_files_packages"] = key_files_packages

        return summary

    def get_key_files_data(self):
        """
        Return the data for all the files flagged as `is_key_file` from the
        Scan results.
        `is_key_file` is True when a file is "top-level" file and either a
        legal, readme or manifest file.
        The results are also limited to readable text only.
        """
        if not self.data:
            return

        files = self.data.get("files", [])
        return [
            file for file in files if file.get("is_key_file") and file.get("is_text")
        ]

    @property
    def key_files_output_file(self):
        if self.output_file:
            return str(self.output_file).replace("/scan_", "/key_files_")

    def get_license_matches_data(self):
        """
        Return the license matches from the Scan results grouped in a dict by
        license key.
        """
        if not self.data:
            return

        license_matches = defaultdict(list)
        files = self.data.get("files", [])

        for file in files:
            path = file.get("path")
            licenses = file.get("licenses", [])
            file_cache = []

            for license in licenses:
                matched_rule = license.get("matched_rule", {})
                license_expression = matched_rule.get("license_expression")
                matched_text = license.get("matched_text")

                # Do not include duplicated matched_text for a given license_expression
                # within the same file
                cache_key = ":".join([license_expression, path, matched_text])
                cache_key = hashlib.md5(cache_key.encode()).hexdigest()
                if cache_key in file_cache:
                    continue

                file_cache.append(cache_key)
                license_matches[license_expression].append(
                    {
                        "path": path,
                        "matched_text": matched_text,
                    }
                )

        return dict(license_matches)

    def reset_values(self):
        self.output_file = None
        self.scancode_version = ""
        self.filename = ""
        self.sha1 = ""
        self.md5 = ""
        self.size = None
        self.task_id = None
        self.task_start_date = None
        self.task_end_date = None
        self.task_exitcode = None
        self.task_output = ""

    def rescan(self, queue="priority.low"):
        """
        Re-run the Scan using the given `queue`, low priority by default.
        """
        return download_and_scan.apply_async(
            args=[self.pk],
            kwargs={"run_subscriptions": False},
            queue=queue,
        )

    def has_subscriptions(self):
        subscriptions = [
            self.emailsubscription_set.exists(),
            self.webhooksubscription_set.exists(),
        ]
        return any(subscriptions)

    def run_subscriptions(self):
        for email_subscription in self.emailsubscription_set.all():
            email_subscription.notify()
        for webhook_subscription in self.webhooksubscription_set.all():
            webhook_subscription.notify()


class EmailSubscription(models.Model):
    scan = models.ForeignKey(
        to=Scan,
        on_delete=models.CASCADE,
    )
    email = models.EmailField(
        verbose_name=_("email address"),
    )

    def __str__(self):
        return f"{self.email} follows {self.scan}"

    def notify(self):
        template = "scanner/subscriptions/scan_completed.txt"
        context = {"scan": self.scan}
        message = render_to_string(template, context)

        email = EmailMessage(
            subject="[ScanCode.io] Scan completed",
            body=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[self.email],
        )
        email.send(fail_silently=True)


class WebhookSubscription(models.Model):
    scan = models.ForeignKey(
        to=Scan,
        on_delete=models.CASCADE,
    )
    user_uuid = models.UUIDField(
        _("User UUID"),
        editable=False,
    )
    target_url = models.URLField(
        _("Target URL"),
        max_length=1024,
    )
    sent = models.BooleanField(
        default=False,
    )
    created_date = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    def __str__(self):
        return f"{self.user_uuid} follows {self.scan}"

    def notify(self):
        payload = {
            "user_uuid": self.user_uuid,
            "scan_uri": self.scan.uri,
            "scan_status": self.scan.status,
        }

        try:
            response = requests.post(
                url=self.target_url,
                data=json.dumps(payload, cls=DjangoJSONEncoder),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
        except requests.exceptions.RequestException:
            return False

        if response.status_code in (200, 201, 202):
            self.sent = True
            self.save()
            return True
        return False
