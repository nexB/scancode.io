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

"""
WSGI config for ScanCode.io.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/dev/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

from celery.exceptions import OperationalError

from scancodeio.celery import app
from scanpipe.models import Run

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "scancodeio.settings")


def get_celery_worker_status():
    try:
        i = app.control.inspect()
        active = i.active()
        scheduled = i.scheduled()
        if active[list(active.keys())[0]] or scheduled[list(scheduled.keys())[0]]:
            return True
    except OperationalError:
        return False


result = get_celery_worker_status()
if not result:
    Run.objects.filter(task_exitcode__isnull=True).update(task_exitcode=1)

application = get_wsgi_application()
