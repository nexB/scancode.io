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

import sys
from pathlib import Path

import environ

PROJECT_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = PROJECT_DIR.parent

# Environment

env_file = "/etc/scancodeio/.env"
if not Path(env_file).exists():
    env_file = str(ROOT_DIR.joinpath(".env"))

environ.Env.read_env(env_file)
env = environ.Env()

SECRET_KEY = env.str("SECRET_KEY")

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=[".localhost", "127.0.0.1", "[::1]"])

# ScanCode.io

SCANCODE_DEFAULT_OPTIONS = env.list("SCANCODE_DEFAULT_OPTIONS", default=[])

# Application definition

INSTALLED_APPS = (
    # Local apps
    # Must come before Third-party apps for proper templates override
    "scanner",
    "scanpipe",
    # Django built-in
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.admin",
    "django.contrib.humanize",
    # Third-party apps
    "crispy_forms",
    "django_filters",
    "rest_framework",
    "rest_framework.authtoken",
    "drf_spectacular",
)

MIDDLEWARE = (
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
)

ROOT_URLCONF = "scancodeio.urls"

WSGI_APPLICATION = "scancodeio.wsgi.application"

# Database

DATABASES = {
    "default": {
        "ENGINE": env.str("SCANCODEIO_DB_ENGINE", "django.db.backends.postgresql"),
        "HOST": env.str("SCANCODEIO_DB_HOST", "localhost"),
        "NAME": env.str("SCANCODEIO_DB_NAME", "scancodeio"),
        "USER": env.str("SCANCODEIO_DB_USER", "scancodeio"),
        "PASSWORD": env.str("SCANCODEIO_DB_PASSWORD", "scancodeio"),
        "PORT": "5432",
        "ATOMIC_REQUESTS": True,
    }
}

# Templates

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": False,
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.request",
            ],
        },
    },
]

# Passwords

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 14,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# True if running tests through `./manage test`
IS_TESTS = "test" in sys.argv

# Cache

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "default",
    },
    "scan_results": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "scan",
        "TIMEOUT": 86_400,  # 1 day
        "OPTIONS": {
            # Maximum entries allowed in the cache before old values are deleted
            "MAX_ENTRIES": 1_000_000,
        },
    },
}

# Logging

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "null": {
            "class": "logging.NullHandler",
        },
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "loggers": {
        "scanner.tasks": {
            "handlers": ["null"] if IS_TESTS else ["console"],
            "level": env.str("DJANGO_LOG_LEVEL", "INFO"),
        },
        "scanpipe.pipelines": {
            "handlers": ["null"] if IS_TESTS else ["console"],
            "level": env.str("DJANGO_LOG_LEVEL", "INFO"),
        },
    },
}

# Instead of sending out real emails the console backend just writes the emails
# that would be sent to the standard output.
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Internationalization

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)

STATIC_URL = "/static/"

STATIC_ROOT = "/var/scancodeio/static/"

STATICFILES_DIRS = [
    str(PROJECT_DIR.joinpath("static")),
]

# Third-party apps

CRISPY_TEMPLATE_PACK = "bootstrap3"

# Celery

CELERY_BROKER_URL = env.str("CELERY_BROKER_URL", default="redis://")
CELERY_RESULT_BACKEND = env.str("CELERY_RESULT_BACKEND", default="redis://")
CELERY_IGNORE_RESULT = env.bool("CELERY_IGNORE_RESULT", default=True)
CELERY_TASK_DEFAULT_QUEUE = env.str("CELERY_RESULT_BACKEND", default="default")
# When True, tasks will be executed immediately in the local thread instead of being
# sent to the queue for execution by a worker.
CELERY_TASK_ALWAYS_EAGER = env.bool("CELERY_TASK_ALWAYS_EAGER", default=True)

# Django restframework

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework.authentication.TokenAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_RENDERER_CLASSES": (
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
        "rest_framework.renderers.AdminRenderer",
    ),
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
    ),
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    "UPLOADED_FILES_USE_URL": False,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SPECTACULAR_SETTINGS = {
    "SERVE_INCLUDE_SCHEMA": False,
    "TITLE": "Scancode.io API",
    "COMPONENT_SPLIT_REQUEST": True,
}
