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
import tempfile
from pathlib import Path
from urllib.parse import urljoin

import environ

PROJECT_DIR = Path(__file__).resolve().parent
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

# SECURITY WARNING: don't run with debug turned on in production
DEBUG = env.bool("SCANCODEIO_DEBUG", default=False)

SCANCODEIO_WORKSPACE_LOCATION = env.str("SCANCODEIO_WORKSPACE_LOCATION", default="var")

SCANCODE_TOOLKIT_CLI_OPTIONS = env.list("SCANCODE_TOOLKIT_CLI_OPTIONS", default=[])

# Set the number of parallel processes to use for ScanCode related scan execution.
# If the SCANCODEIO_PROCESSES argument is not set, defaults to an optimal number of CPUs
# available on the machine.
SCANCODEIO_PROCESSES = env.int("SCANCODEIO_PROCESSES", default=None)

SCANCODEIO_POLICIES_FILE = env.str("SCANCODEIO_POLICIES_FILE", default="policies.yml")

# This setting defines the additional locations ScanCode.io will search for pipelines.
# This should be set to a list of strings that contain full paths to your additional
# pipelines directories.
SCANCODEIO_PIPELINES_DIRS = env.list("SCANCODEIO_PIPELINES_DIRS", default=[])

# Application definition

INSTALLED_APPS = (
    # Local apps
    # Must come before Third-party apps for proper templates override
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
    'mozilla_django_oidc',
)

MIDDLEWARE = (
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "mozilla_django_oidc.middleware.SessionRefresh",
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
        "PORT": env.str("SCANCODEIO_DB_PORT", "5432"),
        "ATOMIC_REQUESTS": True,
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"

# Templates

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "debug": DEBUG,
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.request",
                "scancodeio.context_processors.versions",
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

# Testing

# True if running tests through `./manage test`
IS_TESTS = "test" in sys.argv

if IS_TESTS:
    # Do not pollute the workspace while running the tests
    SCANCODEIO_WORKSPACE_LOCATION = tempfile.mkdtemp()

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
        "scanpipe.pipelines": {
            "handlers": ["null"] if IS_TESTS else ["console"],
            "level": env.str("DJANGO_LOG_LEVEL", "INFO"),
        },
        "scanpipe.pipes": {
            "handlers": ["null"] if IS_TESTS else ["console"],
            "level": env.str("DJANGO_LOG_LEVEL", "INFO"),
        },
        'mozilla_django_oidc': {
            'handlers': ["null"] if IS_TESTS else ["console"],
            'level': env.str("DJANGO_LOG_LEVEL", "INFO"),
        },
    },
}

# Instead of sending out real emails the console backend just writes the emails
# that would be sent to the standard output.
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

# Internationalization

LANGUAGE_CODE = "en-us"

TIME_ZONE = env.str("TIME_ZONE", default="UTC")

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
CELERY_TRACK_STARTED = env.bool("CELERY_TRACK_STARTED", default=True)
CELERY_IGNORE_RESULT = env.bool("CELERY_IGNORE_RESULT", default=False)
CELERY_TASK_DEFAULT_QUEUE = env.str("CELERY_RESULT_BACKEND", default="default")
# When True, tasks will be executed immediately in the local thread instead of being
# sent to the queue for execution by a worker.
CELERY_TASK_ALWAYS_EAGER = env.bool("CELERY_TASK_ALWAYS_EAGER", default=True)

#OIDC Integration
OIDC_RP_CLIENT_ID = env.str("OIDC_RP_CLIENT_ID", default=None)
OIDC_RP_CLIENT_SECRET = env.str("OIDC_RP_CLIENT_SECRET", default=None)
OIDC_RP_SIGN_ALGO = env.str("OIDC_RP_SIGN_ALGO", default="RS256")

OIDC_OP_JWKS_ENDPOINT = urljoin(env.str("OIDC_OP_REALM_ENDPOINT"), "protocol/openid-connect/certs")
OIDC_OP_AUTHORIZATION_ENDPOINT = urljoin(env.str("OIDC_OP_REALM_ENDPOINT"), "protocol/openid-connect/auth")
OIDC_OP_TOKEN_ENDPOINT = urljoin(env.str("OIDC_OP_REALM_ENDPOINT"), "protocol/openid-connect/token")
OIDC_OP_USER_ENDPOINT = urljoin(env.str("OIDC_OP_REALM_ENDPOINT"), "protocol/openid-connect/userinfo")
OIDC_OP_LOGOUT_ENDPOINT = urljoin(env.str("OIDC_OP_REALM_ENDPOINT"), "protocol/openid-connect/logout")

LOGIN_URL = 'oidc_authentication_init'
LOGOUT_REDIRECT_URL = "/"
OIDC_OP_LOGOUT_URL_METHOD = 'scancodeio.auth.provider_logout'

# Django restframework

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "mozilla_django_oidc.contrib.drf.OIDCAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": env.tuple(
        "REST_FRAMEWORK_DEFAULT_PERMISSION_CLASSES",
        default=("rest_framework.permissions.IsAuthenticated",),
    ),
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
    "PAGE_SIZE": env.int("SCANCODEIO_REST_API_PAGE_SIZE", default=50),
    "UPLOADED_FILES_USE_URL": False,
}

AUTHENTICATION_BACKENDS = (
    'mozilla_django_oidc.auth.OIDCAuthenticationBackend',
    'django.contrib.auth.backends.ModelBackend',
) 