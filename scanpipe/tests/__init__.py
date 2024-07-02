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

import os
from datetime import datetime
from unittest import mock

from django.apps import apps

from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredPackage
from scanpipe.tests.pipelines.do_nothing import DoNothing
from scanpipe.tests.pipelines.profile_step import ProfileStep
from scanpipe.tests.pipelines.raise_exception import RaiseException

scanpipe_app = apps.get_app_config("scanpipe")

scanpipe_app.register_pipeline("do_nothing", DoNothing)
scanpipe_app.register_pipeline("profile_step", ProfileStep)
scanpipe_app.register_pipeline("raise_exception", RaiseException)

FIXTURES_REGEN = os.environ.get("SCANCODEIO_TEST_FIXTURES_REGEN", False)
mocked_now = mock.Mock(now=lambda: datetime(2010, 10, 10, 10, 10, 10))


def make_resource_file(project, path, **extra):
    return CodebaseResource.objects.create(
        project=project,
        path=path,
        name=path.split("/")[-1],
        extension="." + path.split(".")[-1],
        type=CodebaseResource.Type.FILE,
        is_text=True,
        tag=path.split("/")[0],
        **extra
    )


def make_resource_directory(project, path, **extra):
    return CodebaseResource.objects.create(
        project=project,
        path=path,
        name=path.split("/")[-1],
        type=CodebaseResource.Type.DIRECTORY,
        tag=path.split("/")[0],
        **extra
    )


def make_package(project, package_url, **extra):
    package = DiscoveredPackage(project=project, **extra)
    package.set_package_url(package_url)
    package.save()
    return package


def make_dependency(project, **extra):
    return DiscoveredDependency.objects.create(project=project, **extra)


resource_data1 = {
    "path": "notice.NOTICE",
    "type": "file",
    "name": "notice.NOTICE",
    "status": "",
    "tag": "",
    "extension": ".NOTICE",
    "size": 1178,
    "md5": "90cd416fd24df31f608249b77bae80f1",
    "sha1": "4bd631df28995c332bf69d9d4f0f74d7ee089598",
    "sha256": "b323607418a36b5bd700fcf52ae9ca49f82ec6359bc4b89b1b2d73cf75321757",
    "sha512": "",
    "mime_type": "text/plain",
    "file_type": "ASCII text",
    "programming_language": "",
    "is_binary": False,
    "is_text": True,
    "is_archive": False,
    "is_media": False,
    "is_legal": False,
    "is_manifest": False,
    "is_readme": False,
    "is_top_level": False,
    "is_key_file": False,
    "license_detections": [],
    "detected_license_expression": "",
    "compliance_alert": "",
    "copyrights": [],
    "holders": [],
    "authors": [],
    "package_data": [],
    "for_packages": [],
    "emails": [],
    "urls": [],
    "extra_data": {},
}

package_data1 = {
    "type": "deb",
    "namespace": "debian",
    "name": "adduser",
    "version": "3.118",
    "qualifiers": {"arch": "all"},
    "subpath": None,
    "primary_language": "bash",
    "description": "add and remove users and groups",
    "release_date": "1999-10-10",
    "parties": [
        {
            "type": None,
            "role": "maintainer",
            "name": "Debian Adduser Developers <adduser@packages.debian.org>",
            "email": None,
            "url": None,
        }
    ],
    "keywords": ["admin"],
    "homepage_url": "https://packages.debian.org",
    "download_url": "https://download.url/package.zip",
    "filename": "package.zip",
    "size": "849",
    "sha1": None,
    "md5": "76cf50f29e47676962645632737365a7",
    "sha256": None,
    "sha512": None,
    "bug_tracking_url": None,
    "code_view_url": None,
    "vcs_url": "https://packages.vcs.url",
    "copyright": (
        "Copyright (c) 2000 Roland Bauerschmidt <rb@debian.org>\n"
        "Copyright (c) 1997, 1998, 1999 Guy Maor <maor@debian.org>\n"
        "Copyright (c) 1995 Ted Hajek <tedhajek@boombox.micro.umn.edu>\n"
        "portions Copyright (c) 1994 Debian Association, Inc."
    ),
    "declared_license_expression": "gpl-2.0 AND gpl-2.0-plus",
    "declared_license_expression_spdx": "GPL-2.0-only AND GPL-2.0-or-later",
    "other_license_expression": "apache-2.0 AND (mpl-1.1 OR gpl-2.0)",
    "other_license_expression_spdx": "Apache-2.0 AND (MPL-1.1 OR GPL-2.0)",
    "extracted_license_statement": "",
    "notice_text": "Notice\nText",
    "root_path": None,
    "dependencies": [],
    "source_packages": [],
    "purl": "pkg:deb/debian/adduser@3.118?arch=all",
    "repository_homepage_url": None,
    "repository_download_url": None,
    "api_data_url": None,
    "package_uid": "pkg:deb/debian/adduser@3.118?uuid=610bed29-ce39-40e7-92d6-fd8b",
}

package_data2 = {
    "type": "deb",
    "namespace": "debian",
    "name": "adduser",
    "version": "3.119",
}

for_package_uid = "pkg:deb/debian/adduser@3.118?uuid=610bed29-ce39-40e7-92d6-fd8b"

dependency_data1 = {
    "purl": "pkg:pypi/dask",
    "package_type": "pypi",
    "extracted_requirement": "dask<2023.0.0,>=2022.6.0",
    "scope": "install",
    "is_runtime": True,
    "is_optional": False,
    "is_resolved": False,
    "dependency_uid": "pkg:pypi/dask?uuid=e656b571-7d3f-46d1-b95b-8f037aef9692",
    "for_package_uid": for_package_uid,
    "datafile_path": "daglib-0.3.2.tar.gz-extract/daglib-0.3.2/PKG-INFO",
    "datasource_id": "pypi_sdist_pkginfo",
}

dependency_data2 = {
    "purl": "pkg:gem/appraisal@2.2.0",
    "package_type": "gem",
    "extracted_requirement": "",
    "scope": "dependencies",
    "is_runtime": True,
    "is_optional": False,
    "is_resolved": True,
    "dependency_uid": (
        "pkg:gem/appraisal@2.2.0?uuid=1907f061-911b-4980-a2d4-ae1a9ed871a9"
    ),
    "for_package_uid": for_package_uid,
    "datafile_path": "data.tar.gz-extract/Gemfile.lock",
    "datasource_id": "gemfile_lock",
}

dependency_data3 = {
    "purl": "pkg:pypi/dask",
    "package_type": "pypi",
    "extracted_requirement": ">= 1.0",
    "scope": "install",
    "is_runtime": True,
    "is_optional": False,
    "is_resolved": False,
    "dependency_uid": "pkg:pypi/dask?uuid=e656b571-7d3f-46d1-b95b-8f037aef9692",
    "for_package_uid": for_package_uid,
    "datafile_path": "daglib-0.3.2.tar.gz-extract/daglib-0.3.2/PKG-INFO",
    "datasource_id": "pypi_sdist_pkginfo",
}

license_policies = [
    {
        "license_key": "apache-2.0",
        "label": "Approved License",
        "color_code": "#008000",
        "compliance_alert": "",
    },
    {
        "license_key": "mpl-2.0",
        "label": "Restricted License",
        "color_code": "#ffcc33",
        "compliance_alert": "warning",
    },
    {
        "license_key": "gpl-3.0",
        "label": "Prohibited License",
        "color_code": "#c83025",
        "compliance_alert": "error",
    },
]

license_policies_index = {
    "gpl-3.0": {
        "color_code": "#c83025",
        "compliance_alert": "error",
        "label": "Prohibited License",
        "license_key": "gpl-3.0",
    },
    "apache-2.0": {
        "color_code": "#008000",
        "compliance_alert": "",
        "label": "Approved License",
        "license_key": "apache-2.0",
    },
    "mpl-2.0": {
        "color_code": "#ffcc33",
        "compliance_alert": "warning",
        "label": "Restricted License",
        "license_key": "mpl-2.0",
    },
}


scorecard_data = {
  "date": "2024-06-17",
  "repo": {
    "name": "github.com/pallets/flask",
    "commit": "d718ecf6d3dfc4656d262154c59672437c1ea075"
  },
  "scorecard": {
    "version": "v5.0.0-rc2-63-g5d08c1cc",
    "commit": "5d08c1cc11c1e45c2ab2a88adac0a18464f0216b"
  },
  "score": 6.7,
  "checks": [
    {
      "name": "Code-Review",
      "score": 1,
      "reason": "Found 2/11 approved changesets -- score normalized to 1",
      "details": None,
      "documentation": {
        "short": "Determines if the project requires human code review before pull requests (aka merge requests) are merged.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#code-review"
      }
    },
    {
      "name": "Maintained",
      "score": 10,
      "reason": "30 commit(s) and 17 issue activity found in the last 90 days -- score normalized to 10",
      "details": None,
      "documentation": {
        "short": "Determines if the project is \"actively maintained\".",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#maintained"
      }
    },
    {
      "name": "CII-Best-Practices",
      "score": 0,
      "reason": "no effort to earn an OpenSSF best practices badge detected",
      "details": None,
      "documentation": {
        "short": "Determines if the project has an OpenSSF (formerly CII) Best Practices Badge.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#cii-best-practices"
      }
    },
    {
      "name": "License",
      "score": 10,
      "reason": "license file detected",
      "details": [
        "Info: project has a license file: LICENSE.txt:0",
        "Info: FSF or OSI recognized license: BSD 3-Clause \"New\" or \"Revised\" License: LICENSE.txt:0"
      ],
      "documentation": {
        "short": "Determines if the project has defined a license.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#license"
      }
    },
    {
      "name": "Dangerous-Workflow",
      "score": 10,
      "reason": "no dangerous workflow patterns detected",
      "details": None,
      "documentation": {
        "short": "Determines if the project's GitHub Action workflows avoid dangerous patterns.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#dangerous-workflow"
      }
    },
    {
      "name": "Signed-Releases",
      "score": 10,
      "reason": "5 out of the last 5 releases have a total of 5 signed artifacts.",
      "details": [
        "Info: provenance for release artifact: multiple.intoto.jsonl: https://api.github.com/repos/pallets/flask/releases/assets/160813583",
        "Info: provenance for release artifact: multiple.intoto.jsonl: https://api.github.com/repos/pallets/flask/releases/assets/149637381",
        "Info: provenance for release artifact: multiple.intoto.jsonl: https://api.github.com/repos/pallets/flask/releases/assets/146388022",
        "Info: provenance for release artifact: multiple.intoto.jsonl: https://api.github.com/repos/pallets/flask/releases/assets/128454404",
        "Info: provenance for release artifact: multiple.intoto.jsonl: https://api.github.com/repos/pallets/flask/releases/assets/122480844"
      ],
      "documentation": {
        "short": "Determines if the project cryptographically signs release artifacts.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#signed-releases"
      }
    },
    {
      "name": "Token-Permissions",
      "score": 0,
      "reason": "detected GitHub workflow tokens with excessive permissions",
      "details": [
        "Info: jobLevel 'actions' permission set to 'read': .github/workflows/publish.yaml:32",
        "Warn: no topLevel permission defined: .github/workflows/publish.yaml:1",
        "Warn: no topLevel permission defined: .github/workflows/tests.yaml:1",
        "Info: no jobLevel write permissions found"
      ],
      "documentation": {
        "short": "Determines if the project's workflows follow the principle of least privilege.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#token-permissions"
      }
    },
    {
      "name": "Binary-Artifacts",
      "score": 10,
      "reason": "no binaries found in the repo",
      "details": None,
      "documentation": {
        "short": "Determines if the project has generated executable (binary) artifacts in the source repository.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#binary-artifacts"
      }
    },
    {
      "name": "Branch-Protection",
      "score": -1,
      "reason": "internal error: error during branchesHandler.setup: internal error: githubv4.Query: Resource not accessible by integration",
      "details": None,
      "documentation": {
        "short": "Determines if the default and release branches are protected with GitHub's branch protection settings.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#branch-protection"
      }
    },
    {
      "name": "Pinned-Dependencies",
      "score": 4,
      "reason": "dependency not pinned by hash detected -- score normalized to 4",
      "details": [
        "Info: Possibly incomplete results: error parsing shell code: invalid parameter name: .github/workflows/tests.yaml:44",
        "Warn: pipCommand not pinned by hash: .devcontainer/on-create-command.sh:5",
        "Warn: pipCommand not pinned by hash: .devcontainer/on-create-command.sh:6",
        "Warn: pipCommand not pinned by hash: .github/workflows/publish.yaml:19",
        "Warn: pipCommand not pinned by hash: .github/workflows/tests.yaml:44",
        "Warn: pipCommand not pinned by hash: .github/workflows/tests.yaml:60",
        "Info:  10 out of  10 GitHub-owned GitHubAction dependencies pinned",
        "Info:   3 out of   3 third-party GitHubAction dependencies pinned",
        "Info:   0 out of   5 pipCommand dependencies pinned"
      ],
      "documentation": {
        "short": "Determines if the project has declared and pinned the dependencies of its build process.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#pinned-dependencies"
      }
    },
    {
      "name": "Fuzzing",
      "score": 10,
      "reason": "project is fuzzed",
      "details": [
        "Info: OSSFuzz integration found"
      ],
      "documentation": {
        "short": "Determines if the project uses fuzzing.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#fuzzing"
      }
    },
    {
      "name": "Packaging",
      "score": 10,
      "reason": "packaging workflow detected",
      "details": [
        "Info: Project packages its releases by way of GitHub Actions.: .github/workflows/publish.yaml:55"
      ],
      "documentation": {
        "short": "Determines if the project is published as a package that others can easily download, install, easily update, and uninstall.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#packaging"
      }
    },
    {
      "name": "Security-Policy",
      "score": 9,
      "reason": "security policy file detected",
      "details": [
        "Info: security policy file detected: github.com/pallets/.github/SECURITY.md:1",
        "Info: Found linked content: github.com/pallets/.github/SECURITY.md:1",
        "Warn: One or no descriptive hints of disclosure, vulnerability, and/or timelines in security policy",
        "Info: Found text in security policy: github.com/pallets/.github/SECURITY.md:1"
      ],
      "documentation": {
        "short": "Determines if the project has published a security policy.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#security-policy"
      }
    },
    {
      "name": "Vulnerabilities",
      "score": 6,
      "reason": "4 existing vulnerabilities detected",
      "details": [
        "Warn: Project is vulnerable to: GHSA-h5c8-rqwp-cp95",
        "Warn: Project is vulnerable to: GHSA-h75v-3vvj-5mfj",
        "Warn: Project is vulnerable to: GHSA-2g68-c3qc-8985",
        "Warn: Project is vulnerable to: GHSA-hrfv-mqp8-q5rw / PYSEC-2023-221"
      ],
      "documentation": {
        "short": "Determines if the project has open, known unfixed vulnerabilities.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#vulnerabilities"
      }
    },
    {
      "name": "SAST",
      "score": 0,
      "reason": "SAST tool is not run on all commits -- score normalized to 0",
      "details": [
        "Warn: 0 commits out of 22 are checked with a SAST tool"
      ],
      "documentation": {
        "short": "Determines if the project uses static code analysis.",
        "url": "https://github.com/ossf/scorecard/blob/5d08c1cc11c1e45c2ab2a88adac0a18464f0216b/docs/checks.md#sast"
      }
    }
  ]
}