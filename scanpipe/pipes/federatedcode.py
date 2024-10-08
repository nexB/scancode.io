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


import tempfile
import textwrap
from pathlib import Path
from urllib.parse import urljoin

from git import Repo

from aboutcode import hashid
from scancodeio import VERSION
from scancodeio import settings
from scanpipe.pipes.output import JSONResultsGenerator


def is_configured():
    """Return True if the required FederatedCode settings have been set."""
    missing_vars = []
    if not settings.FEDERATEDCODE_GIT_ACCOUNT:
        missing_vars.append("FEDERATEDCODE_GIT_ACCOUNT")
    if not settings.FEDERATEDCODE_GIT_SERVICE_TOKEN:
        missing_vars.append("FEDERATEDCODE_GIT_SERVICE_TOKEN")
    if not settings.FEDERATEDCODE_GIT_SERVICE_NAME:
        missing_vars.append("FEDERATEDCODE_GIT_SERVICE_NAME")
    if not settings.FEDERATEDCODE_GIT_SERVICE_EMAIL:
        missing_vars.append("FEDERATEDCODE_GIT_SERVICE_EMAIL")

    if missing_vars:
        return False, f'Missing environment variables: {", ".join(missing_vars)}'

    return True, ""


def clone_repository(repo_url, logger=None):
    """Clone repository to local_path."""
    local_dir = tempfile.mkdtemp()

    authenticated_repo_url = repo_url.replace(
        "https://",
        f"https://{settings.FEDERATEDCODE_GIT_SERVICE_TOKEN}@",
    )
    repo = Repo.clone_from(url=authenticated_repo_url, to_path=local_dir, depth=1)

    repo.config_writer(config_level="repository").set_value(
        "user", "name", settings.FEDERATEDCODE_GIT_SERVICE_NAME
    ).release()

    repo.config_writer(config_level="repository").set_value(
        "user", "email", settings.FEDERATEDCODE_GIT_SERVICE_EMAIL
    ).release()

    return repo


def get_package_repository(package, logger=None):
    """Return the Git repository URL and scan path for a given package."""
    package_base_dir = hashid.get_package_base_dir(purl=package.purl)
    package_repo_name = package_base_dir.parts[0]

    package_scan_path = package_base_dir / package.version / "scan.json"
    package_git_repo_url = urljoin(
        settings.FEDERATEDCODE_GIT_ACCOUNT, f"{package_repo_name}.git"
    )

    return package_git_repo_url, package_scan_path


def add_scan_result(project, repo, package_scan_file, logger=None):
    """Add package scan result to the local Git repository."""
    relative_scan_file_path = Path(*package_scan_file.parts[1:])

    write_to = Path(repo.working_dir) / relative_scan_file_path

    write_to.parent.mkdir(parents=True, exist_ok=True)
    results_generator = JSONResultsGenerator(project)
    with open(write_to, encoding="utf-8", mode="w") as file:
        for chunk in results_generator:
            file.write(chunk)

    return relative_scan_file_path


def commit_and_push_changes(
    repo, file_to_commit, purl, remote_name="origin", logger=None
):
    """Commit and push changes to remote repository."""
    author_name = settings.FEDERATEDCODE_GIT_SERVICE_NAME
    author_email = settings.FEDERATEDCODE_GIT_SERVICE_EMAIL

    change_type = "Add" if file_to_commit in repo.untracked_files else "Update"
    commit_message = f"""\
    {change_type} scan result for {purl}

    Tool: pkg:github/aboutcode-org/scancode.io@v{VERSION}
    Reference: https://{settings.ALLOWED_HOSTS[0]}/

    Signed-off-by: {author_name} <{author_email}>
    """

    default_branch = repo.active_branch.name

    repo.index.add([file_to_commit])
    repo.index.commit(textwrap.dedent(commit_message))
    repo.git.push(remote_name, default_branch)
