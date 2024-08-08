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

import json
import sys
import uuid
from pathlib import Path

from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist

from attributecode.model import About
from packagedcode import APPLICATION_PACKAGE_DATAFILE_HANDLERS
from packagedcode.licensing import get_license_detections_and_expression
from packageurl import PackageURL
from python_inspector.api import resolve_dependencies

from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredPackage
from scanpipe.pipes import cyclonedx
from scanpipe.pipes import flag
from scanpipe.pipes import spdx
from scanpipe.pipes import update_or_create_dependency
from scanpipe.pipes import update_or_create_package

"""
Resolve packages from manifest, lockfile, and SBOM.
"""


def resolve_manifest_resources(resource, package_registry):
    """Get package data from resource."""
    packages = get_packages_from_manifest(resource.location, package_registry) or []

    for package_data in packages:
        package_data["codebase_resources"] = [resource]

    return packages


def get_dependencies_from_manifest(resource):
    """Get dependency data from resource."""
    dependencies = []

    default_package_type = get_default_package_type(resource.location)
    if not default_package_type:
        return []

    if default_package_type == "spdx":
        dependencies = resolve_spdx_dependencies(input_location=resource.location)

    return dependencies


def get_data_from_manifests(project, package_registry, manifest_resources, model=None):
    """
    Get package and dependency data from package manifests/lockfiles/SBOMs or
    for resolved packages from package requirements.
    """
    resolved_packages = []
    resolved_dependencies = []
    sboms_headers = {}

    if not manifest_resources.exists():
        project.add_warning(
            description="No resources containing package data found in codebase.",
            model=model,
        )
        return []

    for resource in manifest_resources:
        packages = resolve_manifest_resources(resource, package_registry)
        if packages:
            resolved_packages.extend(packages)
            if headers := get_manifest_headers(resource):
                sboms_headers[resource.name] = headers
        else:
            project.add_error(
                description="No packages could be resolved",
                model=model,
                resource=resource,
            )

        dependencies = get_dependencies_from_manifest(resource)
        if dependencies:
            resolved_dependencies.extend(dependencies)

    if sboms_headers:
        project.update_extra_data({"sboms_headers": sboms_headers})

    return resolved_packages, resolved_dependencies


def create_packages_and_dependencies(project, packages, resolved=False):
    """
    Create DiscoveredPackage and DiscoveredDependency objects for
    packages detected in a package manifest, lockfile or SBOM.

    If resolved, create packages out of resolved dependencies,
    otherwise create dependencies.
    """
    for package_data in packages:
        package_data = set_license_expression(package_data)
        dependencies = package_data.pop("dependencies", [])
        codebase_resources = package_data.pop("codebase_resources", [])
        update_or_create_package(project, package_data, codebase_resources)

        for dependency_data in dependencies:
            if resolved:
                if resolved_package := dependency_data.get("resolved_package"):
                    resolved_package.pop("dependencies", [])
                    update_or_create_package(project, resolved_package)
            else:
                update_or_create_dependency(project, dependency_data)


def create_dependencies_from_packages_extra_data(project):
    """
    Create Dependency objects from the Package extra_data values.
    The Package instances need to be saved first in the database before creating the
    Dependency objects.
    The dependencies declared in the SBOM are stored on the Package.extra_data field
    and resolved as Dependency objects in this function.
    """
    project_packages = project.discoveredpackages.all()
    created_count = 0

    packages_with_depends_on = project_packages.filter(
        extra_data__has_key="depends_on"
    ).prefetch_related("codebase_resources")

    for for_package in packages_with_depends_on:
        datafile_resource = None
        codebase_resources = for_package.codebase_resources.all()
        if len(codebase_resources) == 1:
            datafile_resource = codebase_resources[0]

        for bom_ref in for_package.extra_data.get("depends_on", []):
            try:
                resolved_to_package = project_packages.get(package_uid=bom_ref)
            except (ObjectDoesNotExist, MultipleObjectsReturned):
                project.add_error(
                    description=f"Could not find resolved_to package entry: {bom_ref}.",
                    model="create_dependencies",
                )
                continue

            DiscoveredDependency.objects.create(
                project=project,
                dependency_uid=str(uuid.uuid4()),
                for_package=for_package,
                resolved_to_package=resolved_to_package,
                datafile_resource=datafile_resource,
                is_runtime=True,
                is_resolved=True,
                is_direct=True,
            )
            created_count += 1

    return created_count


def get_packages_from_manifest(input_location, package_registry=None):
    """
    Resolve packages or get packages data from a package manifest file/
    lockfile/SBOM at `input_location`.
    """
    default_package_type = get_default_package_type(input_location)
    # we only try to resolve packages if file at input_location is
    # a package manifest, and ignore for other files
    if not default_package_type:
        return

    # Get resolvers for available packages/SBOMs in the registry
    resolver = package_registry.get(default_package_type)
    if resolver:
        resolved_packages = resolver(input_location=input_location)
        return resolved_packages


def get_manifest_resources(project):
    """Get all resources in the codebase which are package manifests."""
    for resource in project.codebaseresources.no_status():
        manifest_type = get_default_package_type(input_location=resource.location)
        if manifest_type:
            resource.update(status=flag.APPLICATION_PACKAGE)

    return project.codebaseresources.filter(status=flag.APPLICATION_PACKAGE)


def resolve_pypi_packages(input_location):
    """Resolve the PyPI packages from the `input_location` requirements file."""
    python_version = f"{sys.version_info.major}{sys.version_info.minor}"
    operating_system = "linux"

    inspector_output = resolve_dependencies(
        requirement_files=[input_location],
        python_version=python_version,
        operating_system=operating_system,
        prefer_source=True,
    )

    return inspector_output.packages


def resolve_about_package(input_location):
    """Resolve the package from the ``input_location`` .ABOUT file."""
    about = About(location=input_location)
    about_data = about.as_dict()
    package_data = about_data.copy()

    if package_url := about_data.get("package_url"):
        package_url_data = PackageURL.from_string(package_url).to_dict(encode=True)
        for field_name, value in package_url_data.items():
            if value:
                package_data[field_name] = value

    package_data["extra_data"] = {}

    if about_resource := about_data.get("about_resource"):
        package_data["filename"] = list(about_resource.keys())[0]

    if ignored_resources := about_data.get("ignored_resources"):
        package_data["extra_data"]["ignored_resources"] = list(ignored_resources.keys())

    populate_license_notice_fields_about(package_data, about_data)

    for field_name, value in about_data.items():
        if field_name.startswith("checksum_"):
            package_data[field_name.replace("checksum_", "")] = value

    package_data = DiscoveredPackage.clean_data(package_data)
    return package_data


def populate_license_notice_fields_about(package_data, about_data):
    """
    Populate ``package_data`` with license and notice attributes
    from ``about_data``.
    """
    if license_expression := about_data.get("license_expression"):
        package_data["declared_license_expression"] = license_expression

    if notice_dict := about_data.get("notice_file"):
        package_data["notice_text"] = list(notice_dict.values())[0]
        package_data["extra_data"]["notice_file"] = list(notice_dict.keys())[0]

    if license_dict := about_data.get("license_file"):
        package_data["extra_data"]["license_file"] = list(license_dict.keys())[0]
        package_data["extracted_license_statement"] = list(license_dict.values())[0]


def resolve_about_packages(input_location):
    """
    Wrap ``resolve_about_package`` to return a list as expected by the
    InspectManifest pipeline.
    """
    return [resolve_about_package(input_location)]


def convert_spdx_expression(license_expression_spdx):
    """
    Return an ScanCode license expression from a SPDX `license_expression_spdx`
    string.
    """
    return get_license_detections_and_expression(license_expression_spdx)[1]


def spdx_package_to_package_data(spdx_package):
    """Convert the provided spdx_package into package_data."""
    package_url_dict = {}
    # Store the original "SPDXID" as package_uid for dependencies resolution.
    package_uid = spdx_package.spdx_id

    for ref in spdx_package.external_refs:
        if ref.type == "purl":
            purl = ref.locator
            package_url_dict = PackageURL.from_string(purl).to_dict(encode=True)

    checksum_data = {
        checksum.algorithm.lower(): checksum.value
        for checksum in spdx_package.checksums
    }

    declared_license_expression_spdx = spdx_package.license_concluded
    declared_expression = ""
    if declared_license_expression_spdx:
        declared_expression = convert_spdx_expression(declared_license_expression_spdx)

    package_data = {
        "package_uid": package_uid,
        "name": spdx_package.name,
        "download_url": spdx_package.download_location,
        "declared_license_expression": declared_expression,
        "declared_license_expression_spdx": declared_license_expression_spdx,
        "extracted_license_statement": spdx_package.license_declared,
        "copyright": spdx_package.copyright_text,
        "version": spdx_package.version,
        "homepage_url": spdx_package.homepage,
        "filename": spdx_package.filename,
        "description": spdx_package.description,
        "release_date": spdx_package.release_date,
        **package_url_dict,
        **checksum_data,
    }

    return {
        key: value
        for key, value in package_data.items()
        if value not in [None, "", "NOASSERTION"]
    }


def spdx_relationship_to_dependency_data(spdx_relationship):
    """Convert the provided spdx_relationship into dependency_data."""
    # spdx_id is a dependency of related_spdx_id
    if spdx_relationship.is_dependency_relationship:
        for_package_uid = spdx_relationship.related_spdx_id
        resolve_to_package_uid = spdx_relationship.spdx_id
    else:  # spdx_id depends on related_spdx_id
        for_package_uid = spdx_relationship.spdx_id
        resolve_to_package_uid = spdx_relationship.related_spdx_id

    dependency_data = {
        "for_package_uid": for_package_uid,
        "resolve_to_package_uid": resolve_to_package_uid,
        "is_runtime": True,
        "is_resolved": True,
        "is_direct": True,
    }
    return dependency_data


def get_spdx_document_from_file(input_location):
    """Return the loaded SPDX document from the `input_location` file."""
    input_path = Path(input_location)
    spdx_document = json.loads(input_path.read_text())

    try:
        spdx.validate_document(spdx_document)
    except Exception as e:
        raise Exception(f'SPDX document "{input_path.name}" is not valid: {e}')

    return spdx_document


def resolve_spdx_packages(input_location):
    """Resolve the packages from the `input_location` SPDX document file."""
    spdx_document = get_spdx_document_from_file(input_location)
    return [
        spdx_package_to_package_data(spdx.Package.from_data(spdx_package))
        for spdx_package in spdx_document.get("packages", [])
    ]


def resolve_spdx_dependencies(input_location):
    """Resolve the dependencies from the `input_location` SPDX document file."""
    spdx_document = get_spdx_document_from_file(input_location)
    spdx_relationships = [
        spdx.Relationship.from_data(spdx_relationship)
        for spdx_relationship in spdx_document.get("relationships", [])
    ]

    return [
        spdx_relationship_to_dependency_data(spdx_relationship)
        for spdx_relationship in spdx_relationships
    ]


def get_default_package_type(input_location):
    """
    Return the package type associated with the provided `input_location`.
    This type is used to get the related handler that knows how process the input.
    """
    input_location = str(input_location)

    for handler in APPLICATION_PACKAGE_DATAFILE_HANDLERS:
        if handler.is_datafile(input_location):
            return handler.default_package_type

    if input_location.endswith((".spdx", ".spdx.json")):
        return "spdx"

    if input_location.endswith(("bom.json", ".cdx.json", "bom.xml", ".cdx.xml")):
        return "cyclonedx"

    if input_location.endswith((".json", ".xml")):
        if cyclonedx.is_cyclonedx_bom(input_location):
            return "cyclonedx"
        if spdx.is_spdx_document(input_location):
            return "spdx"


# Mapping between `default_package_type` its related resolver functions
# for package dependency resolvers
resolver_registry = {
    "pypi": resolve_pypi_packages,
}


# Mapping between `default_package_type` its related resolver functions
# for SBOMs and About files
sbom_registry = {
    "about": resolve_about_packages,
    "spdx": resolve_spdx_packages,
    "cyclonedx": cyclonedx.resolve_cyclonedx_packages,
}


def set_license_expression(package_data):
    """
    Set the license expression from a detected license dict/str in provided
    `package_data`.
    """
    extracted_license_statement = package_data.get("extracted_license_statement")
    declared_license_expression = package_data.get("declared_license_expression")

    if extracted_license_statement and not declared_license_expression:
        _, license_expression = get_license_detections_and_expression(
            extracted_license_statement
        )
        if license_expression:
            package_data["declared_license_expression"] = license_expression

    return package_data


def get_manifest_headers(resource):
    """Extract headers from a manifest file based on its package type."""
    input_location = resource.location
    package_type = get_default_package_type(input_location)
    extract_fields = []

    if package_type == "cyclonedx":
        extract_fields = [
            "bomFormat",
            "specVersion",
            "serialNumber",
            "version",
            "metadata",
        ]
    elif package_type == "spdx":
        extract_fields = [
            "spdxVersion",
            "dataLicense",
            "SPDXID",
            "name",
            "documentNamespace",
            "creationInfo",
            "comment",
        ]

    if extract_fields:
        return extract_headers(input_location, extract_fields)


def extract_headers(input_location, extract_fields):
    """Read a file from the given location and extracts specified fields."""
    input_path = Path(input_location)
    document_data = input_path.read_text()

    if str(input_location).endswith(".json"):
        cyclonedx_document = json.loads(document_data)
        extracted_headers = {
            field: value
            for field, value in cyclonedx_document.items()
            if field in extract_fields
        }
        return extracted_headers

    return {}
