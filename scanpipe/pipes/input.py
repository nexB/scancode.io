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

import shutil
from pathlib import Path

from django.core.exceptions import FieldDoesNotExist
from django.core.validators import EMPTY_VALUES
from django.db import models

import openpyxl
from typecode.contenttype import get_type

from scanpipe import pipes
from scanpipe.models import CodebaseRelation
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredLicense
from scanpipe.models import DiscoveredPackage
from scanpipe.pipes import scancode
from scanpipe.pipes.output import mappings_key_by_fieldname


def copy_input(input_location, dest_path):
    """Copy the ``input_location`` (file or directory) to the ``dest_path``."""
    input_path = Path(input_location)
    destination = Path(dest_path) / input_path.name

    if input_path.is_dir():
        shutil.copytree(input_location, destination)
    else:
        shutil.copyfile(input_location, destination)

    return destination


def copy_inputs(input_locations, dest_path):
    """Copy the provided ``input_locations`` to the ``dest_path``."""
    for input_location in input_locations:
        copy_input(input_location, dest_path)


def move_input(input_location, dest_path):
    """Move the provided ``input_location`` to the ``dest_path``."""
    destination = dest_path / Path(input_location).name
    return shutil.move(input_location, destination)


def move_inputs(inputs, dest_path):
    """Move the provided ``inputs`` to the ``dest_path``."""
    for input_location in inputs:
        move_input(input_location, dest_path)


def get_tool_name_from_scan_headers(scan_data):
    """Return the ``tool_name`` of the first header in the provided ``scan_data``."""
    if headers := scan_data.get("headers", []):
        first_header = headers[0]
        tool_name = first_header.get("tool_name", "")
        return tool_name


def is_archive(location):
    """Return True if the file at ``location`` is an archive."""
    return get_type(location).is_archive


def load_inventory_from_toolkit_scan(project, input_location):
    """
    Create license detections, packages, dependencies, and resources
    loaded from the ScanCode-toolkit scan results located at ``input_location``.
    """
    scanned_codebase = scancode.get_virtual_codebase(project, input_location)
    scancode.create_discovered_licenses(project, scanned_codebase)
    scancode.create_discovered_packages(project, scanned_codebase)
    scancode.create_codebase_resources(project, scanned_codebase)
    scancode.create_discovered_dependencies(
        project, scanned_codebase, strip_datafile_path_root=True
    )


def load_inventory_from_scanpipe(project, scan_data):
    """
    Create license detections, packages, dependencies, resources, and relations
    loaded from a ScanCode.io JSON output provided as ``scan_data``.
    """
    for detection_data in scan_data.get("license_detections", []):
        pipes.update_or_create_license_detection(project, detection_data)

    for package_data in scan_data.get("packages", []):
        pipes.update_or_create_package(project, package_data)

    for resource_data in scan_data.get("files", []):
        pipes.update_or_create_resource(project, resource_data)

    for dependency_data in scan_data.get("dependencies", []):
        pipes.update_or_create_dependency(project, dependency_data)

    for relation_data in scan_data.get("relations", []):
        pipes.get_or_create_relation(project, relation_data)


model_to_object_maker_func = {
    DiscoveredPackage: pipes.update_or_create_package,
    DiscoveredDependency: pipes.update_or_create_dependency,
    DiscoveredLicense: pipes.update_or_create_license_detection,
    CodebaseResource: pipes.update_or_create_resource,
    CodebaseRelation: pipes.get_or_create_relation,
}

worksheet_name_to_model = {
    "PACKAGES": DiscoveredPackage,
    "LICENSE_DETECTIONS": DiscoveredLicense,
    "RESOURCES": CodebaseResource,
    "DEPENDENCIES": DiscoveredDependency,
    "RELATIONS": CodebaseRelation,
}


def get_worksheet_data(worksheet):
    """Return the data from provided ``worksheet`` as a list of dict."""
    try:
        header = [cell.value for cell in next(worksheet.rows)]
    except StopIteration:
        return {}

    worksheet_data = [
        dict(zip(header, row))
        for row in worksheet.iter_rows(min_row=2, values_only=True)
    ]
    return worksheet_data


def clean_xlsx_field_value(model_class, field_name, value):
    """Clean the ``value`` for compatibility with the database ``model_class``."""
    if value in EMPTY_VALUES:
        return

    if field_name == "for_packages":
        return value.splitlines()

    elif field_name in ["purl", "for_package_uid", "datafile_path"]:
        return value

    try:
        field = model_class._meta.get_field(field_name)
    except FieldDoesNotExist:
        return

    if dict_key := mappings_key_by_fieldname.get(field_name):
        return [{dict_key: entry} for entry in value.splitlines()]

    elif isinstance(field, models.JSONField):
        if field.default == list:
            return value.splitlines()
        elif field.default == dict:
            return  # dict stored as JSON are not supported

    return value


def clean_xlsx_data_to_model_data(model_class, xlsx_data):
    """Clean the ``xlsx_data`` for compatibility with the database ``model_class``."""
    cleaned_data = {}

    for field_name, value in xlsx_data.items():
        if cleaned_value := clean_xlsx_field_value(model_class, field_name, value):
            cleaned_data[field_name] = cleaned_value

    return cleaned_data


def load_inventory_from_xlsx(project, input_location):
    """
    Create packages, dependencies, resources, and relations loaded from XLSX file
    located at ``input_location``.
    """
    workbook = openpyxl.load_workbook(input_location, read_only=True, data_only=True)

    for worksheet_name, model_class in worksheet_name_to_model.items():
        if worksheet_name not in workbook:
            continue

        worksheet_data = get_worksheet_data(worksheet=workbook[worksheet_name])
        for row_data in worksheet_data:
            object_maker_func = model_to_object_maker_func.get(model_class)
            cleaned_data = clean_xlsx_data_to_model_data(model_class, row_data)
            if cleaned_data:
                object_maker_func(project, cleaned_data)
