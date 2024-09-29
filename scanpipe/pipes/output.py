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

import csv
import decimal
import json
import re
from operator import attrgetter
from pathlib import Path

from django.apps import apps
from django.core.serializers.json import DjangoJSONEncoder
from django.forms.models import model_to_dict
from django.template import Context
from django.template import Template

import saneyaml
import xlsxwriter
from cyclonedx.model import bom as cdx_bom
from cyclonedx.model import component as cdx_component
from cyclonedx.model import vulnerability as cdx_vulnerability
from cyclonedx.output import OutputFormat
from cyclonedx.output import make_outputter
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from license_expression import Licensing
from license_expression import ordered_unique
from licensedcode.cache import build_spdx_license_expression
from licensedcode.cache import get_licenses_by_spdx_key
from licensedcode.cache import get_licensing
from licensedcode.models import License
from scancode_config import __version__ as scancode_toolkit_version

from scancodeio import SCAN_NOTICE
from scancodeio import __version__ as scancodeio_version
from scanpipe.pipes import docker
from scanpipe.pipes import spdx

scanpipe_app = apps.get_app_config("scanpipe")


def safe_filename(filename):
    """Convert the provided `filename` to a safe filename."""
    return re.sub("[^A-Za-z0-9.-]+", "_", filename).lower()


def get_queryset(project, model_name):
    """Return a consistent QuerySet for all supported outputs (json, xlsx, csv, ...)"""
    querysets = {
        "discoveredpackage": (
            project.discoveredpackages.all().order_by(
                "type",
                "namespace",
                "name",
                "version",
            )
        ),
        "discovereddependency": (
            project.discovereddependencies.all()
            .prefetch_for_serializer()
            .order_by(
                "type",
                "namespace",
                "name",
                "version",
                "datasource_id",
            )
        ),
        "codebaseresource": (
            project.codebaseresources.without_symlinks().prefetch_for_serializer()
        ),
        "codebaserelation": (
            project.codebaserelations.select_related("from_resource", "to_resource")
        ),
        "projectmessage": project.projectmessages.all(),
    }
    return querysets.get(model_name)


def queryset_to_csv_file(queryset, fieldnames, output_file):
    """
    Output csv content generated from the provided `queryset` objects to the
    `output_file`.
    The fields to be included as columns and their order are controlled by the
    `fieldnames` list.
    """
    writer = csv.DictWriter(output_file, fieldnames)
    writer.writeheader()

    for record in queryset.iterator(chunk_size=2000):
        row = {field: getattr(record, field) for field in fieldnames}
        writer.writerow(row)


def queryset_to_csv_stream(queryset, fieldnames, output_stream):
    """
    Output csv content generated from the provided `queryset` objects to the
    `output_stream`.
    The fields to be included as columns and their order are controlled by the
    `fieldnames` list.
    """
    writer = csv.DictWriter(output_stream, fieldnames)
    # Not using writer.writeheader() since this method do not "return" the
    # value while writer.writerow() does.
    header = dict(zip(fieldnames, fieldnames))
    yield writer.writerow(header)

    for record in queryset.iterator(chunk_size=2000):
        row = {field: getattr(record, field) for field in fieldnames}
        yield writer.writerow(row)


def to_csv(project):
    """
    Generate output for the provided `project` in csv format.
    Since the csv format does not support multiple tabs, one file is created
    per object type.
    The output files are created in the `project` output/ directory.
    Return a list of paths of the generated output files.
    """
    from scanpipe.api.serializers import get_serializer_fields

    model_names = [
        "discoveredpackage",
        "discovereddependency",
        "codebaseresource",
        "projectmessage",
    ]

    output_files = []

    for model_name in model_names:
        queryset = get_queryset(project, model_name)
        model_class = queryset.model
        fieldnames = get_serializer_fields(model_class)
        output_filename = project.get_output_file_path(f"{model_name}", "csv")

        with output_filename.open("w") as output_file:
            queryset_to_csv_file(queryset, fieldnames, output_file)

        output_files.append(output_filename)

    return output_files


class JSONResultsGenerator:
    """
    Return the `project` JSON results as a Python generator.
    Use this class to stream the results from the database to the client browser
    without having to load everything in memory first.

    Note that the Django Serializer class can output to a stream but can't be
    sent directly to a StreamingHttpResponse.
    The results would have to be streamed to a file first, then iterated by the
    StreamingHttpResponse, which do not work great in a HTTP request context as
    the request can time out while the file is generated.

    This class re-use Serializers from the API to avoid code duplication.
    Those imports need to be kept internal to this class to prevent circular import
    issues.
    """

    def __init__(self, project):
        self.project = project

    def __iter__(self):
        yield "{\n"
        yield from self.serialize(label="headers", generator=self.get_headers)
        yield from self.serialize(label="packages", generator=self.get_packages)
        yield from self.serialize(label="dependencies", generator=self.get_dependencies)
        yield from self.serialize(label="files", generator=self.get_files)
        yield from self.serialize(
            label="relations", generator=self.get_relations, latest=True
        )
        yield "}"

    def serialize(self, label, generator, latest=False):
        yield f'"{label}": [\n'

        prefix = ",\n"
        first = True

        for entry in generator(self.project):
            if first:
                first = False
            else:
                entry = prefix + entry
            yield entry

        yield "]\n" if latest else "],\n"

    @staticmethod
    def encode(data):
        return json.dumps(data, indent=2, cls=DjangoJSONEncoder)

    def get_headers(self, project):
        from scanpipe.api.serializers import RunSerializer

        runs = project.runs.all()
        runs = RunSerializer(runs, many=True, exclude_fields=("url", "project"))

        other_tools = [f"pkg:pypi/scancode-toolkit@{scancode_toolkit_version}"]

        headers = {
            "tool_name": "scanpipe",
            "tool_version": scancodeio_version,
            "other_tools": other_tools,
            "notice": SCAN_NOTICE,
            "uuid": project.uuid,
            "created_date": project.created_date,
            "notes": project.notes,
            "settings": project.settings,
            "input_sources": project.get_inputs_with_source(),
            "runs": runs.data,
            "extra_data": project.extra_data,
        }
        yield self.encode(headers)

    def encode_queryset(self, project, model_name, serializer):
        queryset = get_queryset(project, model_name)
        for obj in queryset.iterator(chunk_size=2000):
            yield self.encode(serializer(obj).data)

    def get_packages(self, project):
        from scanpipe.api.serializers import DiscoveredPackageSerializer

        yield from self.encode_queryset(
            project, "discoveredpackage", DiscoveredPackageSerializer
        )

    def get_dependencies(self, project):
        from scanpipe.api.serializers import DiscoveredDependencySerializer

        yield from self.encode_queryset(
            project, "discovereddependency", DiscoveredDependencySerializer
        )

    def get_files(self, project):
        from scanpipe.api.serializers import CodebaseResourceSerializer

        yield from self.encode_queryset(
            project, "codebaseresource", CodebaseResourceSerializer
        )

    def get_relations(self, project):
        from scanpipe.api.serializers import CodebaseRelationSerializer

        yield from self.encode_queryset(
            project, "codebaserelation", CodebaseRelationSerializer
        )


def to_json(project):
    """
    Generate output for the provided `project` in JSON format.
    The output file is created in the `project` output/ directory.
    Return the path of the generated output file.
    """
    results_generator = JSONResultsGenerator(project)
    output_file = project.get_output_file_path("results", "json")

    with output_file.open("w") as file:
        for chunk in results_generator:
            file.write(chunk)

    return output_file


model_name_to_worksheet_name = {
    "discoveredpackage": "PACKAGES",
    "discovereddependency": "DEPENDENCIES",
    "codebaseresource": "RESOURCES",
    "codebaserelation": "RELATIONS",
    "projectmessage": "MESSAGES",
}


def queryset_to_xlsx_worksheet(queryset, workbook, exclude_fields=()):
    """
    Add a new worksheet to the ``workbook`` ``xlsxwriter.Workbook`` using the
    ``queryset``. The ``queryset`` "model_name" is used as a name for the
    "worksheet".
    Exclude fields listed in the ``exclude_fields`` sequence of field names.

    Add an extra trailing "xlsx_errors" column with conversion error messages if
    any. Return a number of conversion errors.
    """
    from scanpipe.api.serializers import get_serializer_fields

    model_class = queryset.model
    model_name = model_class._meta.model_name
    worksheet_name = model_name_to_worksheet_name.get(model_name)

    fields = get_serializer_fields(model_class)
    exclude_fields = exclude_fields or []
    fields = [field for field in fields if field not in exclude_fields]

    return _add_xlsx_worksheet(
        workbook=workbook,
        worksheet_name=worksheet_name,
        rows=queryset,
        fields=fields,
    )


def _add_xlsx_worksheet(workbook, worksheet_name, rows, fields):
    """
    Add a new ``worksheet_name`` worksheet to the ``workbook``
    ``xlsxwriter.Workbook``. Write the iterable of ``rows`` objects using their
    attributes listed in the ``fields`` sequence of field names.
    Add a "xlsx_errors" column with conversion error messages if any.
    Return a number of conversion errors.
    """
    worksheet = workbook.add_worksheet(worksheet_name)
    worksheet.set_default_row(height=14)

    header = list(fields) + ["xlsx_errors"]
    worksheet.write_row(row=0, col=0, data=header)

    errors_count = 0
    errors_col_index = len(fields) - 1  # rows and cols are zero-indexed

    for row_index, record in enumerate(rows, start=1):
        row_errors = []
        for col_index, field in enumerate(fields):
            value = getattr(record, field)

            if not value:
                continue

            value, error = _adapt_value_for_xlsx(field, value)

            if error:
                row_errors.append(error)

            if value:
                worksheet.write_string(row_index, col_index, str(value))

        if row_errors:
            errors_count += len(row_errors)
            row_errors = "\n".join(row_errors)
            worksheet.write_string(row_index, errors_col_index, row_errors)

    return errors_count


# Some scan attributes such as "copyrights" are list of dicts.
#
#  'authors': [{'end_line': 7, 'start_line': 7, 'author': 'John Doe'}],
#  'copyrights': [{'end_line': 5, 'start_line': 5, 'copyright': 'Copyright (c) nexB'}],
#  'emails': [{'email': 'joe@foobar.com', 'end_line': 1, 'start_line': 1}],
#  'holders': [{'end_line': 5, 'start_line': 5, 'holder': 'nexB Inc.'}],
#  'urls': [{'end_line': 3, 'start_line': 3, 'url': 'https://foobar.com/'}]
#
# We therefore use a mapping to find which key to use:
mappings_key_by_fieldname = {
    "copyrights": "copyright",
    "holders": "holder",
    "authors": "author",
    "emails": "email",
    "urls": "url",
}


def _adapt_value_for_xlsx(fieldname, value, maximum_length=32767, _adapt=True):
    """
    Return two tuples of:
    (``value`` adapted for use in an XLSX cell, error message or None)

    Convert the value to a string and perform these adaptations:
    - Keep only unique values in lists, preserving ordering.
    - Truncate the "description" field to the first five lines.
    - Truncate any field too long to fit in an XLSX cell and report error.
    - Create a combined license expression for expressions
    - Normalize line endings
    - Truncate the value to a ``maximum_length`` supported by XLSX.

    Does nothing if "_adapt" is False (used for tests).
    """
    error = None
    if not _adapt:
        return value, error

    if not value:
        return "", error

    if fieldname == "description":
        max_description_lines = 5
        value = "\n".join(value.splitlines(False)[:max_description_lines])

    # we only get this key in each dict of a list for some fields
    mapping_key = mappings_key_by_fieldname.get(fieldname)
    if mapping_key:
        value = [mapping[mapping_key] for mapping in value]

    # convert these to text lines, remove duplicates
    if isinstance(value, list | tuple):
        value = ordered_unique(str(v) for v in value if v)
        value = "\n".join(value)

    # convert these to YAML which is the most readable dump format
    if isinstance(value, dict):
        value = saneyaml.dump(value)

    value = str(value)

    # XLSX does not like CRLF
    value = value.replace("\r\n", "\n")

    # XLSX does not like long values
    len_val = len(value)
    if len_val > maximum_length:
        error = (
            f"The value of: {fieldname} has been truncated from: {len_val} "
            f"to {maximum_length} length to fit in an XLSX cell maximum length"
        )
        value = value[:maximum_length]

    return value, error


def to_xlsx(project):
    """
    Generate output for the provided ``project`` in XLSX format.
    The output file is created in the ``project`` "output/" directory.
    Return the path of the generated output file.

    Note that the XLSX worksheets contain each an extra "xlsx_errors" column
    with possible error messages for a row when converting the data to XLSX
    exceed the limits of what can be stored in a cell.
    """
    output_file = project.get_output_file_path("results", "xlsx")
    exclude_fields = [
        "extra_data",
        "package_data",
        "license_detections",
        "other_license_detections",
        "license_clues",
    ]

    if not scanpipe_app.policies_enabled:
        exclude_fields.append("compliance_alert")

    model_names = [
        "discoveredpackage",
        "discovereddependency",
        "codebaseresource",
        "codebaserelation",
        "projectmessage",
    ]

    with xlsxwriter.Workbook(output_file) as workbook:
        for model_name in model_names:
            queryset = get_queryset(project, model_name)
            queryset_to_xlsx_worksheet(queryset, workbook, exclude_fields)

        if layers_data := docker.get_layers_data(project):
            _add_xlsx_worksheet(workbook, "LAYERS", layers_data, docker.layer_fields)

    return output_file


def _get_spdx_extracted_licenses(license_expressions):
    """
    Generate and return the SPDX `extracted_licenses` from provided
    `license_expressions` list of expressions.
    """
    licensing = Licensing()
    license_index = get_licenses_by_spdx_key()
    urls_fields = [
        "licensedb_url",
        "scancode_url",
        "faq_url",
        "homepage_url",
        "osi_url",
        "ignorable_urls",
        "other_urls",
        "text_urls",
    ]
    spdx_license_refs = set()
    extracted_licenses = []

    for expression in license_expressions:
        spdx_expression = build_spdx_license_expression(expression)
        license_keys = licensing.license_keys(spdx_expression)
        spdx_license_refs.update(
            [key for key in license_keys if key.startswith("LicenseRef")]
        )

    for license_ref in spdx_license_refs:
        license = license_index.get(license_ref.lower())

        see_alsos = []
        for field_name in urls_fields:
            value = getattr(license, field_name)
            if isinstance(value, list):
                see_alsos.extend(value)
            elif value:
                see_alsos.append(value)

        extracted_licenses.append(
            spdx.ExtractedLicensingInfo(
                license_id=license.spdx_license_key,
                extracted_text=license.text or " ",
                name=license.name,
                see_alsos=see_alsos,
            )
        )

    return extracted_licenses


def get_dependency_as_spdx_relationship(dependency, document_spdx_id, packages_as_spdx):
    """Return a spdx.Relationship crafted from the provided ``dependency`` instance."""
    if dependency.is_for_package:  # Package dependency
        parent_id = dependency.for_package.spdx_id
    else:  # Project dependency
        parent_id = document_spdx_id

    if dependency.is_resolved_to_package:  # Resolved to a Package
        child_id = dependency.resolved_to_package.spdx_id
    else:  # Not resolved to a Package (only package_url value is available)
        dependency_as_package = dependency.as_spdx_package()
        packages_as_spdx.append(dependency_as_package)
        child_id = dependency_as_package.spdx_id

    spdx_relationship = spdx.Relationship(
        spdx_id=child_id,
        related_spdx_id=parent_id,
        relationship="DEPENDENCY_OF",
    )
    return spdx_relationship


def to_spdx(project, include_files=False):
    """
    Generate output for the provided ``project`` in SPDX document format.
    The output file is created in the ``project`` "output/" directory.
    Return the path of the generated output file.
    """
    output_file = project.get_output_file_path("results", "spdx.json")

    discoveredpackage_qs = get_queryset(project, "discoveredpackage")
    discovereddependency_qs = get_queryset(project, "discovereddependency")

    document_spdx_id = f"SPDXRef-DOCUMENT-{project.uuid}"
    packages_as_spdx = []
    license_expressions = []
    relationships = []

    for package in discoveredpackage_qs:
        packages_as_spdx.append(package.as_spdx())
        if license_expression := package.declared_license_expression:
            license_expressions.append(license_expression)

    for dependency in discovereddependency_qs:
        spdx_relationship = get_dependency_as_spdx_relationship(
            dependency,
            document_spdx_id,
            packages_as_spdx,
        )
        relationships.append(spdx_relationship)

    files_as_spdx = []
    if include_files:
        files_as_spdx = [
            resource.as_spdx()
            for resource in get_queryset(project, "codebaseresource").files()
        ]

    document = spdx.Document(
        spdx_id=document_spdx_id,
        name=f"scancodeio_{project.name}",
        namespace=f"https://scancode.io/spdxdocs/{project.uuid}",
        creation_info=spdx.CreationInfo(tool=f"ScanCode.io-{scancodeio_version}"),
        packages=packages_as_spdx,
        files=files_as_spdx,
        extracted_licenses=_get_spdx_extracted_licenses(license_expressions),
        relationships=relationships,
        comment=SCAN_NOTICE,
    )

    with output_file.open("w") as file:
        file.write(document.as_json())

    return output_file


def vulnerability_as_cyclonedx(vulnerability_data, component_bom_ref):
    affects = [cdx_vulnerability.BomTarget(ref=f"urn:cdx:{component_bom_ref}")]

    source = cdx_vulnerability.VulnerabilitySource(
        name="VulnerableCode",
        url=vulnerability_data.get("url"),
    )

    references = []
    ratings = []
    for reference in vulnerability_data.get("references", []):
        source = cdx_vulnerability.VulnerabilitySource(
            url=reference.get("reference_url"),
        )

        references.append(
            cdx_vulnerability.VulnerabilityReference(
                id=reference.get("reference_id"),
                source=source,
            )
        )

        for score_entry in reference.get("scores", []):
            # CycloneDX only support a float value for the score field,
            # where on the VulnerableCode data it can be either a score float value
            # or a severity string value.
            score_value = score_entry.get("value")
            try:
                score = decimal.Decimal(score_value)
                severity = None
            except decimal.DecimalException:
                score = None
                severity = getattr(
                    cdx_vulnerability.VulnerabilitySeverity,
                    score_value.upper(),
                    None,
                )

            ratings.append(
                cdx_vulnerability.VulnerabilityRating(
                    source=source,
                    score=score,
                    severity=severity,
                    # Providing a value for method raise a AssertionError
                    # method=score_entry.get("scoring_system"),
                    vector=score_entry.get("scoring_elements"),
                )
            )

    cwes = [
        weakness.get("cwe_id") for weakness in vulnerability_data.get("weaknesses", [])
    ]

    return cdx_vulnerability.Vulnerability(
        id=vulnerability_data.get("vulnerability_id"),
        source=source,
        description=vulnerability_data.get("summary"),
        affects=affects,
        references=references,
        cwes=cwes,
        ratings=ratings,
    )


def get_cyclonedx_bom(project):
    """
    Return a CycloneDX `Bom` object filled with provided `project` data.
    See https://cyclonedx.org/use-cases/#dependency-graph
    """
    project_as_root_component = cdx_component.Component(
        name=project.name,
        bom_ref=str(project.uuid),
    )

    bom = cdx_bom.Bom()
    bom.metadata = cdx_bom.BomMetaData(
        component=project_as_root_component,
        tools=[
            cdx_bom.Tool(
                name="ScanCode.io",
                version=scancodeio_version,
            )
        ],
        properties=[
            cdx_bom.Property(
                name="notice",
                value=SCAN_NOTICE,
            )
        ],
    )

    vulnerabilities = []
    dependencies = {}

    package_qs = get_queryset(project, "discoveredpackage")
    package_qs = package_qs.prefetch_related("children_packages")

    for package in package_qs:
        component = package.as_cyclonedx()
        bom.components.add(component)
        bom.register_dependency(project_as_root_component, [component])

        # Store the component dependencies to be added later since all components need
        # to be added on the BOM first.
        dependencies[component] = [
            package.cyclonedx_bom_ref for package in package.children_packages.all()
        ]

        for vulnerability_data in package.affected_by_vulnerabilities:
            vulnerabilities.append(
                vulnerability_as_cyclonedx(vulnerability_data, component.bom_ref)
            )

    for component, depends_on_bom_refs in dependencies.items():
        if not depends_on_bom_refs:
            continue
        # Craft disposable Component instances for registering dependencies
        dependencies = [
            cdx_component.Component(name="", bom_ref=ref) for ref in depends_on_bom_refs
        ]
        bom.register_dependency(component, dependencies)

    bom.vulnerabilities = vulnerabilities

    return bom


def sort_bom_with_schema_ordering(bom_as_dict, schema_version):
    """Sort the ``bom_as_dict`` using the ordering from the ``schema_version``."""
    schema_file = JsonStrictValidator(schema_version)._schema_file
    with open(schema_file) as sf:
        schema_dict = json.loads(sf.read())

    order_from_schema = list(schema_dict.get("properties", {}).keys())
    ordered_dict = {
        key: bom_as_dict.get(key) for key in order_from_schema if key in bom_as_dict
    }

    return json.dumps(ordered_dict, indent=2)


def to_cyclonedx(project, version="1.6"):
    """
    Generate output for the provided ``project`` in CycloneDX BOM format.
    The output file is created in the ``project`` "output/" directory.
    Return the path of the generated output file.
    """
    schema_version = SchemaVersion.from_version(version)
    output_file = project.get_output_file_path("results", "cdx.json")

    bom = get_cyclonedx_bom(project)
    json_outputter = make_outputter(bom, OutputFormat.JSON, schema_version)

    # Using the internal API in place of the output_as_string() method to avoid
    # a round of deserialization/serialization while fixing the field ordering.
    json_outputter.generate()
    bom_as_dict = json_outputter._bom_json

    # The default order out of the outputter is not great, the following sorts the
    # bom using the order from the schema.
    sorted_json = sort_bom_with_schema_ordering(bom_as_dict, schema_version)

    with output_file.open("w") as file:
        file.write(sorted_json)

    return output_file


def get_expression_as_attribution_links(parsed_expression):
    template = '<a href="#license_{symbol.key}">{symbol.wrapped.spdx_license_key}</a>'
    return parsed_expression.simplify().render(template=template)


def render_template(template_string, context):
    """Render a Django ``template_string`` using the ``context`` dict."""
    return Template(template_string).render(Context(context))


def render_template_file(template_location, context):
    """Render a Django template at ``template_location`` using the ``context`` dict."""
    template_string = Path(template_location).read_text()
    return render_template(template_string, context)


def get_attribution_template(project):
    """Return a custom attribution template if provided or the default one."""
    if config_directory := project.get_codebase_config_directory():
        custom_template = config_directory / "templates" / "attribution.html"
        if custom_template.exists():
            return custom_template

    scanpipe_templates = Path(scanpipe_app.path) / "templates"
    default_template = scanpipe_templates / "scanpipe" / "attribution.html"
    return default_template


def make_unknown_license_object(license_symbol):
    """
    Return a ``License`` object suitable for the provided ``license_symbol``,
    that is representing a license key unknown by the current toolkit licensed index.
    """
    mocked_spdx_license_key = f"LicenseRef-unknown-{license_symbol.key}"
    return License(
        key=license_symbol.key,
        spdx_license_key=mocked_spdx_license_key,
        text="ERROR: Unknown license key, no text available.",
        is_builtin=False,
    )


def get_package_expression_symbols(parsed_expression):
    """
    Return the list of ``license_symbols`` contained in the ``parsed_expression``.
    Since unknown license keys are missing a ``License`` set in the ``wrapped``
    attribute, a special "unknown" ``License`` object is injected.
    """
    license_symbols = []

    for parsed_symbol in parsed_expression.symbols:
        # .decompose() is required for LicenseWithExceptionSymbol support
        for license_symbol in parsed_symbol.decompose():
            if not hasattr(license_symbol, "wrapped"):
                license_symbol.wrapped = make_unknown_license_object(license_symbol)
            license_symbols.append(license_symbol)

    return license_symbols


def get_package_data_for_attribution(package, licensing):
    """
    Convert the ``package`` instance into a dictionary of values usable during
    attribution generation.
    """
    package_data = model_to_dict(package, exclude=["codebase_resources"])
    package_data["package_url"] = package.package_url

    if license_expression := package.declared_license_expression:
        parsed = licensing.parse(license_expression)
        license_symbols = get_package_expression_symbols(parsed)

        package_licenses = [symbol.wrapped for symbol in set(license_symbols)]
        package_data["licenses"] = package_licenses

        expression_links = get_expression_as_attribution_links(parsed)
        package_data["expression_links"] = expression_links

    return package_data


def get_unique_licenses(packages):
    """
    Return a list of unique License symbol objects preserving ordering.
    Return an empty list if the packages do not have licenses.

    Replace by the following one-liner once this toolkit issues is fixed:
    https://github.com/aboutcode-org/scancode-toolkit/issues/3425
    licenses = set(license for package in packages for license in package["licenses"])
    """
    seen_license_keys = set()
    licenses = []

    for package in packages:
        for license in package.get("licenses") or []:
            if license.key not in seen_license_keys:
                seen_license_keys.add(license.key)
                licenses.append(license)

    return licenses


def to_attribution(project):
    """
    Generate attribution for the provided ``project``.
    The output file is created in the ``project`` "output/" directory.
    Return the path of the generated output file.

    Custom template can be provided in the
    `codebase/.scancode/templates/attribution.html` location.

    The model instances are converted into data dict to prevent any data leak as the
    attribution template is customizable.
    """
    output_file = project.get_output_file_path("results", "attribution.html")

    project_data = model_to_dict(project, fields=["name", "notes", "created_date"])

    licensing = get_licensing()
    packages = [
        get_package_data_for_attribution(package, licensing)
        for package in get_queryset(project, "discoveredpackage")
    ]

    licenses = get_unique_licenses(packages)
    licenses = sorted(licenses, key=attrgetter("spdx_license_key"))

    context = {
        "project": project_data,
        "packages": packages,
        "licenses": licenses,
    }

    if template_string := project.get_env("attribution_template"):
        rendered_template = render_template(template_string, context)
    else:
        template_location = get_attribution_template(project)
        rendered_template = render_template_file(template_location, context)

    output_file.write_text(rendered_template)
    return output_file
