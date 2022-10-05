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
import re
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime

SPDX_SPEC_VERSION = "2.3"
SPDX_LICENSE_LIST_VERSION = "3.18"
SPDX_JSON_SCHEMA_LOCATION = "spdx-schema-2.3.json"
SPDX_JSON_SCHEMA_URL = (
    "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json"
)

"""
Generate SPDX Documents
- Spec documentation: https://spdx.github.io/spdx-spec/v2.3/

Usage:

import pathlib
from dejacode_toolkit import spdx

creation_info = spdx.CreationInfo(
    person_name="John Doe",
    person_email="john@starship.space",
    organization_name="Starship",
    tool="SPDXCode-1.0",
)

package1 = spdx.Package(
    spdx_id="SPDXRef-package1",
    name="lxml",
    version="3.3.5",
    license_concluded="LicenseRef-1",
    checksums=[
        spdx.Checksum(algorithm="SHA1", value="10c72b88de4c5f3095ebe20b4d8afbedb32b8f"),
        spdx.Checksum(algorithm="MD5", value="56770c1a2df6e0dc51c491f0a5b9d865"),
    ],
    external_refs=[
        spdx.ExternalRef(
            category="PACKAGE-MANAGER",
            type="purl",
            locator="pkg:pypi/lxml@3.3.5",
        ),
    ]
)

document = spdx.Document(
    name="Document name",
    namespace="https://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]",
    creation_info=creation_info,
    packages=[package1],
    extracted_licenses=[
        spdx.ExtractedLicensingInfo(
            license_id="LicenseRef-1",
            extracted_text="License Text",
            name="License 1",
            see_alsos=["https://license1.text"],
        ),
    ],
    comment="This document was created using SPDXCode-1.0",
)

# Display document content:
print(document.as_json())

# Validate document
schema = pathlib.Path(spdx.SPDX_JSON_SCHEMA_LOCATION).read_text()
document.validate(schema)

# Write document to a file:
with open("document_name.spdx.json", "w") as f:
    f.write(document.as_json())
"""


@dataclass
class CreationInfo:
    """
    One instance is required for each SPDX file produced.
    It provides the necessary information for forward and backward compatibility for
    processing tools.
    """

    person_name: str = ""
    organization_name: str = ""
    tool: str = ""
    person_email: str = ""
    organization_email: str = ""
    license_list_version: str = SPDX_LICENSE_LIST_VERSION
    comment: str = ""

    """
    Identify when the SPDX document was originally created.
    The date is to be specified according to combined date and time in UTC format as
    specified in ISO 8601 standard.
    Format: YYYY-MM-DDThh:mm:ssZ
    """
    created: str = field(
        default_factory=lambda: datetime.utcnow().isoformat(timespec="seconds") + "Z",
    )

    def as_dict(self):
        """
        Return the data as a serializable dict.
        """
        data = {
            "created": self.created,
            "creators": self.get_creators(),
        }

        if self.license_list_version:
            data["licenseListVersion"] = self.license_list_version

        if self.comment:
            data["comment"] = self.comment

        return data

    def get_creators(self):
        """
        Return the `creators` list from related field values.
        """
        creators = []

        if self.person_name:
            creators.append(f"Person: {self.person_name} ({self.person_email})")

        if self.organization_name:
            creators.append(
                f"Organization: {self.organization_name} ({self.organization_email})"
            )

        if self.tool:
            creators.append(f"Tool: {self.tool}")

        if not creators:
            raise ValueError("Missing values to build `creators` list.")

        return creators


@dataclass
class Checksum:
    """
    The checksum provides a mechanism that can be used to verify that the contents of
    a File or Package have not changed.
    """

    algorithm: str
    value: str

    def as_dict(self):
        """
        Return the data as a serializable dict.
        """
        return {
            "algorithm": self.algorithm.upper(),
            "checksumValue": self.value,
        }


@dataclass
class ExternalRef:
    """
    An External Reference allows a Package to reference an external source of
    additional information, metadata, enumerations, asset identifiers, or
    downloadable content believed to be relevant to the Package.
    """

    category: str  # Supported values: OTHER, SECURITY, PERSISTENT-ID, PACKAGE-MANAGER
    type: str
    locator: str

    comment: str = ""

    def as_dict(self):
        """
        Return the data as a serializable dict.
        """
        data = {
            "referenceCategory": self.category,
            "referenceType": self.type,
            "referenceLocator": self.locator,
        }

        if self.comment:
            data["comment"] = self.comment

        return data


@dataclass
class ExtractedLicensingInfo:
    """
    An ExtractedLicensingInfo represents a license or licensing notice that was found
    in a package, file or snippet.
    Any license text that is recognized as a license may be represented as a License
    rather than an ExtractedLicensingInfo.
    """

    license_id: str
    extracted_text: str

    name: str = ""
    comment: str = ""
    see_alsos: list[str] = field(default_factory=list)

    def as_dict(self):
        """
        Return the data as a serializable dict.
        """
        required_data = {
            "licenseId": self.license_id,
            "extractedText": self.extracted_text,
        }

        optional_data = {
            "name": self.name,
            "comment": self.comment,
            "seeAlsos": self.see_alsos,
        }

        optional_data = {key: value for key, value in optional_data.items() if value}
        return {**required_data, **optional_data}


@dataclass
class Package:
    """
    Packages referenced in the SPDX document.
    """

    spdx_id: str
    name: str

    download_location: str = "NOASSERTION"
    license_declared: str = "NOASSERTION"
    license_concluded: str = "NOASSERTION"
    copyright_text: str = "NOASSERTION"
    files_analyzed: bool = False

    version: str = ""
    supplier: str = ""
    originator: str = ""
    homepage: str = ""
    filename: str = ""
    description: str = ""
    summary: str = ""
    source_info: str = ""
    release_date: str = ""
    built_date: str = ""
    valid_until_date: str = ""
    # Supported values:
    # APPLICATION | FRAMEWORK | LIBRARY | CONTAINER | OPERATING-SYSTEM |
    # DEVICE | FIRMWARE | SOURCE | ARCHIVE | FILE | INSTALL | OTHER
    primary_package_purpose: str = ""
    comment: str = ""
    license_comments: str = ""

    checksums: list[Checksum] = field(default_factory=list)
    external_refs: list[ExternalRef] = field(default_factory=list)
    attribution_texts: list[str] = field(default_factory=list)

    def as_dict(self):
        """
        Return the data as a serializable dict.
        """
        spdx_id = str(self.spdx_id)
        if not spdx_id.startswith("SPDXRef-"):
            spdx_id = f"SPDXRef-{spdx_id}"

        required_data = {
            "name": self.name,
            "SPDXID": spdx_id,
            "downloadLocation": self.download_location or "NOASSERTION",
            "licenseConcluded": self.license_concluded or "NOASSERTION",
            "copyrightText": self.copyright_text or "NOASSERTION",
            "filesAnalyzed": self.files_analyzed,
        }

        optional_data = {
            "versionInfo": self.version,
            "licenseDeclared": self.license_declared,
            "supplier": self.supplier,
            "originator": self.originator,
            "homepage": self.homepage,
            "packageFileName": self.filename,
            "description": self.description,
            "summary": self.summary,
            "sourceInfo": self.source_info,
            "releaseDate": self.date_to_iso(self.release_date),
            "builtDate": self.date_to_iso(self.built_date),
            "validUntilDate": self.date_to_iso(self.valid_until_date),
            "primaryPackagePurpose": self.primary_package_purpose,
            "comment": self.comment,
            "licenseComments": self.license_comments,
            "checksums": [checksum.as_dict() for checksum in self.checksums],
            "externalRefs": [ref.as_dict() for ref in self.external_refs],
            "attributionTexts": self.attribution_texts,
        }

        optional_data = {key: value for key, value in optional_data.items() if value}
        return {**required_data, **optional_data}

    @staticmethod
    def date_to_iso(date_str):
        """
        Convert a provided `date_str` to the SPDX format: `YYYY-MM-DDThh:mm:ssZ`.
        """
        if not date_str:
            return

        as_datetime = datetime.fromisoformat(date_str)
        return as_datetime.isoformat(timespec="seconds") + "Z"


@dataclass
class Relationship:
    """
    This field provides information about the relationship between two SPDX elements.
    For example, you can represent a relationship between two different Files,
    between a Package and a File, between two Packages,
    or between one SPDXDocument and another SPDXDocument.
    """

    spdx_id: str
    related_spdx_id: str
    relationship: str

    comment: str = ""

    def as_dict(self):
        """
        Return the SPDX relationship as a serializable dict.
        """
        data = {
            "spdxElementId": self.spdx_id,
            "relatedSpdxElement": self.related_spdx_id,
            "relationshipType": self.relationship,
        }

        if self.comment:
            data["comment"] = self.comment

        return data


@dataclass
class Document:
    """
    Collection of section instances each of which contains information about software
    organized using the SPDX format.
    """

    name: str
    namespace: str
    creation_info: CreationInfo
    packages: list[Package]

    spdx_id: str = "SPDXRef-DOCUMENT"
    version: str = SPDX_SPEC_VERSION
    data_license: str = "CC0-1.0"
    comment: str = ""

    extracted_licenses: list[ExtractedLicensingInfo] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)

    def as_dict(self):
        """
        Return the SPDX document as a serializable dict.
        """
        packages = [package.as_dict() for package in self.packages]

        data = {
            "spdxVersion": f"SPDX-{self.version}",
            "dataLicense": self.data_license,
            "SPDXID": self.spdx_id,
            "name": self.safe_document_name(self.name),
            "documentNamespace": self.namespace,
            "creationInfo": self.creation_info.as_dict(),
            "packages": packages,
            "documentDescribes": [self.spdx_id],
        }

        if self.extracted_licenses:
            data["hasExtractedLicensingInfos"] = [
                license_info.as_dict() for license_info in self.extracted_licenses
            ]

        if self.relationships:
            data["relationships"] = [
                relationship.as_dict() for relationship in self.relationships
            ]

        if self.comment:
            data["comment"] = self.comment

        return data

    def as_json(self, indent=2):
        """
        Return the SPDX document as serialized JSON.
        """
        return json.dumps(self.as_dict(), indent=indent)

    @staticmethod
    def safe_document_name(name):
        """
        Convert provided `name` to a safe SPDX document name.
        """
        return re.sub("[^A-Za-z0-9.]+", "_", name).lower()

    def validate(self, schema):
        """
        Check the validation of this SPDX document.
        """
        return validate_document(document=self.as_dict(), schema=schema)


def validate_document(document, schema):
    """
    SPDX document validation.
    Requires the `jsonschema` library.
    """
    try:
        import jsonschema
    except ModuleNotFoundError:
        print(
            "The `jsonschema` library is required to run the validation.\n"
            "Install with: `pip install jsonschema`"
        )
        raise

    if isinstance(document, str):
        document = json.loads(document)
    if isinstance(document, Document):
        document = document.as_dict()

    if isinstance(schema, str):
        schema = json.loads(schema)

    jsonschema.validate(instance=document, schema=schema)
