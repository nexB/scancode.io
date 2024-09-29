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

import json
import re
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from pathlib import Path

SPDX_SPEC_VERSION = "2.3"
SPDX_LICENSE_LIST_VERSION = "3.20"
SPDX_SCHEMA_NAME = "spdx-schema-2.3.json"
SPDX_SCHEMA_PATH = Path(__file__).parent / "schemas" / SPDX_SCHEMA_NAME
SPDX_SCHEMA_URL = (
    "https://github.com/spdx/spdx-spec/raw/development/v2.3.1/schemas/spdx-schema.json"
)

"""
Generate SPDX Documents.
Spec documentation: https://spdx.github.io/spdx-spec/v2.3/

Usage::

    import pathlib
    from scanpipe.pipes import spdx

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
            spdx.Checksum(
                algorithm="SHA1", value="10c72b88de4c5f3095ebe20b4d8afbedb32b8f"
            ),
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
        """Return the data as a serializable dict."""
        data = {
            "created": self.created,
            "creators": self.get_creators_spdx(),
        }

        if self.license_list_version:
            data["licenseListVersion"] = self.license_list_version

        if self.comment:
            data["comment"] = self.comment

        return data

    @classmethod
    def from_data(cls, data):
        return cls(
            **cls.get_creators_dict(data.get("creators", [])),
            license_list_version=data.get("licenseListVersion"),
            comment=data.get("comment"),
            created=data.get("created"),
        )

    def get_creators_spdx(self):
        """Return the `creators` list from related field values."""
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

    @staticmethod
    def get_creators_dict(creators_data):
        """Return the `creators` dict from SPDX data."""
        creators_dict = {}

        for creator in creators_data:
            creator_type, value = creator.split(": ")
            creator_type = creator_type.lower()

            if creator_type == "tool":
                creators_dict["tool"] = value

            else:
                if "(" in value:
                    name, email = value.split(" (")
                    creators_dict[f"{creator_type}_name"] = name
                    creators_dict[f"{creator_type}_email"] = email.split(")")[0]
                else:
                    creators_dict[f"{creator_type}_name"] = value

        return creators_dict


@dataclass
class Checksum:
    """
    The checksum provides a mechanism that can be used to verify that the contents of
    a File or Package have not changed.
    """

    algorithm: str
    value: str

    def as_dict(self):
        """Return the data as a serializable dict."""
        return {
            "algorithm": self.algorithm.upper(),
            "checksumValue": self.value,
        }

    @classmethod
    def from_data(cls, data):
        return cls(
            algorithm=data.get("algorithm"),
            value=data.get("checksumValue"),
        )


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
        """Return the data as a serializable dict."""
        data = {
            "referenceCategory": self.category,
            "referenceType": self.type,
            "referenceLocator": self.locator,
        }

        if self.comment:
            data["comment"] = self.comment

        return data

    @classmethod
    def from_data(cls, data):
        return cls(
            category=data.get("referenceCategory"),
            type=data.get("referenceType"),
            locator=data.get("referenceLocator"),
            comment=data.get("comment"),
        )


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
        """Return the data as a serializable dict."""
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

    @classmethod
    def from_data(cls, data):
        return cls(
            license_id=data.get("licenseId"),
            extracted_text=data.get("extractedText"),
            name=data.get("name"),
            comment=data.get("comment"),
            see_alsos=data.get("seeAlsos"),
        )


@dataclass
class Package:
    """Packages referenced in the SPDX document."""

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
        """Return the data as a serializable dict."""
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
        """Convert a provided `date_str` to the SPDX format: `YYYY-MM-DDThh:mm:ssZ`."""
        if not date_str:
            return

        if date_str.endswith("Z"):
            date_str = date_str[:-1]

        as_datetime = datetime.fromisoformat(date_str)
        return as_datetime.isoformat(timespec="seconds") + "Z"

    @classmethod
    def from_data(cls, data):
        return cls(
            spdx_id=data.get("SPDXID"),
            name=data.get("name"),
            download_location=data.get("downloadLocation"),
            license_concluded=data.get("licenseConcluded"),
            copyright_text=data.get("copyrightText"),
            version=data.get("versionInfo"),
            license_declared=data.get("licenseDeclared"),
            supplier=data.get("supplier"),
            originator=data.get("originator"),
            homepage=data.get("homepage"),
            filename=data.get("packageFileName"),
            description=data.get("description"),
            summary=data.get("summary"),
            source_info=data.get("sourceInfo"),
            release_date=data.get("releaseDate"),
            built_date=data.get("builtDate"),
            valid_until_date=data.get("validUntilDate"),
            primary_package_purpose=data.get("primaryPackagePurpose"),
            comment=data.get("comment"),
            license_comments=data.get("licenseComments"),
            attribution_texts=data.get("attributionTexts"),
            checksums=[
                Checksum.from_data(checksum_data)
                for checksum_data in data.get("checksums", [])
            ],
            external_refs=[
                ExternalRef.from_data(external_ref_data)
                for external_ref_data in data.get("externalRefs", [])
            ],
        )


@dataclass
class File:
    """Files referenced in the SPDX document."""

    spdx_id: str
    name: str
    checksums: list[Checksum] = field(default_factory=list)

    license_concluded: str = "NOASSERTION"
    copyright_text: str = "NOASSERTION"
    license_in_files: list[str] = field(default_factory=list)
    contributors: list[str] = field(default_factory=list)
    notice_text: str = ""
    # Supported values:
    # SOURCE | BINARY | ARCHIVE | APPLICATION | AUDIO | IMAGE | TEXT | VIDEO |
    # DOCUMENTATION | SPDX | OTHER
    types: list[str] = field(default_factory=list)
    attribution_texts: list[str] = field(default_factory=list)
    comment: str = ""
    license_comments: str = ""

    def as_dict(self):
        """Return the data as a serializable dict."""
        required_data = {
            "SPDXID": self.spdx_id,
            "fileName": self.name,
            "checksums": [checksum.as_dict() for checksum in self.checksums],
        }

        optional_data = {
            "fileTypes": self.types,
            "copyrightText": self.copyright_text or "NOASSERTION",
            "fileContributors": self.contributors,
            "licenseConcluded": self.license_concluded or "NOASSERTION",
            "licenseInfoInFiles": self.license_in_files,
            "noticeText": self.notice_text,
            "comment": self.comment,
            "licenseComments": self.license_comments,
            "attributionTexts": self.attribution_texts,
        }

        optional_data = {key: value for key, value in optional_data.items() if value}
        return {**required_data, **optional_data}

    @classmethod
    def from_data(cls, data):
        return cls(
            spdx_id=data.get("SPDXID"),
            name=data.get("fileName"),
            checksums=[
                Checksum.from_data(checksum_data)
                for checksum_data in data.get("checksums", [])
            ],
            types=data.get("fileTypes"),
            copyright_text=data.get("copyrightText"),
            contributors=data.get("fileContributors"),
            license_concluded=data.get("licenseConcluded"),
            license_in_files=data.get("licenseInfoInFiles"),
            notice_text=data.get("noticeText"),
            comment=data.get("comment"),
            license_comments=data.get("licenseComments"),
            attribution_texts=data.get("attributionTexts"),
        )


@dataclass
class Relationship:
    """
    Represent the relationship between two SPDX elements.
    For example, you can represent a relationship between two different Files,
    between a Package and a File, between two Packages,
    or between one SPDXDocument and another SPDXDocument.
    """

    spdx_id: str
    related_spdx_id: str
    relationship: str

    comment: str = ""

    def as_dict(self):
        """Return the SPDX relationship as a serializable dict."""
        data = {
            "spdxElementId": self.spdx_id,
            "relatedSpdxElement": self.related_spdx_id,
            "relationshipType": self.relationship,
        }

        if self.comment:
            data["comment"] = self.comment

        return data

    @classmethod
    def from_data(cls, data):
        return cls(
            spdx_id=data.get("spdxElementId"),
            related_spdx_id=data.get("relatedSpdxElement"),
            relationship=data.get("relationshipType"),
            comment=data.get("comment"),
        )

    @property
    def is_dependency_relationship(self):
        """
        Return True if this relationship type implies that the spdx_id element
        is a dependency of related_spdx_id.
        """
        reverse_dependency_types = ["ANCESTOR_OF", "CONTAINS", "DEPENDS_ON"]
        # Every others types implies that the spdx_id element is a dependency of
        # related_spdx_id. Such as:
        # "DEPENDENCY_OF", "DESCENDANT_OF", "PACKAGE_OF", "CONTAINED_BY", ...
        return self.relationship.upper() not in reverse_dependency_types


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

    files: list[File] = field(default_factory=list)
    extracted_licenses: list[ExtractedLicensingInfo] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)

    def as_dict(self):
        """Return the SPDX document as a serializable dict."""
        data = {
            "spdxVersion": f"SPDX-{self.version}",
            "dataLicense": self.data_license,
            "SPDXID": self.spdx_id,
            "name": self.safe_document_name(self.name),
            "documentNamespace": self.namespace,
            "creationInfo": self.creation_info.as_dict(),
            "packages": [package.as_dict() for package in self.packages],
            "documentDescribes": [package.spdx_id for package in self.packages],
        }

        if self.files:
            data["files"] = [file.as_dict() for file in self.files]

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
        """Return the SPDX document as serialized JSON."""
        return json.dumps(self.as_dict(), indent=indent)

    @classmethod
    def from_data(cls, data):
        return cls(
            spdx_id=data.get("SPDXID"),
            version=data.get("spdxVersion", "").split("SPDX-")[-1],
            data_license=data.get("dataLicense"),
            name=data.get("name"),
            namespace=data.get("documentNamespace"),
            creation_info=CreationInfo.from_data(data.get("creationInfo", {})),
            packages=[
                Package.from_data(package_data)
                for package_data in data.get("packages", [])
            ],
            files=[File.from_data(file_data) for file_data in data.get("files", [])],
            extracted_licenses=[
                ExtractedLicensingInfo.from_data(license_info_data)
                for license_info_data in data.get("hasExtractedLicensingInfos", [])
            ],
            relationships=[
                Relationship.from_data(relationship_data)
                for relationship_data in data.get("relationships", [])
            ],
            comment=data.get("comment"),
        )

    @staticmethod
    def safe_document_name(name):
        """Convert provided `name` to a safe SPDX document name."""
        return re.sub("[^A-Za-z0-9.]+", "_", name).lower()

    def validate(self, schema):
        """Check the validity of this SPDX document."""
        return validate_document(document=self.as_dict(), schema=schema)


def validate_document(document, schema=SPDX_SCHEMA_PATH):
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

    if isinstance(schema, Path):
        schema = schema.read_text()
    if isinstance(schema, str):
        schema = json.loads(schema)

    jsonschema.validate(instance=document, schema=schema)


def is_spdx_document(input_location):
    """Return True if the file at `input_location` is a SPDX Document."""
    with suppress(Exception):
        data = json.loads(Path(input_location).read_text())
        if data.get("SPDXID"):
            return True
    return False
