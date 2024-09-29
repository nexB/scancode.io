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

from pathlib import Path
from unittest import TestCase

from scanpipe.pipes import spdx


class ScanPipeSPDXPipesTest(TestCase):
    data = Path(__file__).parent.parent / "data"

    def setUp(self):
        self.schema = spdx.SPDX_SCHEMA_PATH.read_text()

        self.creation_info_data = {
            "person_name": "John Doe",
            "person_email": "john@starship.space",
            "organization_name": "Starship",
            "tool": "SPDXCode-1.0",
            "comment": "Generated with SPDXCode",
            "created": "2022-09-21T13:50:20Z",
        }
        self.creation_info_spdx_data = {
            "created": "2022-09-21T13:50:20Z",
            "creators": [
                "Person: John Doe (john@starship.space)",
                "Organization: Starship ()",
                "Tool: SPDXCode-1.0",
            ],
            "licenseListVersion": "3.20",
            "comment": "Generated with SPDXCode",
        }
        self.checksum_sha1_data = {
            "algorithm": "SHA1",
            "value": "10c72b88de4c5f3095ebe20b4d8afbedb32b8f",
        }
        self.checksum_sha1_spdx_data = {
            "algorithm": "SHA1",
            "checksumValue": "10c72b88de4c5f3095ebe20b4d8afbedb32b8f",
        }
        self.checksum_md5_data = {
            "algorithm": "MD5",
            "value": "56770c1a2df6e0dc51c491f0a5b9d865",
        }
        self.external_ref_purl_data = {
            "category": "PACKAGE-MANAGER",
            "type": "purl",
            "locator": "pkg:pypi/lxml@3.3.5",
        }
        self.external_ref_purl_spdx_data = {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": "pkg:pypi/lxml@3.3.5",
        }
        self.licensing_info_data = {
            "license_id": "LicenseRef-1",
            "extracted_text": "License Text",
            "name": "License 1",
            "see_alsos": [
                "https://license1.text",
                "https://license1.homepage",
            ],
        }
        self.licensing_info_spdx_data = {
            "licenseId": "LicenseRef-1",
            "extractedText": "License Text",
            "name": "License 1",
            "seeAlsos": [
                "https://license1.text",
                "https://license1.homepage",
            ],
        }
        self.package_data = {
            "spdx_id": "SPDXRef-package1",
            "name": "lxml",
            "version": "3.3.5",
            "license_concluded": "LicenseRef-1",
            "release_date": "2000-01-01",
            "checksums": [
                spdx.Checksum(**self.checksum_sha1_data),
                spdx.Checksum(**self.checksum_md5_data),
            ],
            "external_refs": [spdx.ExternalRef(**self.external_ref_purl_data)],
        }
        self.package_spdx_data = {
            "name": "lxml",
            "SPDXID": "SPDXRef-package1",
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "LicenseRef-1",
            "copyrightText": "NOASSERTION",
            "filesAnalyzed": False,
            "versionInfo": "3.3.5",
            "licenseDeclared": "NOASSERTION",
            "releaseDate": "2000-01-01T00:00:00Z",
            "checksums": [
                {
                    "algorithm": "SHA1",
                    "checksumValue": "10c72b88de4c5f3095ebe20b4d8afbedb32b8f",
                },
                {
                    "algorithm": "MD5",
                    "checksumValue": "56770c1a2df6e0dc51c491f0a5b9d865",
                },
            ],
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/lxml@3.3.5",
                }
            ],
        }
        self.file_data = {
            "spdx_id": "SPDXRef-file1",
            "name": "file.txt",
            "license_concluded": "LicenseRef-1",
            "checksums": [
                spdx.Checksum(**self.checksum_sha1_data),
            ],
            "types": ["TEXT"],
            "comment": "comment",
            "license_comments": "license_comments",
        }
        self.file_spdx_data = {
            "SPDXID": "SPDXRef-file1",
            "fileName": "file.txt",
            "checksums": [
                {
                    "algorithm": "SHA1",
                    "checksumValue": "10c72b88de4c5f3095ebe20b4d8afbedb32b8f",
                }
            ],
            "fileTypes": ["TEXT"],
            "copyrightText": "NOASSERTION",
            "licenseConcluded": "LicenseRef-1",
            "comment": "comment",
            "licenseComments": "license_comments",
        }
        self.relationship_data = {
            "spdx_id": self.package_data["spdx_id"],
            "related_spdx_id": self.file_data["spdx_id"],
            "relationship": "CONTAINS",
        }
        self.relationship_spdx_data = {
            "spdxElementId": "SPDXRef-package1",
            "relatedSpdxElement": "SPDXRef-file1",
            "relationshipType": "CONTAINS",
        }
        self.document_data = {
            "name": "Document name",
            "namespace": "https://[CreatorWebsite]/[DocumentName]-[UUID]",
            "creation_info": spdx.CreationInfo(**self.creation_info_data),
            "packages": [
                spdx.Package(**self.package_data),
            ],
            "extracted_licenses": [
                spdx.ExtractedLicensingInfo(**self.licensing_info_data),
            ],
            "files": [
                spdx.File(**self.file_data),
            ],
            "relationships": [
                spdx.Relationship(**self.relationship_data),
            ],
            "comment": "This document was created using SPDXCode-1.0",
        }
        self.document_spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "document_name",
            "documentNamespace": "https://[CreatorWebsite]/[DocumentName]-[UUID]",
            "creationInfo": {
                "created": "2022-09-21T13:50:20Z",
                "creators": [
                    "Person: John Doe (john@starship.space)",
                    "Organization: Starship ()",
                    "Tool: SPDXCode-1.0",
                ],
                "licenseListVersion": "3.20",
                "comment": "Generated with SPDXCode",
            },
            "packages": [
                {
                    "name": "lxml",
                    "SPDXID": "SPDXRef-package1",
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "LicenseRef-1",
                    "copyrightText": "NOASSERTION",
                    "filesAnalyzed": False,
                    "versionInfo": "3.3.5",
                    "licenseDeclared": "NOASSERTION",
                    "releaseDate": "2000-01-01T00:00:00Z",
                    "checksums": [
                        {
                            "algorithm": "SHA1",
                            "checksumValue": "10c72b88de4c5f3095ebe20b4d8afbedb32b8f",
                        },
                        {
                            "algorithm": "MD5",
                            "checksumValue": "56770c1a2df6e0dc51c491f0a5b9d865",
                        },
                    ],
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/lxml@3.3.5",
                        }
                    ],
                }
            ],
            "files": [
                {
                    "SPDXID": "SPDXRef-file1",
                    "fileName": "file.txt",
                    "checksums": [
                        {
                            "algorithm": "SHA1",
                            "checksumValue": "10c72b88de4c5f3095ebe20b4d8afbedb32b8f",
                        }
                    ],
                    "fileTypes": ["TEXT"],
                    "copyrightText": "NOASSERTION",
                    "licenseConcluded": "LicenseRef-1",
                    "comment": "comment",
                    "licenseComments": "license_comments",
                }
            ],
            "documentDescribes": ["SPDXRef-package1"],
            "hasExtractedLicensingInfos": [
                {
                    "licenseId": "LicenseRef-1",
                    "extractedText": "License Text",
                    "name": "License 1",
                    "seeAlsos": ["https://license1.text", "https://license1.homepage"],
                }
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-package1",
                    "relatedSpdxElement": "SPDXRef-file1",
                    "relationshipType": "CONTAINS",
                }
            ],
            "comment": "This document was created using SPDXCode-1.0",
        }

    def test_spdx_creation_info_as_dict(self):
        creation_info = spdx.CreationInfo(**self.creation_info_data)
        assert self.creation_info_spdx_data == creation_info.as_dict()

    def test_spdx_creation_info_from_data(self):
        assert spdx.CreationInfo.from_data({})
        creation_info = spdx.CreationInfo.from_data(self.creation_info_spdx_data)
        assert self.creation_info_spdx_data == creation_info.as_dict()

    def test_spdx_creation_info_missing_data(self):
        creation_info = spdx.CreationInfo()
        with self.assertRaises(ValueError) as error:
            creation_info.as_dict()
        assert "Missing values to build `creators` list." == str(error.exception)

    def test_spdx_checksum_as_dict(self):
        checksum = spdx.Checksum(**self.checksum_sha1_data)
        assert self.checksum_sha1_spdx_data == checksum.as_dict()

    def test_spdx_checksum_from_data(self):
        assert spdx.Checksum.from_data({})
        checksum = spdx.Checksum.from_data(self.checksum_sha1_spdx_data)
        assert self.checksum_sha1_spdx_data == checksum.as_dict()

    def test_spdx_external_ref_as_dict(self):
        external_ref = spdx.ExternalRef(**self.external_ref_purl_data)
        assert self.external_ref_purl_spdx_data == external_ref.as_dict()

    def test_spdx_external_ref_from_data(self):
        assert spdx.ExternalRef.from_data({})
        external_ref = spdx.ExternalRef.from_data(self.external_ref_purl_spdx_data)
        assert self.external_ref_purl_spdx_data == external_ref.as_dict()

    def test_spdx_extracted_licensing_info_as_dict(self):
        licensing_info = spdx.ExtractedLicensingInfo(**self.licensing_info_data)
        assert self.licensing_info_spdx_data == licensing_info.as_dict()

    def test_spdx_extracted_licensing_info_from_data(self):
        assert spdx.ExtractedLicensingInfo.from_data({})
        licensing_info = spdx.ExtractedLicensingInfo.from_data(
            self.licensing_info_spdx_data
        )
        assert self.licensing_info_spdx_data == licensing_info.as_dict()

    def test_spdx_package_as_dict(self):
        package = spdx.Package(**self.package_data)
        assert self.package_spdx_data == package.as_dict()

    def test_spdx_package_from_data(self):
        assert spdx.Package.from_data({})
        package = spdx.Package.from_data(self.package_spdx_data)
        assert self.package_spdx_data == package.as_dict()

    def test_spdx_package_date_to_iso(self):
        date_to_iso = spdx.Package.date_to_iso
        assert None is date_to_iso(None)
        assert None is date_to_iso("")
        assert "2000-01-01T00:00:00Z" == date_to_iso("2000-01-01")
        assert "2000-01-01T10:00:00Z" == date_to_iso("2000-01-01 10")
        assert "2000-01-01T10:20:00Z" == date_to_iso("2000-01-01 10:20")
        assert "2000-01-01T10:20:30Z" == date_to_iso("2000-01-01 10:20:30")
        assert "2000-01-01T10:20:30Z" == date_to_iso("2000-01-01T10:20:30Z")

        with self.assertRaises(ValueError) as error:
            date_to_iso("not_a_date")
        assert "Invalid isoformat string: 'not_a_date'" == str(error.exception)

    def test_spdx_file_as_dict(self):
        spdx_file = spdx.File(**self.file_data)
        assert self.file_spdx_data == spdx_file.as_dict()

    def test_spdx_file_from_data(self):
        assert spdx.File.from_data({})
        file = spdx.File.from_data(self.file_spdx_data)
        assert self.file_spdx_data == file.as_dict()

    def test_spdx_relationship_as_dict(self):
        relationship = spdx.Relationship(**self.relationship_data)
        assert self.relationship_spdx_data == relationship.as_dict()

    def test_spdx_relationship_from_data(self):
        assert spdx.Relationship.from_data({})
        relationship = spdx.Relationship.from_data(self.relationship_spdx_data)
        assert self.relationship_spdx_data == relationship.as_dict()

    def test_spdx_relationship_is_dependency_relationship_property(self):
        relationship = spdx.Relationship.from_data(self.relationship_spdx_data)
        assert relationship.is_dependency_relationship is False
        relationship.relationship = "DEPENDENCY_OF"
        assert relationship.is_dependency_relationship

    def test_spdx_document_as_dict(self):
        document = spdx.Document(**self.document_data)
        assert self.document_spdx_data == document.as_dict()

    def test_spdx_document_from_data(self):
        assert spdx.Document.from_data({})
        document = spdx.Document.from_data(self.document_spdx_data)
        assert self.document_spdx_data == document.as_dict()

    def test_spdx_document_as_json(self):
        document = spdx.Document(**self.document_data)
        assert isinstance(document.as_json(), str)
        assert '{\n  "spdxVersion": "SPDX-2.3",' == document.as_json()[0:30]

    def test_spdx_document_safe_document_name(self):
        assert "upper_1_2_3_" == spdx.Document.safe_document_name("UPPER@1-2-3^&*")

    def test_spdx_document_validate(self):
        document = spdx.Document(**self.document_data)
        document.validate(self.schema)

    def test_spdx_validate_document(self):
        document = spdx.Document(**self.document_data)
        spdx.validate_document(document, self.schema)

        # Testing support for "PACKAGE_MANAGER" in place of "PACKAGE-MANAGER"
        document_location = self.data / "spdx" / "example-2.3.1.json"
        spdx.validate_document(document_location.read_text(), self.schema)

        with self.assertRaises(Exception):
            spdx.validate_document({}, self.schema)
