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

import io
import json
import sys
import tempfile
import uuid
from dataclasses import asdict
from pathlib import Path
from unittest import mock
from unittest import skipIf

from django.db.utils import DataError
from django.test import TestCase

from scanpipe import pipes
from scanpipe.models import CodebaseRelation
from scanpipe.models import CodebaseResource
from scanpipe.models import Project
from scanpipe.pipes import d2d
from scanpipe.pipes import d2d_config
from scanpipe.pipes import flag
from scanpipe.pipes import jvm
from scanpipe.pipes import scancode
from scanpipe.pipes import symbols
from scanpipe.pipes.input import copy_input
from scanpipe.pipes.input import copy_inputs
from scanpipe.tests import make_resource_directory
from scanpipe.tests import make_resource_file
from scanpipe.tests import package_data1
from scanpipe.tests import package_data2
from scanpipe.tests import resource_data1


class ScanPipeD2DPipesTest(TestCase):
    data = Path(__file__).parent.parent / "data"

    def setUp(self):
        self.project1 = Project.objects.create(name="Analysis")

    def test_scanpipe_pipes_d2d_get_inputs(self):
        with self.assertRaises(FileNotFoundError) as error:
            d2d.get_inputs(self.project1)
        self.assertEqual("from* input files not found.", str(error.exception))

        _, input_location = tempfile.mkstemp(prefix="from-")
        self.project1.copy_input_from(input_location)

        with self.assertRaises(FileNotFoundError) as error:
            d2d.get_inputs(self.project1)
        self.assertEqual("to* input files not found.", str(error.exception))

        _, input_location = tempfile.mkstemp(prefix="to-")
        self.project1.copy_input_from(input_location)

        from_files, to_files = d2d.get_inputs(self.project1)
        self.assertEqual(1, len(from_files))
        self.assertEqual(1, len(to_files))

        _, input_location = tempfile.mkstemp(prefix="from-")
        self.project1.copy_input_from(input_location)
        _, input_location = tempfile.mkstemp(prefix="to-")
        self.project1.copy_input_from(input_location)
        from_files, to_files = d2d.get_inputs(self.project1)
        self.assertEqual(2, len(from_files))
        self.assertEqual(2, len(to_files))

        _, input_location = tempfile.mkstemp(prefix="")
        self.project1.copy_input_from(input_location)
        url_with_fragment = "https://download.url#from"
        input_source1 = self.project1.add_input_source(
            download_url=url_with_fragment, filename=Path(input_location).name
        )
        _, input_location = tempfile.mkstemp(prefix="")
        self.project1.copy_input_from(input_location)
        url_with_fragment = "https://download.url#to"
        input_source2 = self.project1.add_input_source(
            download_url=url_with_fragment, filename=Path(input_location).name
        )

        from_files, to_files = d2d.get_inputs(self.project1)
        self.assertEqual(3, len(from_files))
        self.assertEqual(3, len(to_files))
        self.assertIn(input_source1.path, from_files)
        self.assertIn(input_source2.path, to_files)

    def test_scanpipe_pipes_d2d_get_extracted_path(self):
        path = "not/an/extracted/path/"
        r1 = make_resource_file(self.project1, path)
        expected = "not/an/extracted/path/-extract/"
        self.assertEqual(expected, d2d.get_extracted_path(r1))

        path = "a.jar-extract/subpath/file.ext"
        r2 = make_resource_file(self.project1, path)
        expected = "a.jar-extract/subpath/file.ext-extract/"
        self.assertEqual(expected, d2d.get_extracted_path(r2))

    def test_scanpipe_pipes_d2d_get_extracted_subpath(self):
        path = "not/an/extracted/path/"
        self.assertEqual(path, d2d.get_extracted_subpath(path))

        path = "a.jar-extract/subpath/file.ext"
        self.assertEqual("subpath/file.ext", d2d.get_extracted_subpath(path))

        path = "a.jar-extract/subpath/b.jar-extract/subpath/file.ext"
        self.assertEqual("subpath/file.ext", d2d.get_extracted_subpath(path))

    @mock.patch("scanpipe.pipes.purldb.match_resources")
    def test_scanpipe_pipes_d2d_match_sha1s_to_purldb(self, mock_match_resource):
        to_1 = make_resource_file(
            self.project1,
            "to/notice.NOTICE",
            sha1="4bd631df28995c332bf69d9d4f0f74d7ee089598",
        )
        resources_by_sha1 = {to_1.sha1: [to_1]}
        package_data = package_data1.copy()
        package_data_by_purldb_urls = {"example.com/package-instance": package_data}

        resource_data = resource_data1.copy()
        resource_data["package"] = "example.com/package-instance"
        mock_match_resource.return_value = [resource_data]

        resources_by_sha1, matched_count, sha1_count = d2d.match_sha1s_to_purldb(
            self.project1,
            resources_by_sha1,
            d2d.match_purldb_resource,
            package_data_by_purldb_urls,
        )
        self.assertFalse(resources_by_sha1)
        self.assertEqual(1, matched_count)
        self.assertEqual(1, sha1_count)

        # Ensure match_purldb_resource was run
        package = self.project1.discoveredpackages.get()
        self.assertEqual(package_data["purl"], package.purl)
        to_1.refresh_from_db()
        self.assertEqual(flag.MATCHED_TO_PURLDB_RESOURCE, to_1.status)
        self.assertEqual(1, to_1.discovered_packages.count())
        to_1_package = to_1.discovered_packages.get()
        self.assertEqual(package, to_1_package)

    @mock.patch("scanpipe.pipes.purldb.match_packages")
    def test_scanpipe_pipes_d2d_match_purldb_resources(self, mock_match_package):
        to_1 = make_resource_file(self.project1, "to/package.jar", sha1="abcdef")
        to_1.is_archive = True
        to_1.save()
        # The initial status will be updated to flag.MATCHED_TO_PURLDB_PACKAGE
        to_2 = make_resource_file(
            self.project1, "to/package.jar-extract/a.class", status=flag.MAPPED
        )
        to_3 = make_resource_file(self.project1, "to/package.jar-extract/b.class")

        package_data = package_data1.copy()
        package_data["uuid"] = uuid.uuid4()
        package_data["sha1"] = "abcdef"
        mock_match_package.return_value = [package_data]

        buffer = io.StringIO()
        d2d.match_purldb_resources(
            self.project1,
            extensions=[".jar"],
            matcher_func=d2d.match_purldb_package,
            logger=buffer.write,
        )
        expected = (
            "Matching 1 .jar resources in PurlDB, using SHA1"
            "3 resources matched in PurlDB using 1 SHA1s"
        )
        self.assertEqual(expected, buffer.getvalue())

        package = self.project1.discoveredpackages.get()
        self.assertEqual(package_data["name"], package.name)
        self.assertNotEqual(package_data["uuid"], package.uuid)

        for resource in [to_1, to_2, to_3]:
            resource.refresh_from_db()
            self.assertEqual(flag.MATCHED_TO_PURLDB_PACKAGE, resource.status)
            self.assertEqual(package, resource.discovered_packages.get())

    @mock.patch("scanpipe.pipes.purldb.request_get")
    def test_scanpipe_pipes_d2d_match_purldb_directories(self, mock_request_get):
        to_1 = make_resource_directory(
            self.project1,
            "to/package.jar-extract",
            extra_data={"directory_content": "abcdef"},
        )
        to_2 = make_resource_file(self.project1, "to/package.jar-extract/a.class")
        to_3 = make_resource_file(self.project1, "to/package.jar-extract/b.class")
        package_data = package_data1.copy()
        package_data["uuid"] = uuid.uuid4()
        mock_request_get.side_effect = [
            [
                {
                    "fingerprint": "abcdef",
                    "matched_fingerprint": "abcdef",
                    "package": "http://private.purldb.io/api/packages/package-id-123",
                }
            ],
            package_data,
            [],
        ]

        buffer = io.StringIO()
        d2d.match_purldb_directories(
            self.project1,
            logger=buffer.write,
        )

        expected = (
            "Matching 1 directory from to/ in PurlDB1 directory matched in PurlDB"
        )
        self.assertEqual(expected, buffer.getvalue())

        package = self.project1.discoveredpackages.get()
        self.assertEqual(package_data["name"], package.name)
        self.assertNotEqual(package_data["uuid"], package.uuid)

        for resource in [to_1, to_2, to_3]:
            resource.refresh_from_db()
            self.assertEqual("matched-to-purldb-directory", resource.status)
            self.assertEqual(package, resource.discovered_packages.get())

    def test_scanpipe_pipes_d2d_get_best_path_matches_same_name(self):
        to_1 = CodebaseResource(name="package-1.0.ext", path="to/package-1.0.ext")
        to_2 = CodebaseResource(name="package-2.0.ext", path="to/package-2.0.ext")
        from_1 = CodebaseResource(name="package-1.0.ext", path="from/package-1.0.ext")
        from_2 = CodebaseResource(name="package-2.0.ext", path="from/package-2.0.ext")
        matches = [from_1, from_2]
        self.assertEqual([from_1], d2d.get_best_path_matches(to_1, matches))
        self.assertEqual([from_2], d2d.get_best_path_matches(to_2, matches))

    def test_scanpipe_pipes_d2d_get_best_path_matches_extracted_subpath(self):
        to_1 = CodebaseResource(path="to/jar-extract/a/package-1.0.ext")
        to_2 = CodebaseResource(path="to/jar-extract/a/package-2.0.ext")
        from_1 = CodebaseResource(path="from/src/a/package-1.0.ext")
        from_2 = CodebaseResource(path="from/src/a/package-2.0.ext")
        matches = [from_1, from_2]
        self.assertEqual([from_1], d2d.get_best_path_matches(to_1, matches))
        self.assertEqual([from_2], d2d.get_best_path_matches(to_2, matches))

    def test_scanpipe_pipes_d2d_get_best_path_matches(self):
        to_1 = make_resource_file(self.project1, path="to/a/b/c/file.txt")
        from_1 = make_resource_file(self.project1, path="from/source/f/i/j/file.txt")
        from_2 = make_resource_file(self.project1, path="from/source/a/b/c/file.txt")
        from_3 = make_resource_file(self.project1, path="from/q/w/e/file.txt")

        matches = [from_1, from_2, from_3]
        self.assertEqual([from_2], d2d.get_best_path_matches(to_1, matches))

        # Cannot determine the best as only the filename matches
        to_2 = make_resource_file(self.project1, path="to/x/y/z/init.jsp.readme")
        self.assertEqual(matches, d2d.get_best_path_matches(to_2, matches))

    def test_scanpipe_pipes_d2d_map_checksum(self):
        sha1 = "abcde"
        to_1 = make_resource_file(self.project1, path="to/a/b/c/file.txt", sha1=sha1)
        make_resource_file(self.project1, path="from/source/f/i/j/file.txt", sha1=sha1)
        from_2 = make_resource_file(
            self.project1, path="from/source/a/b/c/file.txt", sha1=sha1
        )
        # Matchable path but missing sha1 value
        make_resource_file(self.project1, path="from/content/a/b/c/file.txt")
        make_resource_file(self.project1, path="from/q/w/e/file.txt", sha1=sha1)

        buffer = io.StringIO()
        d2d.map_checksum(self.project1, "sha1", logger=buffer.write)
        expected = "Mapping 1 to/ resources using sha1 against from/ codebase"
        self.assertEqual(expected, buffer.getvalue())
        self.assertEqual(1, to_1.related_from.count())
        relation = to_1.related_from.get()
        self.assertEqual("sha1", relation.map_type)
        self.assertEqual(from_2, relation.from_resource)

    def test_scanpipe_pipes_d2d_flag_processed_archives(self):
        to_archive = make_resource_file(
            self.project1, path="to/archive.lpkg", is_archive=True
        )
        make_resource_directory(
            self.project1, path="to/archive.lpkg-extract", status=flag.IGNORED_DIRECTORY
        )
        to_archive_embedded = make_resource_file(
            self.project1,
            path="to/archive.lpkg-extract/embedded-archive.lpkg",
            is_archive=True,
        )
        make_resource_directory(
            self.project1,
            path="to/archive.lpkg-extract/embedded-archive.lpkg-extract",
            status=flag.IGNORED_DIRECTORY,
        )
        make_resource_file(
            self.project1,
            path="to/archive.lpkg-extract/file1.txt",
            status=flag.MATCHED_TO_PURLDB_RESOURCE,
        )
        make_resource_file(
            self.project1,
            path="to/archive.lpkg-extract/file2.txt",
            status=flag.MATCHED_TO_PURLDB_RESOURCE,
        )
        resource1 = make_resource_file(
            self.project1,
            path="to/archive.lpkg-extract/embedded-archive.lpkg-extract/file3.txt",
            status=flag.MATCHED_TO_PURLDB_RESOURCE,
        )

        d2d.flag_processed_archives(self.project1)

        to_archive_embedded.refresh_from_db()
        self.assertEqual(flag.ARCHIVE_PROCESSED, to_archive_embedded.status)

        to_archive.refresh_from_db()
        self.assertEqual(flag.ARCHIVE_PROCESSED, to_archive.status)

        to_archive_embedded.update(status="")
        resource1.update(status="")
        d2d.flag_processed_archives(self.project1)
        to_archive_embedded.refresh_from_db()
        self.assertEqual("", to_archive_embedded.status)

    def test_scanpipe_pipes_d2d_map_java_to_class(self):
        from1 = make_resource_file(
            self.project1,
            path="from/flume-ng-node-1.9.0-sources.jar-extract/org/apache/flume/node/"
            "AbstractConfigurationProvider.java",
            extra_data={"java_package": "org.apache.flume.node"},
        )
        from2 = make_resource_file(
            self.project1,
            path="from/flume-ng-node-1.9.0-sources.jar-extract/org/apache/flume/WRONG/"
            "Application.java",
            extra_data={"java_package": "org.apache.flume.WRONG"},
        )
        to1 = make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar-extract/org/apache/flume/node/"
            "AbstractConfigurationProvider$ChannelComponent.class",
        )
        to2 = make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar-extract/org/apache/flume/node/"
            "AbstractConfigurationProvider.class",
        )
        to3 = make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar-extract/org/apache/flume/node/"
            "Application.class",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.JavaLanguage
        )

        expected = "Mapping 3 .class (or other deployed file) resources to 2 ('.java',)"
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(2, self.project1.codebaserelations.count())

        r1 = self.project1.codebaserelations.get(to_resource=to1, from_resource=from1)
        self.assertEqual("java_to_class", r1.map_type)
        expected = {"from_source_root": "from/flume-ng-node-1.9.0-sources.jar-extract/"}
        self.assertEqual(expected, r1.extra_data)

        r2 = self.project1.codebaserelations.get(to_resource=to2, from_resource=from1)
        self.assertEqual("java_to_class", r2.map_type)
        expected = {"from_source_root": "from/flume-ng-node-1.9.0-sources.jar-extract/"}
        self.assertEqual(expected, r2.extra_data)

        no_relations = self.project1.codebaseresources.has_no_relation()
        self.assertIn(from2, no_relations)
        self.assertIn(to3, no_relations)
        to3.refresh_from_db()
        self.assertEqual("", to3.status)

    def test_scanpipe_pipes_d2d_map_java_to_class_with_java_in_deploy(self):
        input_dir = self.project1.input_path
        # "from-Baz.zip" contains Baz.java
        # "to-Baz.jar" contains Baz.java and Baz.class
        input_resources = [
            self.data / "d2d" / "find_java_packages" / "from-Baz.zip",
            self.data / "d2d" / "find_java_packages" / "to-Baz.jar",
        ]

        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()

        d2d.map_checksum(
            project=self.project1, checksum_field="sha1", logger=buffer.write
        )

        d2d.find_jvm_packages(
            self.project1, jvm_lang=jvm.JavaLanguage, logger=buffer.write
        )
        expected = "Finding java packages for 1 ('.java',) resources."
        self.assertIn(expected, buffer.getvalue())
        # Now run map_java_to_class
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.JavaLanguage
        )
        expected = "Mapping 1 .class (or other deployed file) resources to 1 ('.java',)"
        self.assertIn(expected, buffer.getvalue())

    def test_scanpipe_pipes_d2d_map_grammar_to_class(self):
        from1 = make_resource_file(
            self.project1,
            path="from/antlr4-4.5.1-beta-1/tool/src/org/antlr/v4/parse/BlockSetTransformer.g",
            extra_data={"grammar_package": "org.antlr.v4.parse"},
        )

        to1 = make_resource_file(
            self.project1,
            path="to/org/antlr/v4/parse/BlockSetTransformer.class",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.GrammarLanguage
        )

        expected = (
            "Mapping 1 .class (or other deployed file) resources to 1 ('.g', '.g4')"
        )
        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(1, self.project1.codebaserelations.count())

        r1 = self.project1.codebaserelations.get(to_resource=to1, from_resource=from1)
        self.assertEqual("grammar_to_class", r1.map_type)
        expected = {"from_source_root": "from/antlr4-4.5.1-beta-1/tool/src/"}
        self.assertEqual(expected, r1.extra_data)

    def test_scanpipe_pipes_d2d_map_xtend_to_class(self):
        from1 = make_resource_file(
            self.project1,
            path="from/org.openhab.binding.urtsi/src/main/java/org/openhab/"
            + "binding/urtsi/internal/UrtsiDevice.xtend",
            extra_data={"xtend_package": "org.openhab.binding.urtsi.internal"},
        )

        to1 = make_resource_file(
            self.project1,
            path="to/org.openhab.binding.urtsi-1.6.2.jar-extract/org/"
            + "openhab/binding/urtsi/internal/UrtsiDevice.class",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.XtendLanguage
        )

        expected = (
            "Mapping 1 .class (or other deployed file) resources to 1 ('.xtend',)"
        )
        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(1, self.project1.codebaserelations.count())

        r1 = self.project1.codebaserelations.get(to_resource=to1, from_resource=from1)
        self.assertEqual("xtend_to_class", r1.map_type)
        expected = {"from_source_root": "from/org.openhab.binding.urtsi/src/main/java/"}
        self.assertEqual(expected, r1.extra_data)

    def test_scanpipe_pipes_d2d_map_java_to_class_no_java(self):
        make_resource_file(self.project1, path="to/Abstract.class")
        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.JavaLanguage
        )
        expected = "No ('.java',) resources to map."
        self.assertIn(expected, buffer.getvalue())

    def test_scanpipe_pipes_d2d_java_ignore_pattern(self):
        make_resource_file(self.project1, path="to/module-info.class")
        make_resource_file(self.project1, path="to/META-INF/MANIFEST.MF")
        make_resource_file(self.project1, path="to/test.class")
        make_resource_file(self.project1, path="to/META-INF/others.txt")
        make_resource_file(
            self.project1, path="to/META-INF/spring-configuration-metadata.json"
        )
        make_resource_file(self.project1, path="to/OSGI-INF/test.xml")
        make_resource_file(self.project1, path="to/OSGI-INF/test.json")
        make_resource_file(self.project1, path="to/OSGI-INF/test.class")
        buffer = io.StringIO()

        java_config = d2d_config.get_ecosystem_config(ecosystem="Java")
        d2d.ignore_unmapped_resources_from_config(
            project=self.project1,
            patterns_to_ignore=java_config.deployed_resource_path_exclusions,
            logger=buffer.write,
        )
        expected = "Ignoring 6 to/ resources with ecosystem specific configurations."
        self.assertIn(expected, buffer.getvalue())

    def test_scanpipe_pipes_d2d_map_jar_to_java_source(self):
        from1 = make_resource_file(
            self.project1,
            path="from/flume-ng-node-1.9.0-sources.jar-extract/org/apache/flume/node/"
            "AbstractConfigurationProvider.java",
            extra_data={"java_package": "org.apache.flume.node"},
        )
        from2 = make_resource_file(
            self.project1,
            path="from/flume-ng-node-1.9.0-sources.jar-extract",
        )
        to1 = make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar-extract/org/apache/flume/node/"
            "AbstractConfigurationProvider.class",
        )
        make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar-extract/META-INF/MANIFEST.MF",
        )
        to_jar = make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.JavaLanguage
        )
        relation = self.project1.codebaserelations.get()
        self.assertEqual(from1, relation.from_resource)
        self.assertEqual(to1, relation.to_resource)
        self.assertEqual("java_to_class", relation.map_type)
        expected = {"from_source_root": "from/flume-ng-node-1.9.0-sources.jar-extract/"}
        self.assertEqual(expected, relation.extra_data)

        buffer = io.StringIO()
        with self.assertNumQueries(6):
            d2d.map_jar_to_jvm_source(
                self.project1, logger=buffer.write, jvm_lang=jvm.JavaLanguage
            )
        expected = "Mapping 1 .jar resources using map_jar_to_source"
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(2, self.project1.codebaserelations.count())
        relation = self.project1.codebaserelations.get(map_type="jar_to_source")
        self.assertEqual(from2, relation.from_resource)
        self.assertEqual(to_jar, relation.to_resource)

    def test_scanpipe_pipes_d2d_map_groovy_to_class(self):
        from1 = make_resource_file(
            self.project1,
            path="from/project/test.groovy",
            extra_data={"groovy_package": "project"},
        )

        to1 = make_resource_file(
            self.project1,
            path="to/project/test.class",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.GroovyLanguage
        )

        expected = (
            "Mapping 1 .class (or other deployed file) resources to 1 ('.groovy',)"
        )
        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(1, self.project1.codebaserelations.count())

        r1 = self.project1.codebaserelations.get(to_resource=to1, from_resource=from1)
        self.assertEqual("groovy_to_class", r1.map_type)
        expected = {"from_source_root": "from/"}
        self.assertEqual(expected, r1.extra_data)

    def test_scanpipe_pipes_d2d_map_aspectj_to_class(self):
        from1 = make_resource_file(
            self.project1,
            path="from/project/test.aj",
            extra_data={"aspectj_package": "project"},
        )

        to1 = make_resource_file(
            self.project1,
            path="to/project/test.class",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.AspectJLanguage
        )

        expected = "Mapping 1 .class (or other deployed file) resources to 1 ('.aj',)"
        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(1, self.project1.codebaserelations.count())

        r1 = self.project1.codebaserelations.get(to_resource=to1, from_resource=from1)
        self.assertEqual("aspectj_to_class", r1.map_type)
        expected = {"from_source_root": "from/"}
        self.assertEqual(expected, r1.extra_data)

    def test_scanpipe_pipes_d2d_map_clojure_to_class(self):
        from1 = make_resource_file(
            self.project1,
            path="from/project/test.clj",
            extra_data={"clojure_package": "project"},
        )

        to1 = make_resource_file(
            self.project1,
            path="to/project/test.class",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.ClojureLanguage
        )

        expected = "Mapping 1 .class (or other deployed file) resources to 1 ('.clj',)"
        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(1, self.project1.codebaserelations.count())

        r1 = self.project1.codebaserelations.get(to_resource=to1, from_resource=from1)
        self.assertEqual("clojure_to_class", r1.map_type)
        expected = {"from_source_root": "from/"}
        self.assertEqual(expected, r1.extra_data)

    def test_scanpipe_pipes_d2d_map_scala_to_class(self):
        from1 = make_resource_file(
            self.project1,
            path="from/tastyquery/Annotations.scala",
            extra_data={"scala_package": "tastyquery"},
        )

        to1 = make_resource_file(
            self.project1,
            path="to/tastyquery/Annotations.tasty",
        )

        to2 = make_resource_file(
            self.project1,
            path="to/tastyquery/Annotations.class",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.ScalaLanguage
        )

        expected = (
            "Mapping 2 .class (or other deployed file) resources to 1 ('.scala',)"
        )
        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(2, self.project1.codebaserelations.count())

        r1 = self.project1.codebaserelations.get(to_resource=to1, from_resource=from1)
        self.assertEqual("scala_to_class", r1.map_type)
        expected = {"from_source_root": "from/"}
        self.assertEqual(expected, r1.extra_data)

        r2 = self.project1.codebaserelations.get(to_resource=to2, from_resource=from1)
        self.assertEqual("scala_to_class", r2.map_type)
        expected = {"from_source_root": "from/"}
        self.assertEqual(expected, r2.extra_data)

    def test_scanpipe_pipes_d2d_map_jar_to_scala_source(self):
        from1 = make_resource_file(
            self.project1,
            path="from/flume-ng-node-1.9.0-sources.jar-extract/org/apache/flume/node/"
            "AbstractConfigurationProvider.scala",
            extra_data={"scala_package": "org.apache.flume.node"},
        )
        from2 = make_resource_file(
            self.project1,
            path="from/flume-ng-node-1.9.0-sources.jar-extract",
        )
        to1 = make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar-extract/org/apache/flume/node/"
            "AbstractConfigurationProvider.class",
        )
        make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar-extract/META-INF/MANIFEST.MF",
        )
        to_jar = make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.ScalaLanguage
        )
        relation = self.project1.codebaserelations.get()
        self.assertEqual(from1, relation.from_resource)
        self.assertEqual(to1, relation.to_resource)
        self.assertEqual("scala_to_class", relation.map_type)
        expected = {"from_source_root": "from/flume-ng-node-1.9.0-sources.jar-extract/"}
        self.assertEqual(expected, relation.extra_data)

        buffer = io.StringIO()
        with self.assertNumQueries(6):
            d2d.map_jar_to_jvm_source(
                self.project1, logger=buffer.write, jvm_lang=jvm.ScalaLanguage
            )
        expected = "Mapping 1 .jar resources using map_jar_to_source"
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(2, self.project1.codebaserelations.count())
        relation = self.project1.codebaserelations.get(map_type="jar_to_source")
        self.assertEqual(from2, relation.from_resource)
        self.assertEqual(to_jar, relation.to_resource)

    def test_scanpipe_pipes_d2d_scala_ignore_pattern(self):
        make_resource_file(self.project1, path="to/META-INF/MANIFEST.MF")
        make_resource_file(self.project1, path="to/test.class")
        make_resource_file(self.project1, path="to/META-INF/others.txt")
        buffer = io.StringIO()

        scala_config = d2d_config.get_ecosystem_config(ecosystem="Scala")
        d2d.ignore_unmapped_resources_from_config(
            project=self.project1,
            patterns_to_ignore=scala_config.deployed_resource_path_exclusions,
            logger=buffer.write,
        )
        expected = "Ignoring 2 to/ resources with ecosystem specific configurations."
        self.assertIn(expected, buffer.getvalue())

    def test_scanpipe_pipes_d2d_map_jar_to_kotlin_source(self):
        from1 = make_resource_file(
            self.project1,
            path="from/flume-ng-node-1.9.0-sources.jar-extract/org/apache/flume/node/"
            "AbstractConfigurationProvider.kt",
            extra_data={"kotlin_package": "org.apache.flume.node"},
        )
        from2 = make_resource_file(
            self.project1,
            path="from/flume-ng-node-1.9.0-sources.jar-extract",
        )
        to1 = make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar-extract/org/apache/flume/node/"
            "AbstractConfigurationProvider.class",
        )
        make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar-extract/META-INF/MANIFEST.MF",
        )
        to_jar = make_resource_file(
            self.project1,
            path="to/flume-ng-node-1.9.0.jar",
        )

        buffer = io.StringIO()
        d2d.map_jvm_to_class(
            self.project1, logger=buffer.write, jvm_lang=jvm.KotlinLanguage
        )
        relation = self.project1.codebaserelations.get()
        self.assertEqual(from1, relation.from_resource)
        self.assertEqual(to1, relation.to_resource)
        self.assertEqual("kotlin_to_class", relation.map_type)
        expected = {"from_source_root": "from/flume-ng-node-1.9.0-sources.jar-extract/"}
        self.assertEqual(expected, relation.extra_data)

        buffer = io.StringIO()
        with self.assertNumQueries(6):
            d2d.map_jar_to_jvm_source(
                self.project1, logger=buffer.write, jvm_lang=jvm.KotlinLanguage
            )
        expected = "Mapping 1 .jar resources using map_jar_to_source"
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(2, self.project1.codebaserelations.count())
        relation = self.project1.codebaserelations.get(map_type="jar_to_source")
        self.assertEqual(from2, relation.from_resource)
        self.assertEqual(to_jar, relation.to_resource)

    def test_scanpipe_pipes_d2d_kotlin_ignore_pattern(self):
        make_resource_file(self.project1, path="to/META-INF/test.knm")
        make_resource_file(self.project1, path="to/test.class")
        make_resource_file(
            self.project1, path="to/META-INF/kotlin-project-structure-metadata.json"
        )
        buffer = io.StringIO()

        kotlin_config = d2d_config.get_ecosystem_config(ecosystem="Kotlin")
        d2d.ignore_unmapped_resources_from_config(
            project=self.project1,
            patterns_to_ignore=kotlin_config.deployed_resource_path_exclusions,
            logger=buffer.write,
        )
        expected = "Ignoring 2 to/ resources with ecosystem specific configurations."
        self.assertIn(expected, buffer.getvalue())

    def test_scanpipe_pipes_d2d_map_jar_to_source_works_for_jar(self):
        from1 = make_resource_file(
            self.project1,
            path="from/org/apache/logging/log4j/core/util/SystemClock.java",
            extra_data={"java_package": "org.apache.logging.log4j.core.util"},
        )
        to1 = make_resource_file(
            self.project1,
            path=(
                "to/META-INF/versions/9/org/apache/logging/log4j/core/util/"
                "SystemClock.class"
            ),
        )
        to2 = make_resource_file(
            self.project1,
            path="to/org/apache/logging/log4j/core/util/SystemClock.class",
        )

        d2d.map_jvm_to_class(self.project1, jvm_lang=jvm.JavaLanguage)

        expected = [
            (from1.path, to1.path, "java_to_class"),
            (from1.path, to2.path, "java_to_class"),
        ]

        results = list(
            self.project1.codebaserelations.all().values_list(
                "from_resource__path", "to_resource__path", "map_type"
            )
        )

        self.assertEqual(expected, results)

    def test_scanpipe_pipes_d2d_get_indexable_qualified_java_paths_from_values_yields_correct_paths(  # NOQA: E501
        self,
    ):
        resource_values = [
            (
                1,
                "SystemClock.java",
                {"java_package": "org.apache.logging.log4j.core.util"},
            ),
            (
                2,
                "SystemClock2.java",
                {"java_package": "org.apache.logging.log4j.core.util"},
            ),
        ]
        expected = [
            (1, "org/apache/logging/log4j/core/util/SystemClock.java"),
            (2, "org/apache/logging/log4j/core/util/SystemClock2.java"),
        ]
        results = list(
            jvm.JavaLanguage.get_indexable_qualified_paths_from_values(resource_values)
        )
        self.assertEqual(expected, results)

    def test_scanpipe_pipes_d2d_map_path(self):
        from1 = make_resource_file(
            self.project1,
            path="from/core/src/main/org/apache/bar/file.ext",
        )
        make_resource_file(
            self.project1,
            path="from/core/src/main/org/apache2/bar/file.ext",
        )
        make_resource_file(
            self.project1,
            path="from/core/src/main/org/apache/bar/file2.ext",
        )
        to1 = make_resource_file(
            self.project1,
            path="to/apache/bar/file.ext",
        )
        make_resource_file(
            self.project1,
            path="to/apache/foo/file.ext",
        )

        buffer = io.StringIO()
        d2d.map_path(self.project1, logger=buffer.write)
        expected = "Mapping 2 to/ resources using path map against from/ codebase"
        self.assertIn(expected, buffer.getvalue())
        file_name_too_many = self.project1.codebaseresources.get(
            path="to/apache/foo/file.ext"
        )

        self.assertEqual(1, self.project1.codebaserelations.count())
        relation = self.project1.codebaserelations.get()
        self.assertEqual(from1, relation.from_resource)
        self.assertEqual(to1, relation.to_resource)
        self.assertEqual("path", relation.map_type)
        self.assertEqual({"path_score": "3/3"}, relation.extra_data)
        self.assertNotEqual("too-many-maps", file_name_too_many.status)

    def test_scanpipe_pipes_d2d_find_java_packages(self):
        input_locations = [
            self.data / "d2d" / "find_java_packages" / "Foo.java",
            self.data / "d2d" / "find_java_packages" / "Baz.java",
            self.data / "d2d" / "find_java_packages" / "Baz.class",
        ]

        from_dir = self.project1.codebase_path / "from"
        from_dir.mkdir()
        copy_inputs(input_locations, from_dir)
        pipes.collect_and_create_codebase_resources(self.project1)

        buffer = io.StringIO()
        d2d.find_jvm_packages(
            self.project1, jvm_lang=jvm.JavaLanguage, logger=buffer.write
        )

        expected = "Finding java packages for 2 ('.java',) resources."
        self.assertEqual(expected, buffer.getvalue())

        expected = [
            {"extra_data": {}, "path": "from"},
            {"extra_data": {}, "path": "from/Baz.class"},
            {"extra_data": {"java_package": "org.apache.biz"}, "path": "from/Baz.java"},
            {"extra_data": {"java_package": "org.apache.foo"}, "path": "from/Foo.java"},
        ]
        results = list(self.project1.codebaseresources.values("path", "extra_data"))
        self.assertEqual(expected, results)

    def test_scanpipe_pipes_d2d_map_javascript_skips_dot_file(self):
        make_resource_file(
            self.project1,
            path=(
                "from/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web/src/main/resources/META-INF/resources/"
                "adaptive_media/js/.main.js"
            ),
        )
        d2d.map_javascript(self.project1)
        self.assertEqual(0, self.project1.codebaserelations.count())

    def test_scanpipe_pipes_d2d_map_javascript(self):
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "intelligent robotics platform.lpkg-extract/"
            "com.example.adaptive.media.web-0.0.5.jar-extract/META-INF/"
            "resources/adaptive_media/js"
        )
        to_dir.mkdir(parents=True)
        resource_files = [
            self.data / "d2d-javascript" / "to" / "main.js.map",
            self.data / "d2d-javascript" / "to" / "main.js",
        ]
        copy_inputs(resource_files, to_dir)

        from_input_location = self.data / "d2d-javascript" / "from" / "main.js"
        from_dir = (
            self.project1.codebase_path
            / "from/project.tar.zst/modules/apps/adaptive-media/"
            "adaptive-media-web/src/main/resources/META-INF/resources/"
            "adaptive_media/js"
        )
        from_dir.mkdir(parents=True)
        copy_input(from_input_location, from_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        from_resource = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web/src/main/resources/META-INF/resources/"
                "adaptive_media/js/main.js"
            )
        )

        buffer = io.StringIO()
        d2d.map_javascript(self.project1, logger=buffer.write)
        expected = (
            "Mapping 1 .map resources using javascript map against from/ codebase."
        )
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(2, self.project1.codebaserelations.count())
        relation = self.project1.codebaserelations.all()
        self.assertEqual(from_resource, relation[0].from_resource)
        self.assertEqual(from_resource, relation[1].from_resource)

    def test_scanpipe_pipes_d2d_map_javascript_works_with_diff_ratio(self):
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "intelligent robotics platform.lpkg-extract/"
            "com.example.adaptive.media.web-0.0.5.jar-extract/META-INF/"
            "resources/adaptive_media/js"
        )
        to_dir.mkdir(parents=True)
        resource_files = [
            self.data / "d2d-javascript" / "to" / "unmain.js.map",
            self.data / "d2d-javascript" / "to" / "unmain.js",
        ]
        copy_inputs(resource_files, to_dir)

        from_input_location = self.data / "d2d-javascript" / "from" / "unmain.js"
        from_dir = (
            self.project1.codebase_path
            / "from/project.tar.zst/modules/apps/adaptive-media/"
            "adaptive-media-web/src/main/resources/META-INF/resources/"
            "adaptive_media/js"
        )
        from_dir.mkdir(parents=True)
        copy_input(from_input_location, from_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        from_resource = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web/src/main/resources/META-INF/resources/"
                "adaptive_media/js/unmain.js"
            )
        )

        buffer = io.StringIO()
        d2d.map_javascript(self.project1, logger=buffer.write)
        expected = (
            "Mapping 1 .map resources using javascript map against from/ codebase."
        )
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(2, self.project1.codebaserelations.count())
        relation = self.project1.codebaserelations.all()
        self.assertEqual(from_resource, relation[0].from_resource)
        self.assertEqual(from_resource, relation[1].from_resource)

    @mock.patch("scanpipe.pipes.purldb.match_resources")
    @mock.patch("scanpipe.pipes.purldb.request_get")
    def test_scanpipe_pipes_d2d_match_js_purldb(self, mock_match_resource, mock_get):
        to_location = self.data / "d2d-javascript" / "to" / "unmain.js.map"
        to_dir = (
            self.project1.codebase_path
            / "to/project.tar.zst/modules/apps/adaptive-media/"
            "adaptive-media-web/src/main/resources/META-INF/resources/"
            "adaptive_media/js"
        )
        to_dir.mkdir(parents=True)
        copy_input(to_location, to_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        mock_get.return_value = [
            {
                "package": "http://example.com/api/packages/xyz/",
                "purl": "pkg:deb/debian/adduser@3.118",
                "path": "package/dist/SassWarning.js",
                "type": "file",
                "sha1": "4bbc6d18a574e11fbdcbb74a24f1956bcedcc170",
            },
            {
                "package": "http://example.com/api/packages/zyx/",
                "purl": "pkg:deb/debian/adduser@3.118",
                "path": "package/dist/SassWarning.js",
                "type": "file",
                "sha1": "d6bfcf7d1f8a00cc639b3a186a52453d37c52f61",
            },
        ]

        package_data = package_data1.copy()
        package_data["uuid"] = uuid.uuid4()
        mock_match_resource.return_value = package_data

        buffer = io.StringIO()
        d2d.match_purldb_resources(
            self.project1,
            extensions=[".map", ".js"],
            matcher_func=d2d.match_purldb_resource,
            logger=buffer.write,
        )
        expected = (
            "Matching 1 .map, .js resources in PurlDB, using SHA1"
            "1 resources matched in PurlDB using 2 SHA1s"
        )
        self.assertEqual(expected, buffer.getvalue())

        package = self.project1.discoveredpackages.get()
        self.assertEqual(package_data["name"], package.name)
        self.assertNotEqual(package_data["uuid"], package.uuid)

    def test_scanpipe_pipes_d2d_map_javascript_post_purldb_match(self):
        to_map = self.data / "d2d-javascript" / "to" / "main.js.map"
        to_mini = self.data / "d2d-javascript" / "to" / "main.js"
        to_dir = (
            self.project1.codebase_path
            / "to/project.tar.zst/modules/apps/adaptive-media/"
            "adaptive-media-web/src/main/resources/META-INF/resources/"
            "adaptive_media/js"
        )
        to_dir.mkdir(parents=True)
        copy_input(to_mini, to_dir)
        copy_input(to_map, to_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        to_map_resources = self.project1.codebaseresources.filter(
            path=(
                "to/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web/src/main/resources/META-INF/resources/"
                "adaptive_media/js/main.js.map"
            )
        )

        package_data = package_data1.copy()
        package_data["uuid"] = uuid.uuid4()

        package, matched_resources_count = d2d.create_package_from_purldb_data(
            self.project1,
            to_map_resources,
            package_data,
            flag.MATCHED_TO_PURLDB_RESOURCE,
        )

        buffer = io.StringIO()
        d2d.map_javascript_post_purldb_match(
            self.project1,
            logger=buffer.write,
        )
        expected = (
            "Mapping 1 minified .js and .css resources based on existing PurlDB match."
        )
        self.assertEqual(expected, buffer.getvalue())

        result = package.codebase_resources.count()
        self.assertEqual(2, result)

    def test_scanpipe_pipes_d2d_map_javascript_path(self):
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "intelligent robotics platform.lpkg-extract/"
            "com.example.adaptive.media.web-0.0.5.jar-extract/META-INF/"
            "resources/adaptive_media/js"
        )
        to_dir.mkdir(parents=True)
        resource_files = [
            self.data / "d2d-javascript" / "to" / "main.js.map",
            self.data / "d2d-javascript" / "to" / "main.js",
        ]
        copy_inputs(resource_files, to_dir)

        from_input_location = self.data / "d2d-javascript" / "from" / "main.js"
        from_dir = (
            self.project1.codebase_path
            / "from/project.tar.zst/modules/apps/adaptive-media/"
            "adaptive-media-web/src/main/resources/META-INF/resources/"
            "adaptive_media/js"
        )
        from_dir.mkdir(parents=True)
        copy_input(from_input_location, from_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        from_resource = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web/src/main/resources/META-INF/resources/"
                "adaptive_media/js/main.js"
            )
        )

        buffer = io.StringIO()
        d2d.map_javascript_path(self.project1, logger=buffer.write)
        expected = "Mapping 1 to/ resources using javascript map against from/ codebase"
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(2, self.project1.codebaserelations.count())
        relation = self.project1.codebaserelations.all()
        self.assertEqual(from_resource, relation[0].from_resource)
        self.assertEqual(from_resource, relation[1].from_resource)

    def test_scanpipe_pipes_d2d_map_javascript_colocation(self):
        to_dir1 = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "intelligent robotics platform.lpkg-extract/"
            "com.example.adaptive.media.web-0.0.5.jar-extract/META-INF/"
            "resources/adaptive_media/js"
        )
        to_dir1.mkdir(parents=True)
        to_resource_files1 = [
            self.data / "d2d-javascript" / "to" / "main.js.map",
            self.data / "d2d-javascript" / "to" / "main.js",
        ]
        copy_inputs(to_resource_files1, to_dir1)

        to_resource_file3 = self.data / "d2d-javascript" / "to" / "unmain.js"
        to_dir3 = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "intelligent robotics platform.lpkg-extract/"
            "com.example.adaptive.media.web-0.0.5.jar-extract/META-INF/"
            "resources/adaptive_media/jsx"
        )
        to_dir3.mkdir(parents=True)
        copy_input(to_resource_file3, to_dir3)

        from_input_location = self.data / "d2d-javascript" / "from" / "main.js"
        from_dir1 = (
            self.project1.codebase_path
            / "from/project.tar.zst/modules/apps/adaptive-media/"
            "adaptive-media-web/src/main/resources/META-INF/resources/"
            "adaptive_media/js"
        )
        from_dir1.mkdir(parents=True)
        copy_input(from_input_location, from_dir1)

        from_dir2 = (
            self.project1.codebase_path
            / "from/project.tar.zst/modules/apps/adaptive-media/"
            "ambiguous-machine-cloud/src/main/resources/META-INF/resources/"
            "adaptive_media/js"
        )
        from_dir2.mkdir(parents=True)
        copy_input(from_input_location, from_dir2)

        from_dir3 = (
            self.project1.codebase_path
            / "from/project.tar.zst/modules/apps/adaptive-media/"
            "adaptive-media-web/src/main/resources/META-INF/resources/"
            "adaptive_media/jsx"
        )
        from_dir3.mkdir(parents=True)
        copy_input(from_input_location, from_dir3)

        pipes.collect_and_create_codebase_resources(self.project1)

        from_resource1 = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web/src/main/resources/META-INF/resources/"
                "adaptive_media/js/main.js"
            )
        )
        to_resource1 = self.project1.codebaseresources.get(
            path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "intelligent robotics platform.lpkg-extract/"
                "com.example.adaptive.media.web-0.0.5.jar-extract/META-INF/"
                "resources/adaptive_media/js/main.js"
            )
        )

        from_resource3 = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web/src/main/resources/META-INF/resources/"
                "adaptive_media/jsx/main.js"
            )
        )
        to_resource3 = self.project1.codebaseresources.get(
            path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "intelligent robotics platform.lpkg-extract/"
                "com.example.adaptive.media.web-0.0.5.jar-extract/META-INF/"
                "resources/adaptive_media/jsx/unmain.js"
            )
        )

        pipes.make_relation(
            from_resource=from_resource1,
            to_resource=to_resource1,
            map_type="js_compiled",
        )

        pipes.make_relation(
            from_resource=from_resource3,
            to_resource=to_resource3,
            map_type="js_compiled",
        )

        buffer = io.StringIO()
        d2d.map_javascript_colocation(self.project1, logger=buffer.write)
        expected = (
            "Mapping 1 to/ resources against from/ codebase "
            "based on neighborhood file mapping."
        )

        relation = self.project1.codebaserelations.filter(
            to_resource__path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "intelligent robotics platform.lpkg-extract/"
                "com.example.adaptive.media.web-0.0.5.jar-extract/META-INF/"
                "resources/adaptive_media/js/main.js.map"
            ),
        )
        from_expected = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web/src/main/resources/META-INF/resources/"
                "adaptive_media/js/main.js"
            )
        )

        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(from_expected, relation[0].from_resource)

    def test_map_thirdparty_npm_packages(self):
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "resources/node_modules/foo-bar"
        )
        to_input_location = self.data / "d2d-javascript/to/package.json"
        to_dir.mkdir(parents=True)
        copy_input(to_input_location, to_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        buffer = io.StringIO()
        d2d.map_thirdparty_npm_packages(self.project1, logger=buffer.write)

        package_json = self.project1.codebaseresources.get(
            path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/package.json"
            )
        )

        expected = (
            "Mapping 1 to/ resources against from/ codebase "
            "based on package.json metadata."
        )
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(1, self.project1.discoveredpackages.count())
        self.assertEqual("npm-package-lookup", package_json.status)

    def test_scanpipe_pipes_d2d_get_project_resources_qs(self):
        package_resource = make_resource_file(
            self.project1, "package.jar", is_archive=True
        )
        make_resource_directory(self.project1, "package.jar-extract/")
        make_resource_file(self.project1, "package.jar-extract/foo.class")

        directory_resource = make_resource_directory(self.project1, "directory1")
        make_resource_file(self.project1, "directory1/foo.txt")

        # This directory and its contents should not be returned
        make_resource_directory(self.project1, "directory100")
        make_resource_file(self.project1, "directory100/bar.txt")

        resources = [package_resource, directory_resource]
        resources_qs = d2d.get_project_resources_qs(self.project1, resources=resources)
        expected_paths = [
            "package.jar",
            "package.jar-extract/",
            "package.jar-extract/foo.class",
            "directory1",
            "directory1/foo.txt",
        ]
        expected_qs = self.project1.codebaseresources.filter(path__in=expected_paths)
        self.assertQuerySetEqual(expected_qs, resources_qs)

    def test_scanpipe_pipes_d2d_get_from_files_related_with_not_in_package_to_files(
        self,
    ):
        from_resource1 = make_resource_file(self.project1, "from/foo.java")
        to_resource1 = make_resource_file(self.project1, "to/foo.class")
        qs = d2d.get_from_files_related_with_not_in_package_to_files(self.project1)
        self.assertQuerySetEqual([], qs)

        pipes.make_relation(from_resource1, to_resource1, "java_to_class")
        qs = d2d.get_from_files_related_with_not_in_package_to_files(self.project1)
        self.assertQuerySetEqual([], qs)

        from_resource1.update(detected_license_expression="mit")
        qs = d2d.get_from_files_related_with_not_in_package_to_files(self.project1)
        self.assertQuerySetEqual([from_resource1], qs)

    def test_scanpipe_pipes_d2d_create_local_files_packages(self):
        from_resource1 = make_resource_file(
            self.project1,
            "from/foo.java",
            detected_license_expression="mit",
            copyrights=[
                {"copyright": "Copyright 1984"},
                {"copyright": "Copyright 2023"},
            ],
        )
        from_resource2 = make_resource_file(
            self.project1,
            "from/foo2.java",
            detected_license_expression="mit",
            copyrights=[{"copyright": "Copyright 2023"}],
        )
        to_resource1 = make_resource_file(self.project1, "to/foo.class")
        pipes.make_relation(from_resource1, to_resource1, "java_to_class")
        pipes.make_relation(from_resource2, to_resource1, "java_to_class")

        d2d.create_local_files_packages(self.project1)
        package = self.project1.discoveredpackages.get()
        self.assertEqual("local-files", package.type)
        self.assertEqual(self.project1.slug, package.namespace)
        self.assertEqual("mit", package.declared_license_expression)
        self.assertEqual("Copyright 2023\nCopyright 1984", package.copyright)

    @mock.patch("scanpipe.pipes.d2d._match_purldb_resources")
    def test_match_resources_with_no_java_source(self, mock_match_purldb_resources):
        mock_match_purldb_resources.return_value = True
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "resources/node_modules/foo-bar"
        )
        to_input_location = self.data / "d2d/find_java_packages/Foo.java"
        to_dir.mkdir(parents=True)
        copy_input(to_input_location, to_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        foo_java = self.project1.codebaseresources.get(
            path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/Foo.java"
            )
        )

        foo_java.update(status=flag.NO_JAVA_SOURCE)

        buffer = io.StringIO()
        d2d.match_resources_with_no_java_source(self.project1, logger=buffer.write)
        foo_java.refresh_from_db()

        expected = (
            f"Mapping 1 to/ resources with {flag.NO_JAVA_SOURCE} "
            "status in PurlDB using SHA1"
        )
        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(flag.REQUIRES_REVIEW, foo_java.status)

    @mock.patch("scanpipe.pipes.d2d._match_purldb_resources")
    def test_match_unmapped_resources(self, mock_match_purldb_resources):
        mock_match_purldb_resources.return_value = True
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "resources/node_modules/foo-bar"
        )
        to_dir.mkdir(parents=True)
        to_resource_files = [
            self.data / "d2d/find_java_packages/Baz.java",
            self.data / "d2d/about_files/expected.json",
        ]
        copy_inputs(to_resource_files, to_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        baz_java = self.project1.codebaseresources.get(
            path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/Baz.java"
            )
        )

        media_file = self.project1.codebaseresources.get(
            path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/expected.json"
            )
        )

        media_file.update(is_media=True)

        buffer = io.StringIO()
        d2d.match_unmapped_resources(self.project1, logger=buffer.write)

        baz_java.refresh_from_db()
        media_file.refresh_from_db()

        expected = "Mapping 1 to/ resources with empty status in PurlDB using SHA1"
        expected_requires_review_count = self.project1.codebaseresources.filter(
            status=flag.REQUIRES_REVIEW
        ).count()

        self.assertIn(expected, buffer.getvalue())
        self.assertEqual(1, expected_requires_review_count)
        self.assertEqual(flag.IGNORED_MEDIA_FILE, media_file.status)

    def test_flag_undeployed_resources(self):
        from_input_location = self.data / "d2d-javascript" / "from" / "main.js"
        from_dir = (
            self.project1.codebase_path
            / "from/project.tar.zst/modules/apps/adaptive-media/"
            "adaptive-media-web/src/main/resources/META-INF/resources/"
            "adaptive_media/js"
        )
        from_dir.mkdir(parents=True)
        copy_input(from_input_location, from_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        d2d.flag_undeployed_resources(self.project1)
        expected = self.project1.codebaseresources.filter(
            status=flag.NOT_DEPLOYED
        ).count()

        self.assertEqual(1, expected)

    def test_scanpipe_pipes_d2d_scan_ignored_to_files(self):
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/META-INF/foo-bar"
        )
        to_input_location = self.data / "d2d/find_java_packages/Foo.java"
        to_dir.mkdir(parents=True)
        copy_input(to_input_location, to_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        foo_java = self.project1.codebaseresources.get(
            path=("to/project.tar.zst-extract/META-INF/foo-bar/Foo.java")
        )
        foo_java.update(status=flag.IGNORED_FROM_CONFIG)

        # Create another file that is already scanned but should not be
        # reverted
        other_scanned = make_resource_file(
            self.project1, "to/other_scanned.txt", status=flag.SCANNED
        )

        d2d.scan_ignored_to_files(self.project1)
        foo_java.refresh_from_db()
        other_scanned.refresh_from_db()

        self.assertEqual(flag.IGNORED_FROM_CONFIG, foo_java.status)
        self.assertEqual(flag.SCANNED, other_scanned.status)

    def test_scan_unmapped_to_files(self):
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "resources/node_modules/foo-bar"
        )
        to_input_location = self.data / "d2d/find_java_packages/Foo.java"
        to_dir.mkdir(parents=True)
        copy_input(to_input_location, to_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        foo_java = self.project1.codebaseresources.get(
            path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/Foo.java"
            )
        )
        foo_java.update(status=flag.REQUIRES_REVIEW)

        # Create another file that is already scanned but should not be
        # reverted
        other_scanned = make_resource_file(
            self.project1, "to/other_scanned.txt", status=flag.SCANNED
        )

        d2d.scan_unmapped_to_files(self.project1)
        foo_java.refresh_from_db()
        other_scanned.refresh_from_db()

        self.assertEqual(flag.REQUIRES_REVIEW, foo_java.status)
        self.assertEqual(flag.SCANNED, other_scanned.status)

    def test_flag_deployed_from_resources_with_missing_license(self):
        from_dir = (
            self.project1.codebase_path
            / "from/project.tar.zst-extract/osgi/marketplace/"
            "resources/node_modules/foo-bar"
        )
        from_dir.mkdir(parents=True)
        from_resource_files = [
            self.data / "d2d/find_java_packages/Foo.java",
            self.data / "d2d/find_java_packages/Baz.java",
            self.data / "d2d/about_files/expected.json",
            self.data / "codebase/a.txt",
        ]
        copy_inputs(from_resource_files, from_dir)
        pipes.collect_and_create_codebase_resources(self.project1)

        from1 = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/Foo.java"
            )
        )
        from2 = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/Baz.java"
            )
        )
        from3 = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/expected.json"
            )
        )
        from4 = self.project1.codebaseresources.get(
            path=(
                "from/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/a.txt"
            )
        )

        from1.update(status=flag.SCANNED)
        from2.update(status=flag.SCANNED)
        from3.update(status=flag.SCANNED)
        from4.update(status=flag.SCANNED)

        from1.update(is_media=True)
        from3.update(detected_license_expression="free-unknown")
        from4.update(extension=".pdf")

        d2d.flag_deployed_from_resources_with_missing_license(
            self.project1, doc_extensions=[".pdf"]
        )

        from1.refresh_from_db()
        from2.refresh_from_db()
        from3.refresh_from_db()
        from4.refresh_from_db()

        self.assertEqual(flag.IGNORED_MEDIA_FILE, from1.status)
        self.assertEqual(flag.NO_LICENSES, from2.status)
        self.assertEqual(flag.UNKNOWN_LICENSE, from3.status)
        self.assertEqual(flag.IGNORED_DOC_FILE, from4.status)

    def test_scanpipe_pipes_d2d_handle_dangling_deployed_legal_files(self):
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "resources/node_modules/foo-bar"
        )
        to_dir.mkdir(parents=True)
        to_resource_files = [
            self.data / "d2d/legal/project.LICENSE",
            self.data / "d2d/legal/license_mit.md",
            self.data / "d2d/legal/project_notice.txt",
            self.data / "codebase/a.txt",
        ]
        copy_inputs(to_resource_files, to_dir)
        pipes.collect_and_create_codebase_resources(self.project1)

        d2d.handle_dangling_deployed_legal_files(project=self.project1, logger=None)

        expected = self.project1.codebaseresources.filter(
            status=flag.REVIEW_DANGLING_LEGAL_FILE
        ).count()

        self.assertEqual(3, expected)

    def test_scanpipe_pipes_flag_whitespace_files(self):
        to_dir = (
            self.project1.codebase_path / "to/project.tar.zst-extract/osgi/marketplace/"
            "resources/node_modules/foo-bar"
        )
        to_dir.mkdir(parents=True)
        to_resource_files = [
            self.data / "d2d/non_whitespace_file.txt",
            self.data / "d2d/whitespace_file.txt",
        ]
        copy_inputs(to_resource_files, to_dir)
        pipes.collect_and_create_codebase_resources(self.project1)

        whitespace_resource = self.project1.codebaseresources.get(
            path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/whitespace_file.txt"
            )
        )
        non_whitespace_resource = self.project1.codebaseresources.get(
            path=(
                "to/project.tar.zst-extract/osgi/marketplace/"
                "resources/node_modules/foo-bar/non_whitespace_file.txt"
            )
        )

        d2d.flag_whitespace_files(project=self.project1)
        whitespace_resource.refresh_from_db()
        non_whitespace_resource.refresh_from_db()

        self.assertEqual(flag.IGNORED_WHITESPACE_FILE, whitespace_resource.status)
        self.assertNotEqual(
            flag.IGNORED_WHITESPACE_FILE, non_whitespace_resource.status
        )

    def test_scanpipe_pipes_create_about_file_indexes(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d/about_files/to-with-jar.zip",
            self.data / "d2d/about_files/from-with-about-file.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)

        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]

        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )

        pipes.collect_and_create_codebase_resources(self.project1)

        from_about_files = (
            self.project1.codebaseresources.files()
            .from_codebase()
            .filter(extension=".ABOUT")
        )
        about_file_indexes = d2d.AboutFileIndexes.create_indexes(
            project=self.project1,
            from_about_files=from_about_files,
        )

        about_path = "from/flume-ng-node-1.9.0-sources.ABOUT"
        about_notice_path = "from/flume-ng-node-1.9.0-sources.NOTICE"

        about_notice_file = self.project1.codebaseresources.get(path=about_notice_path)

        self.assertIn(
            about_path, list(about_file_indexes.about_resources_by_path.keys())
        )
        about_regex = d2d.convert_glob_to_django_regex(
            glob_pattern="*flume-ng-node-*.jar*"
        )
        self.assertEqual(
            about_file_indexes.regex_by_about_path.get(about_path), about_regex
        )
        self.assertEqual(
            about_file_indexes.about_pkgdata_by_path.get(about_path).get("name"),
            "log4j",
        )
        self.assertIn(
            about_notice_file, about_file_indexes.get_about_file_companions(about_path)
        )
        to_resource = self.project1.codebaseresources.get(
            path=(
                "to/flume-ng-node-1.9.0.jar-extract/org/apache/"
                "flume/node/AbstractZooKeeperConfigurationProvider.class"
            )
        )
        self.assertEqual(
            about_file_indexes.get_matched_about_path(to_resource), about_path
        )

    def test_scanpipe_pipes_map_d2d_using_about(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d/about_files/to-with-jar.zip",
            self.data / "d2d/about_files/from-with-about-file.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)

        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]

        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )

        pipes.collect_and_create_codebase_resources(self.project1)

        from_about_files = (
            self.project1.codebaseresources.files()
            .from_codebase()
            .filter(extension=".ABOUT")
        )
        about_file_indexes = d2d.AboutFileIndexes.create_indexes(
            project=self.project1,
            from_about_files=from_about_files,
        )

        to_resources = self.project1.codebaseresources.to_codebase()
        about_file_indexes.map_deployed_to_devel_using_about(
            to_resources=to_resources,
        )

        about_path = "from/flume-ng-node-1.9.0-sources.ABOUT"
        to_resource = self.project1.codebaseresources.get(
            path=(
                "to/flume-ng-node-1.9.0.jar-extract/org/apache/"
                "flume/node/AbstractZooKeeperConfigurationProvider.class"
            )
        )
        self.assertIn(
            to_resource,
            about_file_indexes.mapped_resources_by_aboutpath.get(about_path),
        )

        about_file_indexes.create_about_packages_relations(self.project1)

    def test_scanpipe_pipes_d2d_match_purldb_resources_post_process(self):
        to_map = self.data / "d2d-javascript" / "to" / "main.js.map"
        to_mini = self.data / "d2d-javascript" / "to" / "main.js"
        to_dir = (
            self.project1.codebase_path
            / "to/project.tar.zst/modules/apps/adaptive-media/"
            "adaptive-media-web-extract/src/main/resources/META-INF/resources/"
            "adaptive_media/js"
        )
        to_dir.mkdir(parents=True)
        copy_inputs([to_map, to_mini], to_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        to_resources = self.project1.codebaseresources.filter(
            path__startswith=(
                "to/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web-extract/src/main/resources/META-INF/resources/"
                "adaptive_media/js/main.js"
            )
        )

        to_mini_resource = self.project1.codebaseresources.filter(
            path=(
                "to/project.tar.zst/modules/apps/adaptive-media/"
                "adaptive-media-web-extract/src/main/resources/META-INF/resources/"
                "adaptive_media/js/main.js"
            )
        )

        dummy_package_data1 = package_data1.copy()
        dummy_package_data1["uuid"] = uuid.uuid4()
        package1, _ = d2d.create_package_from_purldb_data(
            self.project1,
            to_resources,
            dummy_package_data1,
            flag.MATCHED_TO_PURLDB_RESOURCE,
        )

        dummy_package_data2 = package_data2.copy()
        dummy_package_data2["uuid"] = uuid.uuid4()
        package2, _ = d2d.create_package_from_purldb_data(
            self.project1,
            to_mini_resource,
            dummy_package_data2,
            flag.MATCHED_TO_PURLDB_RESOURCE,
        )

        buffer = io.StringIO()
        d2d.match_purldb_resources_post_process(
            self.project1,
            logger=buffer.write,
        )
        expected = (
            f"Refining matching for 1 {flag.MATCHED_TO_PURLDB_RESOURCE} archives."
        )
        self.assertIn(expected, buffer.getvalue())

        package1_resource_count = package1.codebase_resources.count()
        package2_resource_count = package2.codebase_resources.count()

        self.assertEqual(2, package1_resource_count)
        self.assertEqual(0, package2_resource_count)

    def test_scanpipe_pipes_d2d_map_elfs(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-elfs/to-data.zip",
            self.data / "d2d-elfs/from-data.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.map_elfs_with_dwarf_paths(project=self.project1, logger=buffer.write)
        self.assertEqual(
            1,
            CodebaseRelation.objects.filter(
                project=self.project1, map_type="dwarf_included_paths"
            ).count(),
        )

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_map_go_paths(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-go/to-data.zip",
            self.data / "d2d-go/from-data.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.map_go_paths(project=self.project1, logger=buffer.write)
        self.assertEqual(
            1,
            CodebaseRelation.objects.filter(
                project=self.project1, map_type="go_file_paths"
            ).count(),
        )
        self.assertEqual(
            1,
            CodebaseResource.objects.filter(
                project=self.project1, status="requires-review"
            ).count(),
        )

    def test_scanpipe_pipes_d2d_map_ruby(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-ruby/to-sentry-delayed_job-5.22.1.gem",
            self.data / "d2d-ruby/from-sentry-ruby-5.22.1.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.map_checksum(
            project=self.project1, checksum_field="sha1", logger=buffer.write
        )
        ruby_config = d2d_config.get_ecosystem_config(ecosystem="Ruby")
        d2d.ignore_unmapped_resources_from_config(
            project=self.project1,
            patterns_to_ignore=ruby_config.deployed_resource_path_exclusions,
            logger=buffer.write,
        )
        d2d.flag_undeployed_resources(project=self.project1)
        self.assertEqual(
            39,
            CodebaseRelation.objects.filter(
                project=self.project1, map_type="sha1"
            ).count(),
        )
        self.assertEqual(
            0,
            CodebaseResource.objects.filter(
                project=self.project1, status="requires-review"
            ).count(),
        )

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_extract_binary_symbols_from_resources(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-macho/to-ollama.zip",
            self.data / "d2d-macho/from-ollama.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()

        binary_resource = self.project1.codebaseresources.get(
            path="to/libggml-cpu-skylakex.so"
        )
        d2d.extract_binary_symbols_from_resources(
            resources=[binary_resource],
            binary_symbols_func=d2d.collect_and_parse_macho_symbols,
            logger=buffer.write,
        )
        symbols = binary_resource.extra_data.get("macho_symbols")
        self.assertNotEqual(symbols, [])

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_extract_binary_symbols(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-macho/to-ollama.zip",
            self.data / "d2d-macho/from-ollama.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.extract_binary_symbols(
            project=self.project1, options=["Go"], logger=buffer.write
        )
        binary_resource = self.project1.codebaseresources.get(
            path="to/libggml-cpu-skylakex.so"
        )
        symbols = binary_resource.extra_data.get("macho_symbols")
        self.assertNotEqual(symbols, [])

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_map_rust_symbols(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-rust/to-trustier-binary-linux.tar.gz",
            self.data / "d2d-rust/from-trustier-source.tar.gz",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.extract_binary_symbols(
            project=self.project1, options=["Rust"], logger=buffer.write
        )
        d2d.map_rust_binaries_with_symbols(project=self.project1, logger=buffer.write)
        self.assertEqual(
            2,
            CodebaseRelation.objects.filter(
                project=self.project1, map_type="rust_symbols"
            ).count(),
        )
        self.assertEqual(
            0,
            CodebaseResource.objects.filter(
                project=self.project1, status="requires-review"
            ).count(),
        )

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_map_go_symbols(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-macho/to-ollama.zip",
            self.data / "d2d-macho/from-ollama.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.extract_binary_symbols(
            project=self.project1, options=["Go"], logger=buffer.write
        )
        d2d.map_go_binaries_with_symbols(project=self.project1, logger=buffer.write)
        self.assertEqual(
            1,
            CodebaseRelation.objects.filter(
                project=self.project1, map_type="macho_symbols"
            ).count(),
        )

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_map_elf_symbols(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-elfs/to-brotli-d2d.zip",
            self.data / "d2d-elfs/from-brotli-d2d.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.extract_binary_symbols(
            project=self.project1, options=["Elf"], logger=buffer.write
        )
        d2d.map_elfs_binaries_with_symbols(project=self.project1, logger=buffer.write)
        self.assertEqual(
            7,
            CodebaseRelation.objects.filter(
                project=self.project1, map_type="elf_symbols"
            ).count(),
        )

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_map_macho_symbols(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-macho/from-lumen.zip",
            self.data / "d2d-macho/to-lumen.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.extract_binary_symbols(
            project=self.project1, options=["MacOS"], logger=buffer.write
        )
        d2d.map_macho_binaries_with_symbols(project=self.project1, logger=buffer.write)
        self.assertEqual(
            9,
            CodebaseRelation.objects.filter(
                project=self.project1, map_type="macho_symbols"
            ).count(),
        )

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_map_python_pyx(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-python/to-intbitset.whl",
            self.data / "d2d-python/from-intbitset.tar.gz",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(self.project1.codebase_path, recurse=True)
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.extract_binary_symbols(
            project=self.project1, options=["Python"], logger=buffer.write
        )
        d2d.map_python_pyx_to_binaries(project=self.project1, logger=buffer.write)
        pyx_match_relations = CodebaseRelation.objects.filter(
            project=self.project1, map_type="python_pyx_match"
        )
        self.assertEqual(1, pyx_match_relations.count())

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_map_winpe_symbols(self):
        input_dir = self.project1.input_path
        input_resources = [
            self.data / "d2d-winpe/to-translucent.zip",
            self.data / "d2d-winpe/from-translucent.zip",
        ]
        copy_inputs(input_resources, input_dir)
        self.from_files, self.to_files = d2d.get_inputs(self.project1)
        inputs_with_codebase_path_destination = [
            (self.from_files, self.project1.codebase_path / d2d.FROM),
            (self.to_files, self.project1.codebase_path / d2d.TO),
        ]
        for input_files, codebase_path in inputs_with_codebase_path_destination:
            for input_file_path in input_files:
                scancode.extract_archive(input_file_path, codebase_path)

        scancode.extract_archives(
            self.project1.codebase_path,
            recurse=True,
        )
        pipes.collect_and_create_codebase_resources(self.project1)
        buffer = io.StringIO()
        d2d.extract_binary_symbols(
            project=self.project1, options=["Windows"], logger=buffer.write
        )
        d2d.map_winpe_binaries_with_symbols(project=self.project1, logger=buffer.write)
        self.assertEqual(
            3,
            CodebaseRelation.objects.filter(
                project=self.project1, map_type="winpe_symbols"
            ).count(),
        )

    @mock.patch("scanpipe.pipes.purldb.match_resources")
    def test_scanpipe_pipes_d2d_match_purldb_resource_no_package_data(
        self, mock_match_resource
    ):
        to_1 = make_resource_file(
            self.project1,
            "to/notice.NOTICE",
            sha1="4bd631df28995c332bf69d9d4f0f74d7ee089598",
        )
        resources_by_sha1 = {to_1.sha1: [to_1]}

        resource_data = resource_data1.copy()
        resource_data["package"] = "example.com/package-instance"
        mock_match_resource.return_value = [resource_data]

        resources_by_sha1, matched_count, sha1_count = d2d.match_sha1s_to_purldb(
            project=self.project1,
            resources_by_sha1=resources_by_sha1,
            matcher_func=d2d.match_purldb_resource,
            package_data_by_purldb_urls={},
        )
        self.assertFalse(resources_by_sha1)
        self.assertEqual(0, matched_count)
        self.assertEqual(1, sha1_count)

        package_count = self.project1.discoveredpackages.count()
        self.assertEqual(0, package_count)

    def test_scanpipe_pipes_d2d_match_purldb_resources_post_process_with_special_char(
        self,
    ):
        to_map = self.data / "d2d-javascript" / "to" / "main.js.map"

        to_dir = self.project1.codebase_path / "to/lib/Matplot++/nodesoup.lib-extract"
        to_dir.mkdir(parents=True)
        copy_inputs([to_map], to_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        to_resources = self.project1.codebaseresources.filter(
            path__startswith=("to/lib/Matplot++/nodesoup.lib-extract/main.js")
        )

        dummy_package_data1 = package_data1.copy()
        dummy_package_data1["uuid"] = uuid.uuid4()
        d2d.create_package_from_purldb_data(
            self.project1,
            to_resources,
            dummy_package_data1,
            flag.MATCHED_TO_PURLDB_RESOURCE,
        )

        buffer = io.StringIO()
        try:
            d2d.match_purldb_resources_post_process(
                self.project1,
                logger=buffer.write,
            )
        except DataError:
            self.fail("DataError was raised, but it should not occur.")

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_map_javascript_symbols(self):
        to_dir = self.project1.codebase_path / "to/project.tar.zst-extract/"
        to_resource_file = (
            self.data / "d2d-javascript/symbols/cesium/to_chunk-CNPP6TQ2.js"
        )
        to_dir.mkdir(parents=True)
        copy_input(to_resource_file, to_dir)

        from_input_location = (
            self.data / "d2d-javascript/symbols/cesium/from_EllipseGeometryLibrary.js"
        )
        from_dir = self.project1.codebase_path / "from/project.zip/"
        from_dir.mkdir(parents=True)
        copy_input(from_input_location, from_dir)

        pipes.collect_and_create_codebase_resources(self.project1)

        buffer = io.StringIO()
        d2d.map_javascript_symbols(self.project1, logger=buffer.write)
        expected = (
            "Mapping 1 JavaScript resources using symbols against 1 from/ codebase."
        )
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(1, self.project1.codebaserelations.count())
        self.assertEqual(
            1,
            self.project1.codebaserelations.filter(
                map_type="javascript_symbols"
            ).count(),
        )

    @skipIf(sys.platform == "darwin", "Test is failing on macOS")
    def test_scanpipe_pipes_d2d_map_javascript_strings(self):
        to_dir = self.project1.codebase_path / "to/project.tar.zst-extract/"
        to_resource_file = (
            self.data / "d2d-javascript/strings/cesium/source-decodeI3S.js"
        )
        to_dir.mkdir(parents=True)
        copy_input(to_resource_file, to_dir)

        from_input_location = (
            self.data / "d2d-javascript/strings/cesium/deployed-decodeI3S.js"
        )
        from_dir = self.project1.codebase_path / "from/project.zip/"
        from_dir.mkdir(parents=True)
        copy_input(from_input_location, from_dir)

        pipes.collect_and_create_codebase_resources(self.project1)
        symbols.collect_and_store_tree_sitter_symbols_and_strings(
            project=self.project1,
        )

        buffer = io.StringIO()
        d2d.map_javascript_strings(self.project1, logger=buffer.write)
        expected = (
            "Mapping 1 JavaScript resources using string "
            "literals against 1 from/ resources."
        )
        self.assertIn(expected, buffer.getvalue())

        self.assertEqual(1, self.project1.codebaserelations.count())
        self.assertEqual(
            1,
            self.project1.codebaserelations.filter(
                map_type="javascript_strings",
            ).count(),
        )

    def test_scanpipe_d2d_load_ecosystem_config(self):
        pipeline_name = "map_deploy_to_develop"
        selected_groups = ["Ruby", "Java", "JavaScript"]

        run = self.project1.add_pipeline(
            pipeline_name=pipeline_name, selected_groups=selected_groups
        )
        pipeline = run.make_pipeline_instance()
        d2d_config.load_ecosystem_config(pipeline=pipeline, options=selected_groups)

        expected_ecosystem_config = (
            self.data / "d2d" / "config" / "ecosystem_config.json"
        )
        with open(expected_ecosystem_config) as f:
            expected_extra_data = json.load(f)

        self.assertEqual(expected_extra_data, asdict(pipeline.ecosystem_config))

    def test_scanpipe_pipes_d2d_extract_protobuf_base_name(self):
        """Test the protobuf base name extraction function."""
        test_cases = [
            ("command_request_pb2.py", "command_request"),
            ("connection_request_pb2.pyi", "connection_request"),
            ("response_pb2.py", "response"),
            ("user_pb3.py", "user"),
            ("data_pb2.pyi", "data"),
            ("regular_file.py", None),
            ("not_protobuf.pyi", None),
            ("pb2_standalone.py", None),
        ]
        for filename, expected in test_cases:
            with self.subTest(filename=filename):
                result = d2d.extract_protobuf_base_name(filename)
                self.assertEqual(expected, result)

    def test_scanpipe_pipes_d2d_map_python_protobuf_files(self):
        """Test protobuf file mapping functionality."""
        from1 = make_resource_file(
            self.project1,
            path="from/valkey_glide-2.0.1/glide-core/src/protobuf/command_request.proto",
        )
        from2 = make_resource_file(
            self.project1,
            path="from/valkey_glide-2.0.1/glide-core/src/protobuf/connection_request.proto",
        )
        from3 = make_resource_file(
            self.project1,
            path="from/valkey_glide-2.0.1/glide-core/src/protobuf/response.proto",
        )
        to1 = make_resource_file(
            self.project1,
            path="to/glide/protobuf/command_request_pb2.py",
        )
        to2 = make_resource_file(
            self.project1,
            path="to/glide/protobuf/command_request_pb2.pyi",
        )
        to3 = make_resource_file(
            self.project1,
            path="to/glide/protobuf/connection_request_pb2.py",
        )
        to4 = make_resource_file(
            self.project1,
            path="to/glide/protobuf/connection_request_pb2.pyi",
        )
        to5 = make_resource_file(
            self.project1,
            path="to/glide/protobuf/response_pb2.py",
        )
        to6 = make_resource_file(
            self.project1,
            path="to/glide/protobuf/response_pb2.pyi",
        )
        d2d.map_python_protobuf_files(self.project1)
        relations = self.project1.codebaserelations.filter(map_type="protobuf_mapping")
        self.assertEqual(6, relations.count())
        expected_mappings = [
            (from1, to1, "command_request"),
            (from1, to2, "command_request"),
            (from2, to3, "connection_request"),
            (from2, to4, "connection_request"),
            (from3, to5, "response"),
            (from3, to6, "response"),
        ]
        for from_resource, to_resource, expected_base_name in expected_mappings:
            relation = relations.filter(
                from_resource=from_resource, to_resource=to_resource
            ).first()
            self.assertIsNotNone(relation)
            self.assertEqual(
                expected_base_name, relation.extra_data["protobuf_base_name"]
            )

    def test_scanpipe_pipes_d2d_map_python_protobuf_files_no_proto_files(self):
        """Test protobuf mapping when no .proto files exist."""
        make_resource_file(
            self.project1,
            path="to/glide/protobuf/command_request_pb2.py",
        )
        d2d.map_python_protobuf_files(self.project1)
        relations = self.project1.codebaserelations.filter(map_type="protobuf_mapping")
        self.assertEqual(0, relations.count())

    def test_scanpipe_pipes_d2d_map_python_protobuf_files_no_py_files(self):
        """Test protobuf mapping when no .py/.pyi files exist."""
        make_resource_file(
            self.project1,
            path="from/valkey_glide-2.0.1/glide-core/src/protobuf/command_request.proto",
        )
        d2d.map_python_protobuf_files(self.project1)
        relations = self.project1.codebaserelations.filter(map_type="protobuf_mapping")
        self.assertEqual(0, relations.count())

    def test_scanpipe_pipes_d2d_is_generated_code_markers(self):
        """Test individual bytecode markers for generated code detection."""
        test_cases = [
            (
                b"some bytes Ljavax/annotation/Generated; other bytes",
                "@Generated annotation detected",
            ),
            (
                b"bytes Lcom/google/protobuf/GeneratedMessageV3; bytes",
                "Google Protocol Buffers",
            ),
            (b"bytes Lorg/apache/thrift/TBase; bytes", "Apache Thrift IDL compiler"),
            (
                b"bytes Lorg/apache/avro/specific/SpecificRecordBase; bytes",
                "Apache Avro schema compiler",
            ),
            (
                b"bytes Ljavax/xml/bind/annotation/XmlRegistry; bytes",
                "JAXB XmlRegistry",
            ),
            (b"bytes Ljavax/xml/ws/WebServiceClient; bytes", "JAX-WS client stub"),
            (
                b"bytes Lio/grpc/stub/annotations/GrpcGenerated; bytes",
                "gRPC compiler stub",
            ),
            (b"bytes Lorg/immutables/value/Generated; bytes", "Immutables Generated"),
            (b"random un-matched bytecode", None),
        ]
        for class_bytes, expected_reason in test_cases:
            with self.subTest(class_bytes=class_bytes):
                self.assertEqual(expected_reason, d2d.is_generated_code(class_bytes))

    def test_scanpipe_pipes_d2d_is_generated_code_clusters(self):
        """Test JAXB cluster heuristic bytecode detection."""
        javax_cluster = (
            b"bytes Ljavax/xml/bind/annotation/XmlAccessorType; "
            b"and Ljavax/xml/bind/annotation/XmlType; bytes"
        )
        jakarta_cluster = (
            b"bytes Ljakarta/xml/bind/annotation/XmlAccessorType; "
            b"and Ljakarta/xml/bind/annotation/XmlType; bytes"
        )

        self.assertEqual(
            "JAXB schema compiler cluster (@XmlAccessorType + @XmlType)",
            d2d.is_generated_code(javax_cluster),
        )
        self.assertEqual(
            "Jakarta JAXB schema compiler cluster (@XmlAccessorType + @XmlType)",
            d2d.is_generated_code(jakarta_cluster),
        )

    def test_scanpipe_pipes_d2d_flag_generated_file_by_path(self):
        """
        Test flag_generated_file identifying files by path pattern
        containing '/generated/'.
        """
        resource = make_resource_file(
            self.project1,
            path="to/target/generated-sources/annotations/com/test.class",
        )

        d2d.flag_generated_file(self.project1)

        resource.refresh_from_db()
        self.assertEqual(flag.GENERATED, resource.status)
        self.assertEqual(
            "Path pattern matches generated directory convention",
            resource.extra_data.get("Generated code"),
        )

    @mock.patch("scanpipe.pipes.d2d.Path.read_bytes")
    def test_scanpipe_pipes_d2d_flag_generated_file_by_bytecode(self, mock_read_bytes):
        """Test flag_generated_file identifying files by reading bytecode."""
        mock_read_bytes.return_value = (
            b"some header bytes Lcom/google/protobuf/GeneratedMessageV3; tail bytes"
        )
        resource = make_resource_file(
            self.project1,
            path="to/com/test.class",
        )

        d2d.flag_generated_file(self.project1)

        resource.refresh_from_db()
        self.assertEqual(flag.GENERATED, resource.status)
        self.assertEqual(
            "Google Protocol Buffers",
            resource.extra_data.get("Generated code"),
        )
