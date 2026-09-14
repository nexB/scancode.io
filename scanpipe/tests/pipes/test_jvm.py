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

from scanpipe.pipes import jvm

java_code = """
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache license, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the license for the specific language governing permissions and
 * limitations under the license.
 */
package org.apache.logging.log4j.core;

import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
"""

java_package_too_far_down = ("\n" * 501) + "package org.apache.logging.log4j.core;"

# Java code where class name differs from filename (like lombok's DelombokTask.java)
java_code_different_class_name = """
package lombok.delombok.ant;

import org.apache.tools.ant.Task;

/**
 * Ant tasks for delombok.
 * This file is named DelombokTask.java but contains class Tasks.
 */
class Tasks {
    public static class Delombok extends Task {
        public void execute() {}
    }

    public static class Format extends Task {
        public void execute() {}
    }
}
"""

# Java code with multiple classes including interface and enum
java_code_multiple_types = """
package com.example;

public class MainClass {
    // Main implementation
}

interface SomeInterface {
    void doSomething();
}

enum Status {
    ACTIVE, INACTIVE
}

abstract class AbstractBase {
    public abstract void process();
}
"""


class ScanPipeJvmTest(TestCase):
    data = Path(__file__).parent.parent / "data"

    def test_scanpipe_pipes_jvm_find_java_package(self):
        package = jvm.JavaLanguage.find_source_package(java_code.splitlines())
        self.assertEqual({"java_package": "org.apache.logging.log4j.core"}, package)

    def test_scanpipe_pipes_jvm_find_java_package_with_spaces(self):
        lines = ["   package    foo.back ;  # dsasdasdasdasdasda.asdasdasd"]
        package = jvm.JavaLanguage.find_source_package(lines)
        self.assertEqual({"java_package": "foo.back"}, package)

    def test_scanpipe_pipes_jvm_find_java_package_return_None(self):
        package = jvm.JavaLanguage.find_source_package(
            java_package_too_far_down.splitlines()
        )
        self.assertIsNone(package)

    def test_scanpipe_pipes_jvm_get_java_package(self):
        input_location = self.data / "jvm" / "common.java"
        package = jvm.JavaLanguage.get_source_package(input_location)
        self.assertEqual({"java_package": "org.apache.logging.log4j.core"}, package)

    def test_scanpipe_pipes_jvm_get_java_package_with_string(self):
        input_location = self.data / "jvm" / "common.java"
        package = jvm.JavaLanguage.get_source_package(str(input_location))
        self.assertEqual({"java_package": "org.apache.logging.log4j.core"}, package)

    def test_scanpipe_pipes_jvm_get_java_package_too_far_down(self):
        input_location = self.data / "jvm" / "no-package.java"
        package = jvm.JavaLanguage.get_source_package(input_location)
        self.assertIsNone(package)

    def test_scanpipe_pipes_jvm_get_source_java_path(self):
        njp = jvm.JavaLanguage.get_source_path("foo/org/common/Bar.class", ".java")
        self.assertEqual("foo/org/common/Bar.java", njp)

    def test_scanpipe_pipes_jvm_get_source_java_path_with_inner_class(self):
        njp = jvm.JavaLanguage.get_source_path(
            "foo/org/common/Bar$inner.class", ".java"
        )
        self.assertEqual("foo/org/common/Bar$inner.java", njp)

    def test_scanpipe_pipes_jvm_get_normalized_java_path(self):
        njp = jvm.JavaLanguage.get_normalized_path("foo/org/common/Bar.class", ".java")
        self.assertEqual("foo/org/common/Bar.java", njp)

    def test_scanpipe_pipes_jvm_get_normalized_java_path_with_inner_class(self):
        njp = jvm.JavaLanguage.get_normalized_path(
            "foo/org/common/Bar$inner.class", ".java"
        )
        self.assertEqual("foo/org/common/Bar.java", njp)

    def test_scanpipe_pipes_jvm_get_normalized_java_path_with_logging_annotation(self):
        njp = jvm.JavaLanguage.get_normalized_path(
            "foo/org/common/Bar_$logger.class", ".java"
        )
        self.assertEqual("foo/org/common/Bar.java", njp)

    def test_scanpipe_pipes_jvm_get_fully_qualified_java_path(self):
        fqjp = jvm.get_fully_qualified_path("org.common", "Bar.java")
        self.assertEqual("org/common/Bar.java", fqjp)

    def test_scanpipe_pipes_jvm_find_java_package_with_different_class_name(self):
        """Test that find_source_package extracts class names differing from filename."""
        result = jvm.JavaLanguage.find_source_package(
            java_code_different_class_name.splitlines()
        )
        self.assertEqual("lombok.delombok.ant", result["java_package"])
        # The class name "Tasks" differs from what would be the filename
        self.assertIn("Tasks", result["java_classes"])
        # Also check for inner classes
        self.assertIn("Delombok", result["java_classes"])
        self.assertIn("Format", result["java_classes"])

    def test_scanpipe_pipes_jvm_find_java_package_with_multiple_types(self):
        """Test that find_source_package extracts all class/interface/enum names."""
        result = jvm.JavaLanguage.find_source_package(
            java_code_multiple_types.splitlines()
        )
        self.assertEqual("com.example", result["java_package"])
        classes = result["java_classes"]
        self.assertIn("MainClass", classes)
        self.assertIn("SomeInterface", classes)
        self.assertIn("Status", classes)
        self.assertIn("AbstractBase", classes)

    def test_scanpipe_pipes_jvm_get_indexable_qualified_paths_with_class_names(self):
        """Test get_indexable_qualified_paths_from_values yields class name paths."""
        resource_values = [
            (
                1,
                "DelombokTask.java",
                {
                    "java_package": "lombok.delombok.ant",
                    "java_classes": ["Tasks", "Delombok"],
                },
            ),
        ]
        paths = list(
            jvm.JavaLanguage.get_indexable_qualified_paths_from_values(resource_values)
        )
        # Should yield: filename path, and paths for each class name that differs
        self.assertEqual(3, len(paths))
        # First is the original filename-based path
        self.assertEqual((1, "lombok/delombok/ant/DelombokTask.java"), paths[0])
        # Then paths for class names that differ from filename
        self.assertEqual((1, "lombok/delombok/ant/Tasks.java"), paths[1])
        self.assertEqual((1, "lombok/delombok/ant/Delombok.java"), paths[2])


class ScanPipeJvmScalaTest(TestCase):
    data = Path(__file__).parent.parent / "data"

    scala_code = """
    package org.apache.logging.log4j.scala
    import scala.concurrent.Future
    """

    scala_package_too_far_down = ("\n" * 501) + "package org.apache.logging.log4j.scala"

    def test_scanpipe_pipes_jvm_find_scala_package(self):
        package = jvm.ScalaLanguage.find_source_package(self.scala_code.splitlines())
        self.assertEqual({"scala_package": "org.apache.logging.log4j.scala"}, package)

    def test_scanpipe_pipes_jvm_find_scala_package_with_spaces(self):
        lines = ["   package    foo.bar.baz ;"]
        package = jvm.ScalaLanguage.find_source_package(lines)
        self.assertEqual({"scala_package": "foo.bar.baz"}, package)

    def test_scanpipe_pipes_jvm_find_scala_package_return_None(self):
        package = jvm.ScalaLanguage.find_source_package(
            self.scala_package_too_far_down.splitlines()
        )
        self.assertIsNone(package)

    def test_scanpipe_pipes_jvm_get_normalized_scala_path(self):
        njp = jvm.ScalaLanguage.get_normalized_path(
            "foo/org/common/Bar.class", ".scala"
        )
        self.assertEqual("foo/org/common/Bar.scala", njp)

    def test_scanpipe_pipes_jvm_get_normalized_scala_path_with_inner_class(self):
        njp = jvm.ScalaLanguage.get_normalized_path(
            "foo/org/common/Bar$inner.class", ".scala"
        )
        self.assertEqual("foo/org/common/Bar.scala", njp)

    def test_scanpipe_pipes_jvm_get_fully_qualified_scala_path(self):
        fqjp = jvm.get_fully_qualified_path("org.common", "Bar.scala")
        self.assertEqual("org/common/Bar.scala", fqjp)


class ScanPipeJvmKotlinTest(TestCase):
    data = Path(__file__).parent.parent / "data"

    kotlin_code = """
    package org.apache.logging.log4j.kotlin

    import kotlinx.coroutines.Deferred
    """

    kotlin_package_too_far_down = (
        "\n" * 501
    ) + "package org.apache.logging.log4j.kotlin"

    def test_scanpipe_pipes_jvm_find_kotlin_package(self):
        package = jvm.KotlinLanguage.find_source_package(self.kotlin_code.splitlines())
        self.assertEqual({"kotlin_package": "org.apache.logging.log4j.kotlin"}, package)

    def test_scanpipe_pipes_jvm_find_kotlin_package_with_spaces(self):
        lines = ["   package    foo.bar.baz   "]
        package = jvm.KotlinLanguage.find_source_package(lines)
        self.assertEqual({"kotlin_package": "foo.bar.baz"}, package)

    def test_scanpipe_pipes_jvm_find_kotlin_package_return_None(self):
        package = jvm.KotlinLanguage.find_source_package(
            self.kotlin_package_too_far_down.splitlines()
        )
        self.assertIsNone(package)

    def test_scanpipe_pipes_jvm_get_normalized_kotlin_path(self):
        njp = jvm.KotlinLanguage.get_normalized_path("foo/org/common/Bar.class", ".kt")
        self.assertEqual("foo/org/common/Bar.kt", njp)

    def test_scanpipe_pipes_jvm_get_normalized_kotlin_path_with_inner_class(self):
        njp = jvm.KotlinLanguage.get_normalized_path(
            "foo/org/common/Bar$inner.class", ".kt"
        )
        self.assertEqual("foo/org/common/Bar.kt", njp)
        njp = jvm.KotlinLanguage.get_normalized_path(
            "foo/org/common/BarKt$inner.class", ".kt"
        )
        self.assertEqual("foo/org/common/Bar.kt", njp)

    def test_scanpipe_pipes_jvm_get_normalized_kotlin_path_with_Kt_suffix(self):
        njp = jvm.KotlinLanguage.get_normalized_path(
            "foo/org/common/LoggerKt.class", ".kt"
        )
        self.assertEqual("foo/org/common/Logger.kt", njp)

    def test_scanpipe_pipes_jvm_get_fully_qualified_kotlin_path(self):
        fqjp = jvm.get_fully_qualified_path("org.common", "Bar.kt")
        self.assertEqual("org/common/Bar.kt", fqjp)
