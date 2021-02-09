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

import inspect
import logging
import timeit
import traceback
from contextlib import contextmanager
from pydoc import getdoc

from django.utils import timezone

logger = logging.getLogger(__name__)


class Pipeline:
    """
    Base class for all Pipelines.
    """

    name = None
    doc = None
    steps = ()

    def __init__(self, run):
        """
        Load the Run and Project instances.
        """
        assert self.steps
        self.run = run
        self.project = run.project

    @classmethod
    def get_name(cls):
        """
        Return the name declared on the class or the name of the class itself.
        """
        return cls.name or cls.__class__.__name__

    @classmethod
    def get_doc(cls):
        """
        Return the doc if declared on the class, or the docstring.
        """
        return cls.doc or getdoc(cls)

    @classmethod
    def get_graph(cls):
        """
        Return the graph of steps.
        """
        return [{"name": step.__name__, "doc": getdoc(step)} for step in cls.steps]

    def log(self, message):
        """
        Log the `message` to this module logger and to the Run instance.
        """
        timestamp = timezone.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-4]
        message = f"{timestamp} {message}"
        logger.info(message)
        self.run.append_to_log(message, save=True)

    def execute(self):
        self.log(f"Pipeline [{self.name}] starting")

        for step in self.steps:
            self.log(f"Step [{step.__name__}] starting")
            start_time = timeit.default_timer()

            try:
                step(self)
            except Exception as e:
                self.log(f"Pipeline failed")
                tb = "".join(traceback.format_tb(e.__traceback__))
                return 1, f"{e}\n\nTraceback:\n{tb}"

            run_time = timeit.default_timer() - start_time
            self.log(f"Step [{step.__name__}] completed in {run_time:.2f} seconds")

        self.log(f"Pipeline completed")

        return 0, ""

    @contextmanager
    def save_errors(self, *exceptions):
        """
        Context manager to save specified exceptions as `ProjectError` in the database.

        Example in a Pipeline step:

        with self.save_errors(ScancodeError):
            run_scancode()
        """
        try:
            yield
        except exceptions as error:
            self.project.add_error(error, model=self.__class__.__name__)


def is_pipeline_subclass(obj):
    """
    Return True if the `obj` is a subclass of `Pipeline` except for the
    `Pipeline` class itself.
    """
    return inspect.isclass(obj) and issubclass(obj, Pipeline) and obj is not Pipeline
