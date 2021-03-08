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

from django.apps import apps
from django.db import transaction

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.utils import extend_schema
from rest_framework import mixins
from rest_framework import renderers
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.parsers import JSONParser
from rest_framework.parsers import MultiPartParser
from rest_framework.response import Response

from scanpipe.api.serializers import CodebaseResourceSerializer
from scanpipe.api.serializers import DiscoveredPackageSerializer
from scanpipe.api.serializers import PipelineSerializer
from scanpipe.api.serializers import ProjectErrorSerializer
from scanpipe.api.serializers import ProjectSerializer
from scanpipe.api.serializers import RunSerializer
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredPackage
from scanpipe.models import Project
from scanpipe.models import ProjectError
from scanpipe.models import Run
from scanpipe.views import project_results_json_response

scanpipe_app_config = apps.get_app_config("scanpipe")


class PassThroughRenderer(renderers.BaseRenderer):
    media_type = ""

    def render(self, data, **kwargs):
        return data


class ProjectViewSet(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.DestroyModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    """
    A viewset that provides ability to list, get, create, and destroy projects.
    Multiple actions are available to manage project instances.
    """

    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    parser_classes = [MultiPartParser, JSONParser]

    @action(detail=True, renderer_classes=[renderers.JSONRenderer])
    def results(self, request, *args, **kwargs):
        """
        Return the results compatible with ScanCode data format.
        The content is returned as a stream of JSON content using the
        JSONResultsGenerator class.
        """
        return project_results_json_response(self.get_object())

    @action(
        detail=True, name="Results (download)", renderer_classes=[PassThroughRenderer]
    )
    def results_download(self, request, *args, **kwargs):
        """
        Return the results as an attachment.
        """
        return project_results_json_response(self.get_object(), as_attachment=True)

    @action(detail=False)
    def pipelines(self, request, *args, **kwargs):
        pipeline_data = [
            {"name": name, **pipeline_class.get_info()}
            for name, pipeline_class in scanpipe_app_config.pipelines.items()
        ]
        return Response(pipeline_data)

    @action(detail=True)
    def resources(self, request, *args, **kwargs):
        project = self.get_object()
        queryset = CodebaseResource.objects.project(project).prefetch_related(
            "discovered_packages"
        )

        paginated_qs = self.paginate_queryset(queryset)
        serializer = CodebaseResourceSerializer(paginated_qs, many=True)

        return Response(serializer.data)

    @action(detail=True)
    def packages(self, request, *args, **kwargs):
        project = self.get_object()
        queryset = DiscoveredPackage.objects.project(project)

        paginated_qs = self.paginate_queryset(queryset)
        serializer = DiscoveredPackageSerializer(paginated_qs, many=True)

        return Response(serializer.data)

    @action(detail=True)
    def errors(self, request, *args, **kwargs):
        project = self.get_object()
        queryset = ProjectError.objects.project(project)

        paginated_qs = self.paginate_queryset(queryset)
        serializer = ProjectErrorSerializer(paginated_qs, many=True)

        return Response(serializer.data)

    @extend_schema(
        parameters=[
            OpenApiParameter("path", OpenApiTypes.STR, description="Path to resource")
        ]
    )
    @action(detail=True, methods=["get"])
    def file_content(self, request, *args, **kwargs):
        project = self.get_object()
        path = request.query_params.get("path")
        codebase_resources = CodebaseResource.objects.project(project)

        try:
            codebase_resource = codebase_resources.get(path=path)
        except CodebaseResource.DoesNotExist:
            message = {"status": "Resource not found. Use ?path=<resource_path>"}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)

        try:
            file_content = codebase_resource.file_content
        except OSError:
            message = {"status": "File not available"}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)

        return Response({"file_content": file_content})

    @action(detail=True, methods=["get", "post"], serializer_class=PipelineSerializer)
    def add_pipeline(self, request, *args, **kwargs):
        project = self.get_object()

        pipeline = request.data.get("pipeline")
        if pipeline:
            if pipeline in scanpipe_app_config.pipelines:
                execute_now = request.data.get("execute_now")
                project.add_pipeline(pipeline, execute_now)
                return Response({"status": "Pipeline added."})

            message = {"status": f"{pipeline} is not a valid pipeline."}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)

        message = {
            "status": "Pipeline required.",
            "pipelines": list(scanpipe_app_config.pipelines.keys()),
        }
        return Response(message, status=status.HTTP_400_BAD_REQUEST)


class RunViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):
    """
    This viewset provides the `detail` only action.
    """

    queryset = Run.objects.all()
    serializer_class = RunSerializer

    @action(detail=True, methods=["get"])
    def start_pipeline(self, request, *args, **kwargs):
        run = self.get_object()
        if run.task_end_date:
            message = {"status": "Pipeline already executed."}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)
        elif run.task_start_date:
            message = {"status": "Pipeline already started."}
            return Response(message, status=status.HTTP_400_BAD_REQUEST)

        transaction.on_commit(run.execute_task_async)

        return Response({"status": f"Pipeline {run.pipeline_name} started."})
