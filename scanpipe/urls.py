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

from django.urls import include
from django.urls import path

from scanpipe import views

urlpatterns = [
    path(
        "project/<slug:slug>/resources/<path:path>/raw/",
        views.CodebaseResourceRawView.as_view(),
        name="resource_raw",
    ),
    path(
        "project/<slug:slug>/resources/diff/",
        views.codebase_resource_diff_view,
        name="resource_diff",
    ),
    path(
        "project/<slug:slug>/resources/<path:path>/",
        views.CodebaseResourceDetailsView.as_view(),
        name="resource_detail",
    ),
    path(
        "project/<slug:slug>/resources/",
        views.CodebaseResourceListView.as_view(),
        name="project_resources",
    ),
    path(
        "project/<slug:slug>/packages/<uuid:uuid>/purldb_tab/",
        views.DiscoveredPackagePurlDBTabView.as_view(),
        name="package_purldb_tab",
    ),
    path(
        "project/<slug:slug>/packages/<uuid:uuid>/",
        views.DiscoveredPackageDetailsView.as_view(),
        name="package_detail",
    ),
    path(
        "project/<slug:slug>/license_detections/<slug:identifier>/",
        views.DiscoveredLicenseDetailsView.as_view(),
        name="license_detail",
    ),
    path(
        "project/<slug:slug>/dependencies/<path:dependency_uid>/",
        views.DiscoveredDependencyDetailsView.as_view(),
        name="dependency_detail",
    ),
    path(
        "project/<slug:slug>/packages/",
        views.DiscoveredPackageListView.as_view(),
        name="project_packages",
    ),
    path(
        "project/<slug:slug>/license_detections/",
        views.DiscoveredLicenseListView.as_view(),
        name="project_licenses",
    ),
    path(
        "project/<slug:slug>/dependencies/",
        views.DiscoveredDependencyListView.as_view(),
        name="project_dependencies",
    ),
    path(
        "project/<slug:slug>/relations/",
        views.CodebaseRelationListView.as_view(),
        name="project_relations",
    ),
    path(
        "project/<slug:slug>/messages/",
        views.ProjectMessageListView.as_view(),
        name="project_messages",
    ),
    path(
        "project/<slug:slug>/archive/",
        views.ProjectArchiveView.as_view(),
        name="project_archive",
    ),
    path(
        "project/<slug:slug>/delete/",
        views.ProjectDeleteView.as_view(),
        name="project_delete",
    ),
    path(
        "project/<slug:slug>/reset/",
        views.ProjectResetView.as_view(),
        name="project_reset",
    ),
    path(
        "project/<slug:slug>/clone/",
        views.ProjectCloneView.as_view(),
        name="project_clone",
    ),
    path(
        "project/<slug:slug>/settings/",
        views.ProjectSettingsView.as_view(),
        name="project_settings",
    ),
    path(
        "project/<slug:slug>/codebase/",
        views.ProjectCodebaseView.as_view(),
        name="project_codebase",
    ),
    path(
        "run/<uuid:uuid>/",
        views.run_detail_view,
        name="run_detail",
    ),
    path(
        "run/<uuid:uuid>/status/",
        views.run_status_view,
        name="run_status",
    ),
    path(
        "run/<uuid:uuid>/step_selection/",
        views.RunStepSelectionFormView.as_view(),
        name="project_run_step_selection",
    ),
    path(
        "pipeline/<str:pipeline_name>/help/",
        views.pipeline_help_view,
        name="pipeline_help",
    ),
    path(
        "project/<slug:slug>/results/<str:format>/<str:version>/",
        views.ProjectResultsView.as_view(),
        name="project_results",
    ),
    path(
        "project/<slug:slug>/results/<str:format>/",
        views.ProjectResultsView.as_view(),
        name="project_results",
    ),
    path(
        "project/<slug:slug>/execute_pipelines/",
        views.execute_pipelines_view,
        name="project_execute_pipelines",
    ),
    path(
        "project/<slug:slug>/stop_pipeline/<uuid:run_uuid>/",
        views.stop_pipeline_view,
        name="project_stop_pipeline",
    ),
    path(
        "project/<slug:slug>/delete_pipeline/<uuid:run_uuid>/",
        views.delete_pipeline_view,
        name="project_delete_pipeline",
    ),
    path(
        "project/<slug:slug>/delete_input/<uuid:input_uuid>/",
        views.delete_input_view,
        name="project_delete_input",
    ),
    path(
        "project/<slug:slug>/download_input/<str:filename>/",
        views.download_input_view,
        name="project_download_input",
    ),
    path(
        "project/<slug:slug>/download_output/<str:filename>/",
        views.download_output_view,
        name="project_download_output",
    ),
    path(
        "project/<slug:slug>/delete_label/<str:label_name>/",
        views.delete_label_view,
        name="project_delete_label",
    ),
    path(
        "project/add/",
        views.ProjectCreateView.as_view(),
        name="project_add",
    ),
    path(
        "project/action/",
        views.ProjectActionView.as_view(),
        name="project_action",
    ),
    path(
        "project/<slug:slug>/charts/",
        views.ProjectChartsView.as_view(),
        name="project_charts",
    ),
    path(
        "project/<slug:slug>/resource_status_summary/",
        views.ProjectResourceStatusSummaryView.as_view(),
        name="project_resource_status_summary",
    ),
    path(
        "project/<slug:slug>/license_detection_summary/",
        views.ProjectLicenseDetectionSummaryView.as_view(),
        name="project_license_detection_summary",
    ),
    path(
        "project/<slug:slug>/",
        views.ProjectDetailView.as_view(),
        name="project_detail",
    ),
    path(
        "project/",
        views.ProjectListView.as_view(),
        name="project_list",
    ),
    path(
        "license/<str:key>/",
        views.LicenseDetailsView.as_view(),
        name="license_detail",
    ),
    path(
        "license/",
        views.LicenseListView.as_view(),
        name="license_list",
    ),
    path("monitor/", include("django_rq.urls")),
]
