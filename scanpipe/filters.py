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

import shlex

from django.apps import apps
from django.core.exceptions import FieldError
from django.core.validators import EMPTY_VALUES
from django.db import models
from django.db.models import Q
from django.db.models.fields import BLANK_CHOICE_DASH
from django.utils.http import urlencode
from django.utils.translation import gettext as _

import django_filters
from django_filters.widgets import LinkWidget
from packageurl.contrib.django.filters import PackageURLFilter

from scanpipe.models import CodebaseRelation
from scanpipe.models import CodebaseResource
from scanpipe.models import DiscoveredDependency
from scanpipe.models import DiscoveredPackage
from scanpipe.models import DiscoveredLicense
from scanpipe.models import Project
from scanpipe.models import ProjectMessage
from scanpipe.models import Run

scanpipe_app = apps.get_app_config("scanpipe")

PAGE_VAR = "page"
EMPTY_VAR = "_EMPTY_"
ANY_VAR = "_ANY_"
OTHER_VAR = "_OTHER_"


class ParentAllValuesFilter(django_filters.ChoiceFilter):
    """
    Similar to ``django_filters.AllValuesFilter`` but using the queryset of the parent
    ``FilterSet``.
    """

    @property
    def field(self):
        qs = self.parent.queryset.distinct()
        qs = qs.order_by(self.field_name).values_list(self.field_name, flat=True)
        self.extra["choices"] = [(o, o) for o in qs]
        return super().field


class StrictBooleanFilter(django_filters.ChoiceFilter):
    def __init__(self, *args, **kwargs):
        kwargs["choices"] = (
            (True, _("Yes")),
            (False, _("No")),
        )
        super().__init__(*args, **kwargs)


class BulmaLinkWidget(LinkWidget):
    """Replace LinkWidget rendering with Bulma CSS classes."""

    extra_css_class = ""

    def render_option(self, name, selected_choices, option_value, option_label):
        option_value = str(option_value)
        if option_label == BLANK_CHOICE_DASH[0][1]:
            option_label = _("All")

        data = self.data.copy()
        data[name] = option_value
        selected = data == self.data or option_value in selected_choices

        # Do not include the pagination in the filter query string.
        data.pop(PAGE_VAR, None)

        css_class = str(self.extra_css_class)
        if selected:
            css_class += " is-active"

        try:
            url = data.urlencode()
        except AttributeError:
            url = urlencode(data, doseq=True)

        return self.option_string().format(
            css_class=css_class,
            query_string=url,
            label=str(option_label),
        )

    def option_string(self):
        return '<li><a href="?{query_string}" class="{css_class}">{label}</a></li>'


class BulmaDropdownWidget(BulmaLinkWidget):
    extra_css_class = "dropdown-item"


class HasValueDropdownWidget(BulmaDropdownWidget):
    def __init__(self, attrs=None, choices=()):
        super().__init__(attrs)
        self.choices = (
            ("", "All"),
            (EMPTY_VAR, "None"),
            (ANY_VAR, "Any"),
        )


class FilterSetUtilsMixin:
    empty_value = EMPTY_VAR
    any_value = ANY_VAR
    other_value = OTHER_VAR
    dropdown_widget_class = BulmaDropdownWidget
    dropdown_widget_fields = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set the widget class for defined ``dropdown_widget_fields``.
        for field_name in self.dropdown_widget_fields:
            self.filters[field_name].extra["widget"] = self.dropdown_widget_class

    @staticmethod
    def remove_field_from_query_dict(query_dict, field_name, remove_value=None):
        """
        For given `field_name`, returns an encoded URL without the value.
        For multi-value filters, a single value can be removed using `remove_value`.
        This URL can be used to remove a filter value from active filters.
        """
        if not query_dict:
            return ""

        data = query_dict.copy()
        field_data = data.pop(field_name, [])

        if remove_value and len(field_data) > 1 and remove_value in field_data:
            for item in field_data:
                if item != remove_value:
                    data.update({field_name: item})

        return data.urlencode()

    def is_active(self):
        """Return True if any of the filters is active except for the 'sort' filter."""
        return bool(
            [
                field_name
                for field_name in self.form.changed_data
                if field_name not in ["sort"]
            ]
        )

    def get_query_no_sort(self):
        return self.remove_field_from_query_dict(self.data, "sort")

    def get_filters_breadcrumb(self):
        return [
            {
                "label": self.filters[field_name].label,
                "value": value,
                "remove_url": self.remove_field_from_query_dict(
                    self.data, field_name, value
                ),
            }
            for field_name in self.form.changed_data
            for value in self.data.getlist(field_name)
        ]

    @classmethod
    def verbose_name_plural(cls):
        return cls.Meta.model._meta.verbose_name_plural

    @property
    def params(self):
        return dict(self.data.items())

    @property
    def params_for_search(self):
        """
        Return the current request query parameter used to keep the state
        of the filters when using the search form.
        The pagination and the search value is removed from those parameters.
        """
        params = self.params
        params.pop(PAGE_VAR, None)
        params.pop("search", None)
        return params

    def filter_queryset(self, queryset):
        """
        Add the ability to filter by empty and none values providing the "magic"
        `empty_value` to any filters.
        """
        for name, value in self.form.cleaned_data.items():
            field_name = self.filters[name].field_name
            if value == self.empty_value:
                queryset = queryset.filter(**{f"{field_name}__in": EMPTY_VALUES})
            elif value == self.any_value:
                queryset = queryset.filter(~Q(**{f"{field_name}__in": EMPTY_VALUES}))
            elif value == self.other_value and hasattr(queryset, "less_common"):
                return queryset.less_common(name)
            else:
                queryset = self.filters[name].filter(queryset, value)

        return queryset


def parse_query_string_to_lookups(query_string, default_lookup_expr, default_field):
    """Parse a query string and convert it into queryset lookups using Q objects."""
    lookups = Q()
    terms = shlex.split(query_string)

    lookup_types = {
        "=": "iexact",
        "^": "istartswith",
        "$": "iendswith",
        "~": "icontains",
        ">": "gt",
        "<": "lt",
    }

    for term in terms:
        lookup_expr = default_lookup_expr
        negated = False

        if ":" in term:
            field_name, search_value = term.split(":", maxsplit=1)
            if field_name.endswith(tuple(lookup_types.keys())):
                lookup_symbol = field_name[-1]
                lookup_expr = lookup_types.get(lookup_symbol)
                field_name = field_name[:-1]

            if field_name.startswith("-"):
                field_name = field_name[1:]
                negated = True

        else:
            search_value = term
            field_name = default_field

        lookups &= Q(**{f"{field_name}__{lookup_expr}": search_value}, _negated=negated)

    return lookups


class QuerySearchFilter(django_filters.CharFilter):
    """Add support for complex query syntax in search filter."""

    def filter(self, qs, value):
        if not value:
            return qs

        lookups = parse_query_string_to_lookups(
            query_string=value,
            default_lookup_expr=self.lookup_expr,
            default_field=self.field_name,
        )

        try:
            return qs.filter(lookups)
        except FieldError:
            return qs.none()


class ProjectFilterSet(FilterSetUtilsMixin, django_filters.FilterSet):
    dropdown_widget_fields = [
        "sort",
        "pipeline",
        "status",
    ]

    search = QuerySearchFilter(
        label="Search", field_name="name", lookup_expr="icontains"
    )
    sort = django_filters.OrderingFilter(
        label="Sort",
        fields=[
            "created_date",
            "name",
            "discoveredpackages_count",
            "discovereddependencies_count",
            "codebaseresources_count",
            "projectmessages_count",
        ],
        empty_label="Newest",
        choices=(
            ("created_date", "Oldest"),
            ("name", "Name (A-z)"),
            ("-name", "Name (z-A)"),
            ("-discoveredpackages_count", "Packages (+)"),
            ("discoveredpackages_count", "Packages (-)"),
            ("-discovereddependencies_count", "Dependencies (+)"),
            ("discovereddependencies_count", "Dependencies (-)"),
            ("-codebaseresources_count", "Resources (+)"),
            ("codebaseresources_count", "Resources (-)"),
            ("-projectmessages_count", "Messages (+)"),
            ("projectmessages_count", "Messages (-)"),
        ),
    )
    pipeline = django_filters.ChoiceFilter(
        label="Pipeline",
        field_name="runs__pipeline_name",
        choices=scanpipe_app.get_pipeline_choices(include_blank=False),
        distinct=True,
    )
    status = django_filters.ChoiceFilter(
        label="Status",
        method="filter_run_status",
        choices=[
            ("not_started", "Not started"),
            ("queued", "Queued"),
            ("running", "Running"),
            ("succeed", "Success"),
            ("failed", "Failure"),
        ],
        distinct=True,
    )
    label = django_filters.CharFilter(
        label="Label",
        field_name="labels__slug",
        distinct=True,
    )

    class Meta:
        model = Project
        fields = ["is_archived"]
        exclude = ["page"]

    def __init__(self, data=None, *args, **kwargs):
        """Filter out the archived projects by default."""
        super().__init__(data, *args, **kwargs)

        # Default filtering by "Active" projects.
        if not data or data.get("is_archived", "") == "":
            self.queryset = self.queryset.filter(is_archived=False)

        active_count = Project.objects.filter(is_archived=False).count()
        archived_count = Project.objects.filter(is_archived=True).count()
        self.filters["is_archived"].extra["widget"] = BulmaLinkWidget(
            choices=[
                ("", f'<i class="fa-solid fa-seedling"></i> {active_count} Active'),
                (
                    "true",
                    f'<i class="fa-solid fa-dice-d6"></i> {archived_count} Archived',
                ),
            ]
        )

    def filter_run_status(self, queryset, name, value):
        """Filter by Run status using the `RunQuerySet` methods."""
        run_queryset_method = value
        run_queryset = getattr(Run.objects, run_queryset_method)()
        return queryset.filter(runs__in=run_queryset)


class JSONContainsFilter(django_filters.CharFilter):
    """
    Allows "contains" lookup on a JSONField converted to text.
    This is useful for data structures stored as a list of dictionaries, where
    Django's default lookups are not available.
    Requires the implementation of "json_field_contains" method on the QuerySet.
    """

    def filter(self, qs, value):
        if value:
            return qs.json_field_contains(self.field_name, value)
        return qs


class InPackageFilter(django_filters.ChoiceFilter):
    def __init__(self, *args, **kwargs):
        kwargs["choices"] = (
            ("true", "In a package"),
            ("false", "Not in a package"),
        )
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value == "true":
            return qs.in_package()
        elif value == "false":
            return qs.not_in_package()
        return qs


MAP_TYPE_CHOICES = (
    ("about_file", "about file"),
    ("java_to_class", "java to class"),
    ("jar_to_source", "jar to source"),
    ("js_compiled", "js compiled"),
    ("js_colocation", "js colocation"),
    ("js_path", "js path"),
    ("path", "path"),
    ("sha1", "sha1"),
)


class RelationMapTypeFilter(django_filters.ChoiceFilter):
    def __init__(self, *args, **kwargs):
        kwargs["choices"] = (
            ("none", "No map"),
            ("any", "Any map"),
            ("many", "Many map"),
            *MAP_TYPE_CHOICES,
        )
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value == "none":
            return qs.has_no_relation()
        elif value == "any":
            return qs.has_relation()
        elif value == "many":
            return qs.has_many_relation()
        return super().filter(qs, value)


class StatusFilter(django_filters.ChoiceFilter):
    def filter(self, qs, value):
        if value == "any":
            return qs.status()
        return super().filter(qs, value)

    @staticmethod
    def get_status_choices(qs, include_any=False):
        """Return the list of unique status for resources in ``project``."""
        default_choices = [(EMPTY_VAR, "No status")]
        if include_any:
            default_choices.append(("any", "Any status"))

        status_values = (
            qs.order_by("status").values_list("status", flat=True).distinct()
        )
        value_choices = [(status, status) for status in status_values if status]
        return default_choices + value_choices


class ResourceFilterSet(FilterSetUtilsMixin, django_filters.FilterSet):
    dropdown_widget_fields = [
        "status",
        "type",
        "compliance_alert",
        "in_package",
        "relation_map_type",
    ]

    search = QuerySearchFilter(
        label="Search",
        field_name="path",
        lookup_expr="icontains",
    )
    sort = django_filters.OrderingFilter(
        label="Sort",
        fields=[
            "path",
            "status",
            "type",
            "size",
            "name",
            "detected_license_expression",
            "extension",
            "programming_language",
            "mime_type",
            "tag",
            "compliance_alert",
            "related_from__map_type",
            "related_from__from_resource__path",
        ],
    )
    compliance_alert = django_filters.ChoiceFilter(
        choices=[(EMPTY_VAR, "None")] + CodebaseResource.Compliance.choices,
    )
    in_package = InPackageFilter(label="In a package")
    status = StatusFilter()
    relation_map_type = RelationMapTypeFilter(
        label="Relation map type",
        field_name="related_from__map_type",
    )

    class Meta:
        model = CodebaseResource
        fields = [
            "search",
            "path",
            "rootfs_path",
            "md5",
            "sha1",
            "sha256",
            "sha512",
            "size",
            "status",
            "tag",
            "type",
            "name",
            "extension",
            "programming_language",
            "mime_type",
            "file_type",
            "compliance_alert",
            "copyrights",
            "holders",
            "authors",
            "detected_license_expression",
            "detected_license_expression_spdx",
            "license_detections",
            "license_clues",
            "percentage_of_license_text",
            "emails",
            "urls",
            "in_package",
            "relation_map_type",
            "is_binary",
            "is_text",
            "is_archive",
            "is_key_file",
            "is_media",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if status_filter := self.filters.get("status"):
            status_filter.extra.update(
                {
                    "choices": status_filter.get_status_choices(
                        self.queryset, include_any=True
                    )
                }
            )

        license_expression_filer = self.filters["detected_license_expression"]
        license_expression_filer.extra["widget"] = HasValueDropdownWidget()

    @classmethod
    def filter_for_lookup(cls, field, lookup_type):
        """Add support for JSONField storing "list" using the JSONListFilter."""
        if isinstance(field, models.JSONField) and field.default == list:
            return JSONContainsFilter, {}

        return super().filter_for_lookup(field, lookup_type)


class IsVulnerable(django_filters.ChoiceFilter):
    def __init__(self, *args, **kwargs):
        kwargs["choices"] = (
            ("yes", "Affected by vulnerabilities"),
            ("no", "No vulnerabilities found"),
        )
        super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value == "yes":
            return qs.filter(~Q(**{f"{self.field_name}__in": EMPTY_VALUES}))
        elif value == "no":
            return qs.filter(**{f"{self.field_name}__in": EMPTY_VALUES})
        return qs


class DiscoveredPackageSearchFilter(QuerySearchFilter):
    def filter(self, qs, value):
        if not value:
            return qs

        if value.startswith("pkg:"):
            return qs.for_package_url(value)

        if ":" in value:
            return super().filter(qs, value)

        search_fields = ["type", "namespace", "name", "version"]
        lookups = Q()
        for field_names in search_fields:
            lookups |= Q(**{f"{field_names}__{self.lookup_expr}": value})

        return qs.filter(lookups)


class DiscoveredLicenseSearchFilter(QuerySearchFilter):
    def filter(self, qs, value):
        if not value:
            return qs

        search_fields = ["license_expression", "license_expression_spdx"]
        lookups = Q()
        for field_names in search_fields:
            lookups |= Q(**{f"{field_names}__{self.lookup_expr}": value})

        return qs.filter(lookups)


class GroupOrderingFilter(django_filters.OrderingFilter):
    """Add the ability to provide a group a fields to order by."""

    def __init__(self, *args, **kwargs):
        """grouped_fields = {"group_name": ["field1", "field2", "field3"]}"""
        self.grouped_fields = kwargs.pop("grouped_fields", {})
        super().__init__(*args, **kwargs)

    def get_ordering_value(self, param):
        descending = param.startswith("-")
        param = param[1:] if descending else param

        group = self.grouped_fields.get(param)
        if not group:
            group = [self.param_map.get(param, param)]

        return [f"-{field_name}" if descending else field_name for field_name in group]

    def filter(self, qs, value):
        if value in EMPTY_VALUES:
            return qs

        ordering = []
        for param in value:
            ordering.extend(self.get_ordering_value(param))

        return qs.order_by(*ordering)


class PackageFilterSet(FilterSetUtilsMixin, django_filters.FilterSet):
    dropdown_widget_fields = [
        "is_vulnerable",
        "compliance_alert",
    ]

    search = DiscoveredPackageSearchFilter(
        label="Search", field_name="name", lookup_expr="icontains"
    )
    sort = GroupOrderingFilter(
        label="Sort",
        fields=[
            "package_url",
            "type",
            "namespace",
            "name",
            "version",
            "declared_license_expression",
            "other_license_expression",
            "compliance_alert",
            "copyright",
            "primary_language",
            "tag",
            "resources_count",
        ],
        grouped_fields={"package_url": ["type", "namespace", "name", "version"]},
    )
    purl = PackageURLFilter(label="Package URL")
    is_vulnerable = IsVulnerable(field_name="affected_by_vulnerabilities")
    compliance_alert = django_filters.ChoiceFilter(
        choices=[(EMPTY_VAR, "None")] + CodebaseResource.Compliance.choices,
    )
    copyright = django_filters.filters.CharFilter(widget=HasValueDropdownWidget)
    declared_license_expression = django_filters.filters.CharFilter(
        widget=HasValueDropdownWidget
    )

    class Meta:
        model = DiscoveredPackage
        fields = [
            "search",
            "purl",
            "type",
            "namespace",
            "name",
            "version",
            "qualifiers",
            "subpath",
            "filename",
            "primary_language",
            "release_date",
            "homepage_url",
            "download_url",
            "size",
            "md5",
            "sha1",
            "bug_tracking_url",
            "code_view_url",
            "vcs_url",
            "type",
            "declared_license_expression",
            "declared_license_expression_spdx",
            "other_license_expression",
            "other_license_expression_spdx",
            "extracted_license_statement",
            "copyright",
            "is_vulnerable",
            "compliance_alert",
            "tag",
        ]


class DependencyFilterSet(FilterSetUtilsMixin, django_filters.FilterSet):
    dropdown_widget_fields = [
        "type",
        "scope",
        "is_runtime",
        "is_optional",
        "is_resolved",
        "datasource_id",
        "is_vulnerable",
    ]

    search = QuerySearchFilter(
        label="Search", field_name="name", lookup_expr="icontains"
    )
    sort = GroupOrderingFilter(
        label="Sort",
        fields=[
            "package_url",
            "type",
            "namespace",
            "name",
            "version",
            "extracted_requirement",
            "scope",
            "is_runtime",
            "is_optional",
            "is_resolved",
            "for_package",
            "datafile_resource",
            "datasource_id",
        ],
        grouped_fields={"package_url": ["type", "namespace", "name", "version"]},
    )
    purl = PackageURLFilter(label="Package URL")
    type = ParentAllValuesFilter()
    scope = ParentAllValuesFilter()
    datasource_id = ParentAllValuesFilter()
    is_runtime = StrictBooleanFilter()
    is_optional = StrictBooleanFilter()
    is_resolved = StrictBooleanFilter()
    is_vulnerable = IsVulnerable(field_name="affected_by_vulnerabilities")

    class Meta:
        model = DiscoveredDependency
        fields = [
            "search",
            "purl",
            "dependency_uid",
            "type",
            "namespace",
            "name",
            "version",
            "qualifiers",
            "subpath",
            "scope",
            "is_runtime",
            "is_optional",
            "is_resolved",
            "datasource_id",
            "is_vulnerable",
        ]


class LicenseFilterSet(FilterSetUtilsMixin, django_filters.FilterSet):
    dropdown_widget_fields = [
        "compliance_alert",
    ]

    search = DiscoveredLicenseSearchFilter(
        label="Search", field_name="name", lookup_expr="icontains"
    )
    sort = GroupOrderingFilter(
        label="Sort",
        fields=[
            "detection_count",
            "identifier",
            "license_expression",
            "license_expression_spdx",
            "compliance_alert",
        ],
    )
    license_expression = ParentAllValuesFilter()
    compliance_alert = django_filters.ChoiceFilter(
        choices=[(EMPTY_VAR, "None")] + CodebaseResource.Compliance.choices,
    )

    class Meta:
        model = DiscoveredLicense
        fields = [
            "search",
            "identifier",
            "detection_count",
            "license_expression",
            "license_expression_spdx",
            "compliance_alert",
        ]


class ProjectMessageFilterSet(FilterSetUtilsMixin, django_filters.FilterSet):
    search = QuerySearchFilter(
        label="Search", field_name="description", lookup_expr="icontains"
    )
    sort = django_filters.OrderingFilter(
        label="Sort",
        fields=[
            "severity",
            "model",
        ],
    )

    class Meta:
        model = ProjectMessage
        fields = [
            "search",
            "severity",
            "model",
            "description",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.filters["severity"].extra["widget"] = BulmaDropdownWidget()


class RelationFilterSet(FilterSetUtilsMixin, django_filters.FilterSet):
    dropdown_widget_fields = [
        "status",
        "map_type",
    ]

    search = QuerySearchFilter(
        label="Search",
        field_name="to_resource__path",
        lookup_expr="icontains",
    )
    sort = django_filters.OrderingFilter(
        label="Sort",
        fields=[
            "from_resource",
            "to_resource",
            "map_type",
        ],
    )
    map_type = django_filters.ChoiceFilter(choices=MAP_TYPE_CHOICES)
    status = StatusFilter(field_name="to_resource__status")

    class Meta:
        model = CodebaseRelation
        fields = [
            "search",
            "map_type",
            "status",
        ]

    def __init__(self, *args, **kwargs):
        project = kwargs.pop("project")
        super().__init__(*args, **kwargs)
        if project:
            status_filter = self.filters.get("status")
            qs = CodebaseResource.objects.filter(project=project)
            status_filter.extra.update(
                {"choices": status_filter.get_status_choices(qs)}
            )
