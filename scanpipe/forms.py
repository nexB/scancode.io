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

from django import forms
from django.apps import apps
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError

from taggit.forms import TagField
from taggit.forms import TagWidget

from pipeline import convert_markdown_to_html
from scanpipe.models import Project
from scanpipe.models import Run
from scanpipe.pipes import fetch

scanpipe_app = apps.get_app_config("scanpipe")


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("widget", MultipleFileInput(attrs={"class": "file-input"}))
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        single_file_clean = super().clean
        if isinstance(data, list | tuple):
            result = [single_file_clean(entry, initial) for entry in data]
        else:
            result = single_file_clean(data, initial)
        return result


class InputsBaseForm(forms.Form):
    input_files = MultipleFileField(required=False)
    input_urls = forms.CharField(
        label="Download URLs",
        required=False,
        help_text=(
            "Provide one or more URLs to download, one per line. "
            "Files are fetched at the beginning of the pipeline run execution."
        ),
        widget=forms.Textarea(
            attrs={
                "class": "textarea is-dynamic",
                "rows": 2,
                "placeholder": (
                    "https://domain.com/archive.zip\n"
                    "docker://docker-reference (e.g.: docker://postgres:13)"
                ),
            },
        ),
    )

    class Media:
        js = ("add-inputs.js",)

    @staticmethod
    def validate_scheme(input_urls):
        """
        Raise a validation error if some of the `input_urls` have a scheme that is not
        supported.
        """
        errors = []

        for url in input_urls:
            try:
                fetch.get_fetcher(url)
            except ValueError as e:
                errors.append(str(e))

        if errors:
            raise ValidationError("\n".join(errors))

    def clean_input_urls(self):
        """
        Fetch the `input_urls` and sets the `downloads` objects in the cleaned_data.
        A validation error is raised if at least one URL can't be fetched.
        """
        input_urls_str = self.cleaned_data.get("input_urls", "")
        input_urls = input_urls_str.split()

        self.validate_scheme(input_urls)

        if errors := fetch.check_urls_availability(input_urls):
            raise ValidationError("Could not fetch:\n" + "\n".join(errors))

        return input_urls

    def handle_inputs(self, project):
        input_files = self.files.getlist("input_files")
        if input_files:
            project.add_uploads(input_files)

        input_urls = self.cleaned_data.get("input_urls", [])
        for url in input_urls:
            project.add_input_source(download_url=url)


class CheckboxChoiceField(forms.MultipleChoiceField):
    widget = forms.CheckboxSelectMultiple


class SelectedGroupsCheckboxChoiceField(CheckboxChoiceField):
    def valid_value(self, value):
        """Accept all values."""
        return True


class PipelineBaseForm(forms.Form):
    pipeline = forms.ChoiceField(
        choices=scanpipe_app.get_pipeline_choices(),
        required=False,
    )
    execute_now = forms.BooleanField(
        label="Execute pipeline now",
        initial=True,
        required=False,
    )
    selected_groups = SelectedGroupsCheckboxChoiceField(required=False)

    def handle_pipeline(self, project):
        pipeline = self.cleaned_data["pipeline"]
        execute_now = self.cleaned_data["execute_now"]
        selected_groups = self.cleaned_data.get("selected_groups", [])
        if pipeline:
            project.add_pipeline(pipeline, execute_now, selected_groups)


class ProjectForm(InputsBaseForm, PipelineBaseForm, forms.ModelForm):
    class Meta:
        model = Project
        fields = [
            "name",
            "input_files",
            "input_urls",
            "pipeline",
            "execute_now",
            "selected_groups",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        name_field = self.fields["name"]
        name_field.widget.attrs["class"] = "input"
        name_field.widget.attrs["autofocus"] = True
        name_field.help_text = "The unique name of your project."

        # Do not include "add-on" pipelines in the context of the create Project form
        pipeline_choices = scanpipe_app.get_pipeline_choices(include_addon=False)
        self.fields["pipeline"].choices = pipeline_choices

    def clean_name(self):
        return " ".join(self.cleaned_data["name"].split())

    def save(self, *args, **kwargs):
        project = super().save(*args, **kwargs)
        self.handle_inputs(project)
        self.handle_pipeline(project)
        return project


class AddInputsForm(InputsBaseForm, forms.Form):
    def save(self, project):
        self.handle_inputs(project)
        return project


class AddPipelineForm(PipelineBaseForm):
    pipeline = forms.ChoiceField(
        choices=scanpipe_app.get_pipeline_choices(),
        widget=forms.RadioSelect(),
        required=True,
    )

    def save(self, project):
        self.handle_pipeline(project)
        return project


class AddLabelsForm(forms.Form):
    labels = TagField(
        label="Add labels to this project:",
        widget=TagWidget(
            attrs={"class": "input", "placeholder": "Comma-separated list of labels"}
        ),
    )

    def save(self, project):
        project.labels.add(*self.cleaned_data["labels"])
        return project


class EditInputSourceTagForm(forms.Form):
    input_source_uuid = forms.CharField(
        max_length=50,
        widget=forms.widgets.HiddenInput,
        required=True,
    )
    tag = forms.CharField(
        widget=forms.TextInput(attrs={"class": "input"}),
    )

    def save(self, project):
        input_source_uuid = self.cleaned_data.get("input_source_uuid")
        try:
            input_source = project.inputsources.get(uuid=input_source_uuid)
        except (ValidationError, ObjectDoesNotExist):
            return

        input_source.update(tag=self.cleaned_data.get("tag", ""))
        return input_source


class ArchiveProjectForm(forms.Form):
    remove_input = forms.BooleanField(
        label="Remove inputs",
        initial=True,
        required=False,
    )
    remove_codebase = forms.BooleanField(
        label="Remove codebase",
        initial=True,
        required=False,
    )
    remove_output = forms.BooleanField(
        label="Remove outputs",
        initial=False,
        required=False,
    )


class ListTextarea(forms.CharField):
    """
    A Django form field that displays as a textarea and converts each line of input
    into a list of items.

    This field extends the `CharField` and uses the `Textarea` widget to display the
    input as a textarea.
    Each line of the textarea input is split into items, removing leading/trailing
    whitespace and empty lines.
    The resulting list of items is then stored as the field value.
    """

    widget = forms.Textarea

    def to_python(self, value):
        """Split the textarea input into lines and remove empty lines."""
        if value:
            return [line.strip() for line in value.splitlines() if line.strip()]

    def prepare_value(self, value):
        """Join the list items into a string with newlines."""
        if value is not None:
            value = "\n".join(value)
        return value


class KeyValueListField(forms.CharField):
    """
    A Django form field that displays as a textarea and converts each line of
    "key:value" input into a list of dictionaries with customizable keys.

    Each line of the textarea input is split into key-value pairs,
    removing leading/trailing whitespace and empty lines. The resulting list of
    dictionaries is then stored as the field value.
    """

    widget = forms.Textarea

    def __init__(self, *args, key_name="key", value_name="value", **kwargs):
        """Initialize the KeyValueListField with custom key and value names."""
        self.key_name = key_name
        self.value_name = value_name
        super().__init__(*args, **kwargs)

    def to_python(self, value):
        """
        Split the textarea input into lines, convert each line to a dictionary,
        and remove empty lines.
        """
        if not value:
            return None

        items = []
        for line in value.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(":", 1)
            if len(parts) != 2:
                raise ValidationError(
                    f"Invalid input line: '{line}'. "
                    f"Each line must contain exactly one ':' character."
                )
            key, value = parts
            key = key.strip()
            value = value.strip()
            if not key or not value:
                raise ValidationError(
                    f"Invalid input line: '{line}'. "
                    f"Both key and value must be non-empty."
                )
            items.append({self.key_name: key, self.value_name: value})

        return items

    def prepare_value(self, value):
        """
        Join the list of dictionaries into a string with newlines,
        using the "key:value" format.
        """
        if value is not None and isinstance(value, list):
            value = "\n".join(
                f"{item[self.key_name]}:{item[self.value_name]}" for item in value
            )
        return value


ignored_patterns_help = """
Provide one or more path patterns to be ignored, one per line.

Each pattern should follow the syntax of Unix shell-style wildcards:
- Use ``*`` to match multiple characters.
- Use ``?`` to match a single character.

Here are some examples:
- To ignore all files with a ".tmp" extension, use: ``*.tmp``
- To ignore all files in a "tests" directory, use: ``tests/*``
- To ignore specific files or directories, provide their exact names or paths, such as:
  ``example/file_to_ignore.txt`` or ``folder_to_ignore/*``

You can also use regular expressions for more complex matching.
Remember that these patterns will be applied recursively to all files and directories
within the project.
Be cautious when specifying patterns to avoid unintended exclusions.
"""

ignored_dependency_scopes_help = """
Specify certain dependency scopes to be ignored for a given package type.

This allows you to exclude dependencies from being created or resolved based on their
scope using the `package_type:scope` syntax, **one per line**.
For example: `npm:devDependencies`
"""


ignored_vulnerabilities_help = """
Specify certain vulnerabilities to be ignored using VCID, CVE, or any aliases.
"""


class ProjectSettingsForm(forms.ModelForm):
    settings_fields = [
        "ignored_patterns",
        "ignored_dependency_scopes",
        "ignored_vulnerabilities",
        "attribution_template",
        "product_name",
        "product_version",
    ]
    ignored_patterns = ListTextarea(
        label="Ignored patterns",
        required=False,
        help_text=convert_markdown_to_html(ignored_patterns_help.strip()),
        widget=forms.Textarea(
            attrs={
                "class": "textarea is-dynamic",
                "rows": 3,
                "placeholder": "*.tmp\ntests/*\n*docs/*.rst",
            },
        ),
    )
    ignored_dependency_scopes = KeyValueListField(
        label="Ignored dependency scopes",
        required=False,
        help_text=convert_markdown_to_html(ignored_dependency_scopes_help.strip()),
        widget=forms.Textarea(
            attrs={
                "class": "textarea is-dynamic",
                "rows": 2,
                "placeholder": "npm:devDependencies\npypi:tests",
            },
        ),
        key_name="package_type",
        value_name="scope",
    )
    ignored_vulnerabilities = ListTextarea(
        label="Ignored vulnerabilities",
        required=False,
        help_text=convert_markdown_to_html(ignored_vulnerabilities_help.strip()),
        widget=forms.Textarea(
            attrs={
                "class": "textarea is-dynamic",
                "rows": 2,
                "placeholder": "VCID-q4q6-yfng-aaag\nCVE-2024-27351",
            },
        ),
    )
    attribution_template = forms.CharField(
        label="Attribution template",
        required=False,
        help_text=(
            "Customize the attribution template to personalize the generated "
            "attribution for your needs."
            "\nThe default template can be found at "
            "https://raw.githubusercontent.com/nexB/scancode.io/main/scanpipe/"
            "templates/scanpipe/attribution.html"
            "\nFeel free to modify its content according to your preferences and paste "
            "the entire HTML code into this field."
        ),
        widget=forms.Textarea(attrs={"class": "textarea is-dynamic", "rows": 3}),
    )
    product_name = forms.CharField(
        label="Product name",
        required=False,
        help_text=(
            "The product name of this project, as specified within the DejaCode "
            "application."
        ),
        widget=forms.TextInput(attrs={"class": "input"}),
    )
    product_version = forms.CharField(
        label="Product version",
        required=False,
        help_text=(
            "The product version of this project, as specified within the DejaCode "
            "application."
        ),
        widget=forms.TextInput(attrs={"class": "input"}),
    )

    class Meta:
        model = Project
        fields = [
            "name",
            "notes",
        ]
        widgets = {
            "name": forms.TextInput(attrs={"class": "input"}),
            "notes": forms.Textarea(attrs={"rows": 3, "class": "textarea is-dynamic"}),
        }

    def __init__(self, *args, **kwargs):
        """Load initial values from Project ``settings`` field."""
        super().__init__(*args, **kwargs)
        for field_name in self.settings_fields:
            field = self.fields[field_name]
            # Do not override the field ``initial`` if the key is not in the settings
            if field_name in self.instance.settings:
                field.initial = self.instance.settings.get(field_name)

    def save(self, *args, **kwargs):
        project = super().save(*args, **kwargs)
        self.update_project_settings(project)
        return project

    def update_project_settings(self, project):
        """Update Project ``settings`` field values from form data."""
        config = {
            field_name: self.cleaned_data[field_name]
            for field_name in self.settings_fields
        }
        project.settings.update(config)
        project.save(update_fields=["settings"])


class ProjectCloneForm(forms.Form):
    clone_name = forms.CharField(widget=forms.TextInput(attrs={"class": "input"}))
    copy_inputs = forms.BooleanField(
        initial=True,
        required=False,
        help_text="Input files located in the input/ work directory will be copied.",
        widget=forms.CheckboxInput(attrs={"class": "checkbox mr-1"}),
    )
    copy_pipelines = forms.BooleanField(
        initial=True,
        required=False,
        help_text="All pipelines assigned to the original project will be copied over.",
        widget=forms.CheckboxInput(attrs={"class": "checkbox mr-1"}),
    )
    copy_settings = forms.BooleanField(
        initial=True,
        required=False,
        help_text="All project settings will be copied.",
        widget=forms.CheckboxInput(attrs={"class": "checkbox mr-1"}),
    )
    copy_subscriptions = forms.BooleanField(
        initial=True,
        required=False,
        help_text="All project webhook subscription will be copied.",
        widget=forms.CheckboxInput(attrs={"class": "checkbox mr-1"}),
    )
    execute_now = forms.BooleanField(
        label="Execute copied pipeline(s) now",
        initial=False,
        required=False,
        help_text="Copied pipelines will be directly executed.",
    )

    def __init__(self, instance, *args, **kwargs):
        self.project = instance
        super().__init__(*args, **kwargs)
        self.fields["clone_name"].initial = f"{self.project.name} clone"

    def clean_clone_name(self):
        clone_name = self.cleaned_data.get("clone_name")
        if Project.objects.filter(name=clone_name).exists():
            raise ValidationError("Project with this name already exists.")
        return clone_name

    def save(self, *args, **kwargs):
        return self.project.clone(**self.cleaned_data)


class PipelineRunStepSelectionForm(forms.ModelForm):
    selected_steps = CheckboxChoiceField(required=False)

    class Meta:
        model = Run
        fields = [
            "selected_steps",
        ]

    def __init__(self, *args, **kwargs):
        if not kwargs.get("instance"):
            raise ValueError("An Run object is required to instantiate this form.")

        super().__init__(*args, **kwargs)
        pipeline_class = self.instance.pipeline_class
        choices = self.get_step_choices(pipeline_class)
        self.fields["selected_steps"].choices = choices

        # All step checkboxes are selected by default unless already defined on the run
        if not self.instance.selected_steps:
            self.initial["selected_steps"] = [choice[0] for choice in choices]

    @staticmethod
    def get_step_choices(pipeline_class):
        """Return a `choices` list of tuple suitable for a Django ChoiceField."""
        return [(step.__name__, step.__name__) for step in pipeline_class.get_steps()]
