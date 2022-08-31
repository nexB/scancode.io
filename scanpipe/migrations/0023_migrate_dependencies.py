# Generated by Django 4.0.6 on 2022-08-12 23:13

from django.core.exceptions import MultipleObjectsReturned, ObjectDoesNotExist
from django.db import migrations

from packageurl import PackageURL


def migrate_dependencies_data_to_discovereddependencies_model(apps, schema_editor):
    DiscoveredPackage = apps.get_model('scanpipe', 'DiscoveredPackage')
    DiscoveredDependency = apps.get_model('scanpipe', 'DiscoveredDependency')

    package_with_dependencies = DiscoveredPackage.objects.exclude(dependencies_data=[])

    for package in package_with_dependencies:
        for dependency_data in package.dependencies_data:
            project = package.project

            # Remove non-supported fields from the data dict
            dependency_data.pop("extra_data", None)
            dependency_data.pop("resolved_package", None)

            # `extracted_requirement` was previously stored as `requirement` prior to
            # https://github.com/nexB/scancode-toolkit/pull/2825/
            requirement = dependency_data.pop("requirement", None)
            if requirement:
                dependency_data["extracted_requirement"] = requirement

            purl = dependency_data.pop("purl", None)
            if purl:
                purl_mapping = PackageURL.from_string(purl).to_dict(empty="")
                dependency_data.update(purl_mapping)

            for_package_uid = dependency_data.pop("for_package_uid")
            try:
                for_package = project.discoveredpackages.get(package_uid=for_package_uid)
            except (ObjectDoesNotExist, MultipleObjectsReturned):
                for_package = None

            datafile_path = dependency_data.pop("datafile_path")
            try:
                datafile_resource = project.codebaseresources.get(path=datafile_path)
            except (ObjectDoesNotExist, MultipleObjectsReturned):
                datafile_resource = None

            DiscoveredDependency.objects.create(
                project=project,
                for_package=for_package,
                datafile_resource=datafile_resource,
                **dependency_data,
            )


class Migration(migrations.Migration):

    dependencies = [
        ('scanpipe', '0022_create_discovereddependencies_model'),
    ]

    operations = [
        migrations.RunPython(migrate_dependencies_data_to_discovereddependencies_model),
    ]
