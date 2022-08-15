# Generated by Django 4.0.6 on 2022-08-12 23:13

from django.db import migrations
from django.db.models import F, Q
from django.db.models.functions import Concat


def migrate_dependencies_to_discovereddependencies(apps, schema_editor):
    DiscoveredPackage = apps.get_model('scanpipe', 'DiscoveredPackage')
    DiscoveredDependency = apps.get_model('scanpipe', 'DiscoveredDependency')

    qs = DiscoveredPackage.objects.filter(dependencies_data__isnull=False)
    for package in qs:
        for pd in package.dependencies_data:
            if "extra_data" in pd:
                pd.pop("extra_data")
            if "resolved_package" in pd:
                pd.pop("resolved_package")
            DiscoveredDependency.objects.create(project=package.project, **pd)


class Migration(migrations.Migration):

    dependencies = [
        ('scanpipe', '0022_rename_dependencies_discoveredpackage_dependencies_data_and_more'),
    ]

    operations = [
        migrations.RunPython(migrate_dependencies_to_discovereddependencies),
    ]