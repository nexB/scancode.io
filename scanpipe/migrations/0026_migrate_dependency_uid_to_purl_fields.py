# Generated by Django 4.0.6 on 2022-08-15 22:25

from django.db import migrations
from django.db.models import Q
from packageurl import PackageURL


def migrate_dependency_uids_to_purl_fields(apps, schema_editor):
    DiscoveredDependency = apps.get_model('scanpipe', 'DiscoveredDependency')

    qs = DiscoveredDependency.objects.exclude(
        Q(dependency_uid="") | Q(dependency_uid__isnull=True)
    )
    for dependency in qs:
        purled_dependency_uid_mapping = PackageURL.from_string(dependency.dependency_uid).to_dict()
        for field_name, value in purled_dependency_uid_mapping.items():
            if not value:
                continue
            setattr(dependency, field_name, value)
        dependency.save()


class Migration(migrations.Migration):

    dependencies = [
        ('scanpipe', '0025_discovereddependency_name_and_more'),
    ]

    operations = [
        migrations.RunPython(migrate_dependency_uids_to_purl_fields),
    ]
