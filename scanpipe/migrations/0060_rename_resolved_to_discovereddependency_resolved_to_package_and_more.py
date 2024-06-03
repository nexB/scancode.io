# Generated by Django 5.0.6 on 2024-06-03 08:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanpipe", "0059_alter_codebaseresource_status"),
    ]

    operations = [
        migrations.RenameField(
            model_name="discovereddependency",
            old_name="resolved_to",
            new_name="resolved_to_package",
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="children_packages",
            field=models.ManyToManyField(
                related_name="parent_packages",
                through="scanpipe.DiscoveredDependency",
                to="scanpipe.discoveredpackage",
            ),
        ),
    ]
