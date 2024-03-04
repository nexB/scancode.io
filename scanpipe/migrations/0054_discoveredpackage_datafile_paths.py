# Generated by Django 5.0.2 on 2024-03-01 16:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanpipe", "0053_restructure_pipelines_data"),
    ]

    operations = [
        migrations.RenameField(
            model_name="discoveredpackage",
            old_name="datasource_id",
            new_name="datasource_ids",
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="datafile_paths",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="A list of Resource paths for package datafiles which were used to assemble this pacakage.",
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="datasource_ids",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="The identifiers for the datafile handlers used to obtain this package.",
            ),
        ),
    ]
