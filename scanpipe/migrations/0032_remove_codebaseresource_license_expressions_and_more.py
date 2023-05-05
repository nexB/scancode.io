# Generated by Django 4.2 on 2023-05-05 15:08

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0031_scancode_toolkit_v32_data_updates"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="codebaseresource",
            name="license_expressions",
        ),
        migrations.RemoveField(
            model_name="codebaseresource",
            name="licenses",
        ),
        migrations.AddField(
            model_name="codebaseresource",
            name="detected_license_expression",
            field=models.TextField(blank=True, help_text=""),
        ),
        migrations.AddField(
            model_name="codebaseresource",
            name="detected_license_expression_spdx",
            field=models.TextField(blank=True, help_text=""),
        ),
        migrations.AddField(
            model_name="codebaseresource",
            name="license_clues",
            field=models.JSONField(
                blank=True, default=list, help_text="List of license clues."
            ),
        ),
        migrations.AddField(
            model_name="codebaseresource",
            name="license_detections",
            field=models.JSONField(
                blank=True, default=list, help_text="List of license detection details."
            ),
        ),
        migrations.AddField(
            model_name="codebaseresource",
            name="percentage_of_license_text",
            field=models.FloatField(blank=True, help_text="", null=True),
        ),
    ]
