# Generated by Django 4.2 on 2023-04-18 14:39

import django.core.serializers.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0028_codebaserelation_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="projecterror",
            name="details",
            field=models.JSONField(
                blank=True,
                default=dict,
                encoder=django.core.serializers.json.DjangoJSONEncoder,
                help_text="Data that caused the error.",
            ),
        ),
    ]