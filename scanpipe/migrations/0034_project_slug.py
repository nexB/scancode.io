# Generated by Django 4.2.2 on 2023-06-28 09:36

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0033_project_notes_project_settings"),
    ]

    operations = [
        migrations.AddField(
            model_name="project",
            name="slug",
            field=models.SlugField(max_length=110, null=True),
        ),
    ]
