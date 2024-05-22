# Generated by Django 5.0.6 on 2024-06-04 20:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanpipe", "0060_discovereddependency_renames"),
    ]

    operations = [
        migrations.AddField(
            model_name="discovereddependency",
            name="is_direct",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="is_private",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="is_virtual",
            field=models.BooleanField(default=False),
        ),
        migrations.AddIndex(
            model_name="discovereddependency",
            index=models.Index(
                fields=["is_direct"], name="scanpipe_di_is_dire_6dc594_idx"
            ),
        ),
    ]
