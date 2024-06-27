# Generated by Django 5.0.6 on 2024-06-04 20:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanpipe", "0061_codebaseresource_is_legal_and_more"),
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
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(
                fields=["is_private"], name="scanpipe_di_is_priv_9ffd1a_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(
                fields=["is_virtual"], name="scanpipe_di_is_virt_c5c176_idx"
            ),
        ),
    ]