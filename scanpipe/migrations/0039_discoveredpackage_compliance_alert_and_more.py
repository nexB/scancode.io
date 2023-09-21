# Generated by Django 4.2.3 on 2023-07-11 12:22

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0038_migrate_vulnerability_data"),
    ]

    operations = [
        migrations.AddField(
            model_name="discoveredpackage",
            name="compliance_alert",
            field=models.CharField(
                blank=True,
                choices=[
                    ("ok", "Ok"),
                    ("warning", "Warning"),
                    ("error", "Error"),
                    ("missing", "Missing"),
                ],
                editable=False,
                help_text="Indicates how the license expression complies with provided policies.",
                max_length=10,
            ),
        ),
        migrations.AlterField(
            model_name="codebaseresource",
            name="compliance_alert",
            field=models.CharField(
                blank=True,
                choices=[
                    ("ok", "Ok"),
                    ("warning", "Warning"),
                    ("error", "Error"),
                    ("missing", "Missing"),
                ],
                editable=False,
                help_text="Indicates how the license expression complies with provided policies.",
                max_length=10,
            ),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(
                fields=["compliance_alert"], name="scanpipe_di_complia_ccf329_idx"
            ),
        ),
    ]
