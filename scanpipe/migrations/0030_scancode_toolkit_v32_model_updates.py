# Generated by Django 4.2 on 2023-05-05 06:52

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0029_codebaseresource_scanpipe_co_type_ea1dd7_idx_and_more"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="discoveredpackage",
            name="contains_source_code",
        ),
        migrations.RemoveField(
            model_name="discoveredpackage",
            name="manifest_path",
        ),
        migrations.RemoveIndex(
            model_name="discoveredpackage",
            name="scanpipe_di_license_e8ce32_idx",
        ),
        migrations.RenameField(
            model_name="discoveredpackage",
            old_name="license_expression",
            new_name="declared_license_expression",
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="declared_license_expression",
            field=models.TextField(
                blank=True,
                help_text="The license expression for this package typically derived from its extracted_license_statement or from some other type-specific routine or convention.",
            ),
        ),
        migrations.RenameField(
            model_name="discoveredpackage",
            old_name="declared_license",
            new_name="extracted_license_statement",
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="extracted_license_statement",
            field=models.TextField(
                blank=True,
                help_text="The license statement mention, tag or text as found in a package manifest and extracted. This can be a string, a list or dict of strings possibly nested, as found originally in the manifest.",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="declared_license_expression_spdx",
            field=models.TextField(
                blank=True,
                help_text="The SPDX license expression for this package converted from its declared_license_expression.",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="holder",
            field=models.TextField(
                blank=True,
                help_text="Holders for this package. Typically one per line.",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="license_detections",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="A list of LicenseDetection mappings typically derived from its extracted_license_statement or from some other type-specific routine or convention.",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="other_license_detections",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="A list of LicenseDetection mappings which is different from the declared_license_expression, (i.e. not the primary license) These are detections for the detection for the license expressions in other_license_expression. ",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="other_license_expression",
            field=models.TextField(
                blank=True,
                help_text="The license expression for this package which is different from the declared_license_expression, (i.e. not the primary license) routine or convention.",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="other_license_expression_spdx",
            field=models.TextField(
                blank=True,
                help_text="The other SPDX license expression for this package converted from its other_license_expression.",
            ),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(
                fields=["declared_license_expression"],
                name="scanpipe_di_declare_4b8499_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(
                fields=["other_license_expression"],
                name="scanpipe_di_other_l_1f1616_idx",
            ),
        ),

        # CodebaseResource
        migrations.RenameField(
            model_name="codebaseresource",
            old_name="license_expressions",
            new_name="detected_license_expression",
        ),
        migrations.AlterField(
            model_name="codebaseresource",
            name="detected_license_expression",
            field=models.TextField(blank=True, help_text="TODO"),
        ),
        migrations.RenameField(
            model_name="codebaseresource",
            old_name="licenses",
            new_name="license_detections",
        ),
        migrations.AddField(
            model_name="codebaseresource",
            name="detected_license_expression_spdx",
            field=models.TextField(blank=True, help_text="TODO"),
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
            name="percentage_of_license_text",
            field=models.FloatField(blank=True, help_text="TODO", null=True),
        ),
    ]
