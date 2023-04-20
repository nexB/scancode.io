# Generated by Django 4.2 on 2023-04-18 06:33

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0027_remove_webhooksubscription_sent_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="CodebaseRelation",
            fields=[
                (
                    "uuid",
                    models.UUIDField(
                        db_index=True,
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                        verbose_name="UUID",
                    ),
                ),
                (
                    "extra_data",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Optional mapping of extra data key/values.",
                    ),
                ),
                (
                    "relationship",
                    models.CharField(
                        choices=[
                            ("identical", "Identical"),
                            ("compiled", "Compiled"),
                            ("path_match", "Path Match"),
                        ],
                        max_length=30,
                    ),
                ),
                ("match_type", models.CharField(max_length=30)),
            ],
            options={
                "ordering": ["from_resource__path", "to_resource__path"],
            },
        ),
        migrations.AlterUniqueTogether(
            name="codebaseresource",
            unique_together=set(),
        ),
        migrations.AddIndex(
            model_name="codebaseresource",
            index=models.Index(fields=["path"], name="scanpipe_co_path_6abc6a_idx"),
        ),
        migrations.AddIndex(
            model_name="codebaseresource",
            index=models.Index(fields=["name"], name="scanpipe_co_name_4da308_idx"),
        ),
        migrations.AddIndex(
            model_name="codebaseresource",
            index=models.Index(
                fields=["extension"], name="scanpipe_co_extensi_afba0e_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="codebaseresource",
            index=models.Index(
                fields=["programming_language"], name="scanpipe_co_program_5aefaf_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="codebaseresource",
            index=models.Index(fields=["sha1"], name="scanpipe_co_sha1_dd8950_idx"),
        ),
        migrations.AddConstraint(
            model_name="codebaseresource",
            constraint=models.UniqueConstraint(
                fields=("project", "path"),
                name="scanpipe_codebaseresource_unique_path_within_project",
            ),
        ),
        migrations.AddField(
            model_name="codebaserelation",
            name="from_resource",
            field=models.ForeignKey(
                editable=False,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="related_to",
                to="scanpipe.codebaseresource",
            ),
        ),
        migrations.AddField(
            model_name="codebaserelation",
            name="project",
            field=models.ForeignKey(
                editable=False,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="%(class)ss",
                to="scanpipe.project",
            ),
        ),
        migrations.AddField(
            model_name="codebaserelation",
            name="to_resource",
            field=models.ForeignKey(
                editable=False,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="related_from",
                to="scanpipe.codebaseresource",
            ),
        ),
    ]