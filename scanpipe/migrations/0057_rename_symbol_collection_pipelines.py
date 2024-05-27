# Generated by Django 5.0.4 on 2024-05-08 17:13

from django.db import migrations


pipeline_old_names_mapping = {
    "collect_pygments_symbols": "collect_symbols_pygments",
    "collect_source_strings": "collect_strings_gettext",
    "collect_symbols": "collect_symbols_ctags",
    "collect_tree_sitter_symbols": "collect_symbols_tree_sitter",
}


def rename_pipelines_data(apps, schema_editor):
    Run = apps.get_model("scanpipe", "Run")
    for old_name, new_name in pipeline_old_names_mapping.items():
        Run.objects.filter(pipeline_name=old_name).update(pipeline_name=new_name)


def reverse_rename_pipelines_data(apps, schema_editor):
    Run = apps.get_model("scanpipe", "Run")
    for old_name, new_name in pipeline_old_names_mapping.items():
        Run.objects.filter(pipeline_name=new_name).update(pipeline_name=old_name)

class Migration(migrations.Migration):

    dependencies = [
        ("scanpipe", "0056_alter_run_scancodeio_version"),
    ]

    operations = [
        migrations.RunPython(
            rename_pipelines_data,
            reverse_code=reverse_rename_pipelines_data,
        ),
    ]
