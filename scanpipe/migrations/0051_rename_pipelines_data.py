# Generated by Django 5.0.1 on 2024-01-17 16:32

from django.db import migrations


pipeline_old_names_mapping = {
    "docker": "analyze_docker_image",
    "root_filesystems": "analyze_root_filesystem_or_vm_image",
    "docker_windows": "analyze_windows_docker_image",
    "inspect_manifest": "inspect_packages",
    "deploy_to_develop": "map_deploy_to_develop",
    "scan_package": "scan_single_package",
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
        ("scanpipe", "0050_remove_project_input_sources"),
    ]

    operations = [
        migrations.RunPython(
            rename_pipelines_data,
            reverse_code=reverse_rename_pipelines_data,
        ),
    ]
