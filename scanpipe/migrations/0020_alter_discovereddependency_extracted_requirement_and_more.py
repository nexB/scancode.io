# Generated by Django 4.0.6 on 2022-07-21 19:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanpipe', '0019_codebaseresource_package_data_discovereddependency'),
    ]

    operations = [
        migrations.AlterField(
            model_name='discovereddependency',
            name='extracted_requirement',
            field=models.CharField(help_text='The version requirements of this dependency.', max_length=64),
        ),
        migrations.AlterField(
            model_name='discovereddependency',
            name='scope',
            field=models.CharField(help_text='The scope of this dependency, how it is used in a project.', max_length=64),
        ),
    ]
