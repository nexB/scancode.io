# Generated by Django 4.0.6 on 2022-08-15 22:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanpipe', '0024_remove_discoveredpackage_dependencies_data'),
    ]

    operations = [
        migrations.AddField(
            model_name='discovereddependency',
            name='name',
            field=models.CharField(blank=True, help_text='Name of the package.', max_length=100),
        ),
        migrations.AddField(
            model_name='discovereddependency',
            name='namespace',
            field=models.CharField(blank=True, help_text='Package name prefix, such as Maven groupid, Docker image owner, GitHub user or organization, etc.', max_length=255),
        ),
        migrations.AddField(
            model_name='discovereddependency',
            name='qualifiers',
            field=models.CharField(blank=True, help_text='Extra qualifying data for a package such as the name of an OS, architecture, distro, etc.', max_length=1024),
        ),
        migrations.AddField(
            model_name='discovereddependency',
            name='subpath',
            field=models.CharField(blank=True, help_text='Extra subpath within a package, relative to the package root.', max_length=200),
        ),
        migrations.AddField(
            model_name='discovereddependency',
            name='type',
            field=models.CharField(blank=True, help_text='A short code to identify the type of this package. For example: gem for a Rubygem, docker for a container, pypi for a Python Wheel or Egg, maven for a Maven Jar, deb for a Debian package, etc.', max_length=16),
        ),
        migrations.AddField(
            model_name='discovereddependency',
            name='version',
            field=models.CharField(blank=True, help_text='Version of the package.', max_length=100),
        ),
    ]