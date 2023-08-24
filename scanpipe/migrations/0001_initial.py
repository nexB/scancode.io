# Generated by Django 3.1.1 on 2020-09-09 15:34

from django.db import migrations, models
import django.db.models.deletion
import scanpipe.models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CodebaseResource',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('path', models.CharField(help_text='The full path value of a resource (file or directory) in the archive it is from.', max_length=2000)),
                ('size', models.BigIntegerField(blank=True, help_text='Size in bytes.', null=True)),
                ('sha1', models.CharField(blank=True, help_text='SHA1 checksum hex-encoded, as in sha1sum.', max_length=40)),
                ('md5', models.CharField(blank=True, help_text='MD5 checksum hex-encoded, as in md5sum.', max_length=32)),
                ('sha256', models.CharField(blank=True, help_text='SHA256 checksum hex-encoded, as in sha256sum.', max_length=64)),
                ('sha512', models.CharField(blank=True, help_text='SHA512 checksum hex-encoded, as in sha512sum.', max_length=128)),
                ('copyrights', models.JSONField(blank=True, default=list, help_text='List of detected copyright statements (and related detection details).')),
                ('holders', models.JSONField(blank=True, default=list, help_text='List of detected copyright holders (and related detection details).')),
                ('authors', models.JSONField(blank=True, default=list, help_text='List of detected authors (and related detection details).')),
                ('licenses', models.JSONField(blank=True, default=list, help_text='List of license detection details.')),
                ('license_expressions', models.JSONField(blank=True, default=list, help_text='List of detected license expressions.')),
                ('emails', models.JSONField(blank=True, default=list, help_text='List of detected emails (and related detection details).')),
                ('urls', models.JSONField(blank=True, default=list, help_text='List of detected URLs (and related detection details).')),
                ('rootfs_path', models.CharField(blank=True, help_text='Path relative to some root filesystem root directory. Useful when working on disk images, docker images, and VM images.Eg.: "/usr/bin/bash" for a path of "tarball-extract/rootfs/usr/bin/bash"', max_length=2000)),
                ('status', models.CharField(blank=True, help_text='Analysis status for this resource.', max_length=30)),
                ('type', models.CharField(choices=[('file', 'File'), ('directory', 'Directory'), ('symlink', 'Symlink')], help_text='Type of this resource as one of: file, directory, symlink', max_length=10)),
                ('extra_data', models.JSONField(blank=True, default=dict, help_text='Optional mapping of extra data key/values.')),
                ('name', models.CharField(blank=True, help_text='File or directory name of this resource.', max_length=255)),
                ('extension', models.CharField(blank=True, help_text='File extension for this resource (directories do not have an extension).', max_length=100)),
                ('programming_language', models.CharField(blank=True, help_text='Programming language of this resource if this is a code file.', max_length=50)),
                ('mime_type', models.CharField(blank=True, help_text='MIME type (aka. media type) for this resource. See https://en.wikipedia.org/wiki/Media_type', max_length=100)),
                ('file_type', models.CharField(blank=True, help_text='Descriptive file type for this resource.', max_length=1024)),
            ],
            options={
                'ordering': ('project', 'path'),
            },
            bases=(scanpipe.models.SaveProjectMessageMixin, models.Model),
        ),
        migrations.CreateModel(
            name='Project',
            fields=[
                ('uuid', models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, primary_key=True, serialize=False, verbose_name='UUID')),
                ('created_date', models.DateTimeField(auto_now_add=True, db_index=True, help_text='Creation date for this project.')),
                ('name', models.CharField(db_index=True, help_text='Name for this project.', max_length=100, unique=True)),
                ('work_directory', models.CharField(editable=False, help_text='Project work directory location.', max_length=2048)),
                ('extra_data', models.JSONField(default=dict, editable=False)),
            ],
            options={
                'ordering': ['-created_date'],
            },
        ),
        migrations.CreateModel(
            name='Run',
            fields=[
                ('task_id', models.UUIDField(blank=True, editable=False, null=True)),
                ('task_start_date', models.DateTimeField(blank=True, editable=False, null=True)),
                ('task_end_date', models.DateTimeField(blank=True, editable=False, null=True)),
                ('task_exitcode', models.IntegerField(blank=True, editable=False, null=True)),
                ('task_output', models.TextField(blank=True, editable=False)),
                ('uuid', models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, primary_key=True, serialize=False, verbose_name='UUID')),
                ('pipeline', models.CharField(max_length=1024)),
                ('created_date', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('description', models.TextField(blank=True)),
                ('project', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='runs', to='scanpipe.project')),
            ],
            options={
                'ordering': ['created_date'],
            },
        ),
        migrations.CreateModel(
            name='ProjectError',
            fields=[
                ('uuid', models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, primary_key=True, serialize=False, verbose_name='UUID')),
                ('created_date', models.DateTimeField(auto_now_add=True)),
                ('model', models.CharField(help_text='Name of the model class.', max_length=100)),
                ('details', models.JSONField(blank=True, default=dict, help_text='Data that caused the error.')),
                ('message', models.TextField(blank=True, help_text='Error message.')),
                ('traceback', models.TextField(blank=True, help_text='Exception traceback.')),
                ('project', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='projecterrors', to='scanpipe.project')),
            ],
            options={
                'ordering': ['created_date'],
            },
        ),
        migrations.CreateModel(
            name='DiscoveredPackage',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(blank=True, help_text='A short code to identify the type of this package. For example: gem for a Rubygem, docker for a container, pypi for a Python Wheel or Egg, maven for a Maven Jar, deb for a Debian package, etc.', max_length=16)),
                ('namespace', models.CharField(blank=True, help_text='Package name prefix, such as Maven groupid, Docker image owner, GitHub user or organization, etc.', max_length=255)),
                ('name', models.CharField(blank=True, help_text='Name of the package.', max_length=100)),
                ('version', models.CharField(blank=True, help_text='Version of the package.', max_length=100)),
                ('qualifiers', models.CharField(blank=True, help_text='Extra qualifying data for a package such as the name of an OS, architecture, distro, etc.', max_length=1024)),
                ('subpath', models.CharField(blank=True, help_text='Extra subpath within a package, relative to the package root.', max_length=200)),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False, unique=True, verbose_name='UUID')),
                ('last_modified_date', models.DateTimeField(blank=True, db_index=True, help_text='Timestamp set when a Package is created or modified', null=True)),
                ('filename', models.CharField(blank=True, db_index=True, help_text='File name of a Resource sometimes part of the URI properand sometimes only available through an HTTP header.', max_length=255)),
                ('primary_language', models.CharField(blank=True, help_text='Primary programming language', max_length=50)),
                ('description', models.TextField(blank=True, help_text='Description for this package. By convention the first line should be a summary when available.')),
                ('release_date', models.DateField(blank=True, db_index=True, help_text='The date that the package file was created, or when it was posted to its original download source.', null=True)),
                ('homepage_url', models.CharField(blank=True, help_text='URL to the homepage for this package.', max_length=1024)),
                ('download_url', models.CharField(blank=True, help_text='A direct download URL.', max_length=2048)),
                ('size', models.BigIntegerField(blank=True, db_index=True, help_text='Size in bytes.', null=True)),
                ('sha1', models.CharField(blank=True, db_index=True, help_text='SHA1 checksum hex-encoded, as in sha1sum.', max_length=40, verbose_name='download SHA1')),
                ('md5', models.CharField(blank=True, db_index=True, help_text='MD5 checksum hex-encoded, as in md5sum.', max_length=32, verbose_name='download MD5')),
                ('bug_tracking_url', models.CharField(blank=True, help_text='URL to the issue or bug tracker for this package', max_length=1024)),
                ('code_view_url', models.CharField(blank=True, help_text='a URL where the code can be browsed online', max_length=1024)),
                ('vcs_url', models.CharField(blank=True, help_text='a URL to the VCS repository in the SPDX form of: "git", "svn", "hg", "bzr", "cvs", https://github.com/nexb/scancode-toolkit.git@405aaa4b3 See SPDX specification "Package Download Location" at https://spdx.org/spdx-specification-21-web-version#h.49x2ik5 ', max_length=1024)),
                ('copyright', models.TextField(blank=True, help_text='Copyright statements for this package. Typically one per line.')),
                ('license_expression', models.TextField(blank=True, help_text='The normalized license expression for this package as derived from its declared license.')),
                ('declared_license', models.TextField(blank=True, help_text='The declared license mention or tag or text as found in a package manifest.')),
                ('notice_text', models.TextField(blank=True, help_text='A notice text for this package.')),
                ('manifest_path', models.CharField(blank=True, help_text='A relative path to the manifest file if any, such as a Maven .pom or a npm package.json.', max_length=1024)),
                ('contains_source_code', models.BooleanField(blank=True, null=True)),
                ('missing_resources', models.JSONField(blank=True, default=list)),
                ('modified_resources', models.JSONField(blank=True, default=list)),
                ('keywords', models.JSONField(blank=True, default=list)),
                ('source_packages', models.JSONField(blank=True, default=list)),
                ('codebase_resources', models.ManyToManyField(related_name='discovered_packages', to='scanpipe.CodebaseResource')),
                ('project', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='discoveredpackages', to='scanpipe.project')),
            ],
            options={
                'ordering': ['uuid'],
            },
            bases=(scanpipe.models.SaveProjectMessageMixin, models.Model),
        ),
        migrations.AddField(
            model_name='codebaseresource',
            name='project',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='codebaseresources', to='scanpipe.project'),
        ),
        migrations.AlterUniqueTogether(
            name='codebaseresource',
            unique_together={('project', 'path')},
        ),
    ]
