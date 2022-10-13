# Generated by Django 4.1.2 on 2022-10-13 06:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scanpipe", "0024_remove_discoveredpackage_dependencies_data"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="discoveredpackage",
            name="last_modified_date",
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="api_data_url",
            field=models.CharField(
                blank=True,
                help_text="API URL to obtain structured data for this package such as the URL to a JSON or XML api its package repository.",
                max_length=1024,
                verbose_name="API data URL",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="datasource_id",
            field=models.CharField(
                blank=True,
                help_text="The identifier for the datafile handler used to obtain this package.",
                max_length=64,
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="file_references",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="List of file paths and details for files referenced in a package manifest. These may not actually exist on the filesystem. The exact semantics and base of these paths is specific to a package type or datafile format.",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="parties",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="A list of parties such as a person, project or organization.",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="repository_download_url",
            field=models.CharField(
                blank=True,
                help_text="Download URL to download the actual archive of code of this package in its package repository. This may be different from the actual download URL.",
                max_length=1024,
                verbose_name="Repository download URL",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="repository_homepage_url",
            field=models.CharField(
                blank=True,
                help_text="URL to the page for this package in its package repository. This is typically different from the package homepage URL proper.",
                max_length=1024,
                verbose_name="Repository homepage URL",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="sha256",
            field=models.CharField(
                blank=True,
                help_text="SHA256 checksum hex-encoded, as in sha256sum.",
                max_length=64,
                verbose_name="SHA256",
            ),
        ),
        migrations.AddField(
            model_name="discoveredpackage",
            name="sha512",
            field=models.CharField(
                blank=True,
                help_text="SHA512 checksum hex-encoded, as in sha512sum.",
                max_length=128,
                verbose_name="SHA512",
            ),
        ),
        migrations.AlterField(
            model_name="codebaseresource",
            name="md5",
            field=models.CharField(
                blank=True,
                help_text="MD5 checksum hex-encoded, as in md5sum.",
                max_length=32,
                verbose_name="MD5",
            ),
        ),
        migrations.AlterField(
            model_name="codebaseresource",
            name="sha1",
            field=models.CharField(
                blank=True,
                help_text="SHA1 checksum hex-encoded, as in sha1sum.",
                max_length=40,
                verbose_name="SHA1",
            ),
        ),
        migrations.AlterField(
            model_name="codebaseresource",
            name="sha256",
            field=models.CharField(
                blank=True,
                help_text="SHA256 checksum hex-encoded, as in sha256sum.",
                max_length=64,
                verbose_name="SHA256",
            ),
        ),
        migrations.AlterField(
            model_name="codebaseresource",
            name="sha512",
            field=models.CharField(
                blank=True,
                help_text="SHA512 checksum hex-encoded, as in sha512sum.",
                max_length=128,
                verbose_name="SHA512",
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="bug_tracking_url",
            field=models.CharField(
                blank=True,
                help_text="URL to the issue or bug tracker for this package.",
                max_length=1024,
                verbose_name="Bug tracking URL",
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="code_view_url",
            field=models.CharField(
                blank=True,
                help_text="a URL where the code can be browsed online.",
                max_length=1024,
                verbose_name="Code view URL",
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="download_url",
            field=models.CharField(
                blank=True,
                help_text="A direct download URL.",
                max_length=2048,
                verbose_name="Download URL",
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="filename",
            field=models.CharField(
                blank=True,
                help_text="File name of a Resource sometimes part of the URI properand sometimes only available through an HTTP header.",
                max_length=255,
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="homepage_url",
            field=models.CharField(
                blank=True,
                help_text="URL to the homepage for this package.",
                max_length=1024,
                verbose_name="Homepage URL",
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="md5",
            field=models.CharField(
                blank=True,
                help_text="MD5 checksum hex-encoded, as in md5sum.",
                max_length=32,
                verbose_name="MD5",
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="primary_language",
            field=models.CharField(
                blank=True, help_text="Primary programming language.", max_length=50
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="release_date",
            field=models.DateTimeField(
                blank=True,
                help_text="The date that the package file was created, or when it was posted to its original download source.",
                null=True,
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="sha1",
            field=models.CharField(
                blank=True,
                help_text="SHA1 checksum hex-encoded, as in sha1sum.",
                max_length=40,
                verbose_name="SHA1",
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="size",
            field=models.BigIntegerField(
                blank=True, help_text="Size in bytes.", null=True
            ),
        ),
        migrations.AlterField(
            model_name="discoveredpackage",
            name="vcs_url",
            field=models.CharField(
                blank=True,
                help_text='A URL to the VCS repository in the SPDX form of: "git", "svn", "hg", "bzr", "cvs", https://github.com/nexb/scancode-toolkit.git@405aaa4b3 See SPDX specification "Package Download Location" at https://spdx.org/spdx-specification-21-web-version#h.49x2ik5',
                max_length=1024,
                verbose_name="VCS URL",
            ),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(
                fields=["filename"], name="scanpipe_di_filenam_1e940b_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(
                fields=["primary_language"], name="scanpipe_di_primary_507471_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(fields=["size"], name="scanpipe_di_size_ddec1a_idx"),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(fields=["md5"], name="scanpipe_di_md5_dc8dd2_idx"),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(fields=["sha1"], name="scanpipe_di_sha1_0e1e43_idx"),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(fields=["sha256"], name="scanpipe_di_sha256_cefc41_idx"),
        ),
        migrations.AddIndex(
            model_name="discoveredpackage",
            index=models.Index(fields=["sha512"], name="scanpipe_di_sha512_a6344e_idx"),
        ),
    ]
