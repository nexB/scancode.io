.. _scancodeio_settings:

Application Settings
====================

ScanCode.io is configured with environment variables stored in a ``.env`` file.

The ``.env`` file is created at the root of the ScanCode.io codebase during its
installation.
You can configure your preferences using the following settings in the ``.env``
file.

.. note::
    ScanCode.io is based on the Django web framework and its settings system.
    The list of settings available in Django is documented at
    `Django Settings <https://docs.djangoproject.com/en/dev/ref/settings/>`_.

.. tip::
    Settings specific to ScanCode.io are all prefixed with ``SCANCODEIO_``.

**Restarting the services is required following any changes to .env:**

.. code-block:: bash

    docker compose restart web worker

Instance settings
-----------------

DATABASE
^^^^^^^^

The database can be configured using the following settings::

    SCANCODEIO_DB_HOST=localhost
    SCANCODEIO_DB_NAME=scancodeio
    SCANCODEIO_DB_USER=user
    SCANCODEIO_DB_PASSWORD=password
    SCANCODEIO_DB_PORT=5432

.. _scancodeio_settings_require_authentication:

SCANCODEIO_REQUIRE_AUTHENTICATION
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default, the ScanCode.io Web UI and REST API are available without any
authentication.

The authentication system can be enable with this settings::

    SCANCODEIO_REQUIRE_AUTHENTICATION=True

Once enabled, all the Web UI views and REST API endpoints will force the user to login
to gain access.

A management command :ref:`cli_create_user` is available to create users and
generate their API key for authentication.

See :ref:`rest_api_authentication` for details on using the ``API key``
authentication system in the REST API.

.. _scancodeio_settings_workspace_location:

SCANCODEIO_WORKSPACE_LOCATION
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This setting defines the workspace location of a given project.
The **workspace** is the directory where **all of the project's files are stored**
, such as input, codebase, and output files::

    SCANCODEIO_WORKSPACE_LOCATION=/var/scancodeio/workspace/

It defaults to a :guilabel:`var/` directory in the local ScanCode.io codebase.

See :ref:`project_workspace` for more details.

.. _scancodeio_settings_config_dir:

SCANCODEIO_CONFIG_DIR
^^^^^^^^^^^^^^^^^^^^^

The location of the :guilabel:`.scancode/` configuration directory within the project
codebase.

Default: ``.scancode``

This directory allows to provide configuration files and customization for a ScanCode.io
project directly through the codebase files.

For example, to provide a custom attribution template to your project, add it in a
:guilabel:`.scancode/` directory located at the root of your codebase before uploading
it to ScanCode.io. The expected location of the attribution template is::

  .scancode/templates/attribution.html

SCANCODEIO_PROCESSES
^^^^^^^^^^^^^^^^^^^^

By default, multiprocessing is enabled and configured to use an optimal number of CPUs
available on the machine. You can control the number of parallel processes available
to ScanCode.io using the SCANCODEIO_PROCESSES setting::

    SCANCODEIO_PROCESSES=4

Multiprocessing can be disabled entirely using "0"::

    SCANCODEIO_PROCESSES=0

To disable both multiprocessing and threading, use "-1"::

    SCANCODEIO_PROCESSES=-1

.. note::
    Multiprocessing and threading are disabled by default on operating system
    where the multiprocessing start method is not "fork", such as on macOS.

.. _scancodeio_settings_async:

SCANCODEIO_ASYNC
^^^^^^^^^^^^^^^^

When enabled, pipeline runs are **executed asynchronously**, meaning that users can
continue using the app while the pipeline are run in the background.

The ASYNC mode is **enabled by default in a "Run with Docker" configuration** but
**disabled in a "Local development" setup**.

It is possible to enable ASYNC mode in a "local development" setup with the following
setting::

    SCANCODEIO_ASYNC=True

Once enabled, pipeline runs will be sent to a task queue instead of being executed
synchronously in the web server process.

.. warning::
    The ASYNC mode required a **Redis server** and running a **tasks worker** using
    ``$ make worker``.

    On macOS, the ASYNC mode requires the following line in your environment::

        export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

SCANCODEIO_TASK_TIMEOUT
^^^^^^^^^^^^^^^^^^^^^^^

Maximum time allowed for a pipeline to complete.
The pipeline run will be stopped and marked as failed if that limit is reached.

The value is a string with specify unit including hour, minute, second
(e.g. "1h", "3m", "5s")::

    SCANCODEIO_TASK_TIMEOUT=24h

Default: ``24h``

SCANCODEIO_SCAN_FILE_TIMEOUT
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Maximum time allowed for a file to be analyzed when scanning a codebase.

The value unit is second and is defined as an integer::

    SCANCODEIO_SCAN_FILE_TIMEOUT=120

Default: ``120`` (2 minutes)

.. _scancodeio_settings_pipelines_dirs:

SCANCODEIO_PIPELINES_DIRS
^^^^^^^^^^^^^^^^^^^^^^^^^

This setting defines any additional locations that ScanCode.io will search in
for pipelines.
It usually includes a list of comma-separated strings containing full paths
of additional pipelines directories::

    SCANCODEIO_PIPELINES_DIRS=/var/scancodeio/pipelines/,/home/user/pipelines/

.. _scancodeio_settings_policies_file:

SCANCODEIO_POLICIES_FILE
^^^^^^^^^^^^^^^^^^^^^^^^

This setting defines the location of the policies file, or ``policies.yml``.
A valid policies file is required to enable compliance-related features.

.. code-block:: yaml

    license_policies:
    -   license_key: mit
        label: Approved License
        compliance_alert: ''
    -   license_key: mpl-2.0
        label: Restricted License
        compliance_alert: warning
    -   license_key: gpl-3.0
        label: Prohibited License
        compliance_alert: error

- Licenses are referenced by the ``license_key``.
- A Policy is defined with ``label`` and ``compliance_alert``.
- The ``compliance_alert`` accepts 3 values: '' for an empty string, warning, and error.

.. note::
    When the policy feature is enabled, the ``compliance_alert`` values are
    displayed in the UI and returned in all downloadable results.

.. tip::
    Check out the :ref:`tutorial_license_policies` tutorial for in-depth coverage of
    this feature.

SCANCODEIO_PAGINATE_BY
^^^^^^^^^^^^^^^^^^^^^^

The number of objects display per page for each object type can be customized with the
following setting::

    SCANCODEIO_PAGINATE_BY=project=30,error=50,resource=100,package=100,dependency=100

SCANCODEIO_REST_API_PAGE_SIZE
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A numeric value indicating the number of objects returned per page in the REST API::

    SCANCODEIO_REST_API_PAGE_SIZE=100

Default: ``50``

.. warning::
    Using a large page size may have an impact on performances.

SCANCODEIO_LOG_LEVEL
^^^^^^^^^^^^^^^^^^^^

By default, only a minimum of logging messages is displayed in the console, mostly
to provide some progress about pipeline run execution.

Default: ``INFO``

The ``DEBUG`` value can be provided to this setting to see all ScanCode.io debug
messages to help track down configuration issues for example.
This mode can be enabled globally through the ``.env`` file::

    SCANCODEIO_LOG_LEVEL=DEBUG

Or, in the context of running a :ref:`scanpipe command <command_line_interface>`:

.. code-block:: console

    $ SCANCODEIO_LOG_LEVEL=DEBUG bin/scanpipe [command]

The web server can be started in DEBUG mode with:

.. code-block:: console

    $ SCANCODEIO_LOG_LEVEL=DEBUG make run

TIME_ZONE
^^^^^^^^^

A string representing the time zone for the current ScanCode.io installation. By
default the ``UTC`` time zone is used::

    TIME_ZONE=Europe/Paris

.. note::
    You can view a detailed list of time zones `here.
    <https://en.wikipedia.org/wiki/List_of_tz_database_time_zones>`_

.. _scancodeio_settings_external_services:

External services (integrations)
--------------------------------

.. _scancodeio_settings_purldb:

PURLDB
^^^^^^

A public instance of **PurlDB** is accessible at https://public.purldb.io/.

Alternatively, you can deploy your own instance of PurlDB by
following the instructions provided in the documentation at
https://purldb.readthedocs.io/.

To configure your local environment, set the ``PURLDB_URL`` in your ``.env`` file::

    PURLDB_URL=https://public.purldb.io/

While using the public PurlDB instance, providing an API key is optional.
However, if authentication is enabled on your PurlDB instance, you can provide the
API key using ``PURLDB_API_KEY``::

    PURLDB_API_KEY=insert_your_api_key_here

.. note::
    Once the PurlDB is configured, a new "PurlDB" tab will be available in the
    discovered package details view.

.. _scancodeio_settings_vulnerablecode:

VULNERABLECODE
^^^^^^^^^^^^^^

You have the option to either deploy your instance of
`VulnerableCode <https://github.com/aboutcode-org/vulnerablecode/>`_
or connect to the `public instance <https://public.vulnerablecode.io/>`_.

To configure your local environment, set the ``VULNERABLECODE_URL`` in your ``.env``
file::

    VULNERABLECODE_URL=https://public.vulnerablecode.io/

When using the public VulnerableCode instance, providing an API key is optional.
However, if authentication is enabled on your VulnerableCode instance,
you can provide the API key using ``VULNERABLECODE_API_KEY``::

    VULNERABLECODE_API_KEY=insert_your_api_key_here

.. _scancodeio_settings_matchcodeio:

MATCHCODE.IO
^^^^^^^^^^^^

There is currently no public instance of MatchCode.io.

Alternatively, you can deploy your own instance of MatchCode.io by
following the instructions provided in the documentation at
https://purldb.readthedocs.io/.

To configure your local environment, set the ``MATCHCODEIO_URL`` in your ``.env`` file::

    MATCHCODEIO_URL=https://<Address to MatchCode.io host>/

If authentication is enabled on your MatchCode.io instance, you can provide the
API key using ``MATCHCODEIO_API_KEY``::

    MATCHCODEIO_API_KEY=insert_your_api_key_here

.. _scancodeio_settings_fetch_authentication:

Fetch Authentication
--------------------

Several settings are available to define the credentials required to access your
private files, depending on the authentication type: Basic, Digest, Token header, etc.

.. note::
    The provided credentials are enabled for all projects on the ScanCode.io instance.

.. warning::
    Ensure that the provided ``host`` values are fully qualified, including the domain
    and subdomain.

.. _scancodeio_settings_fetch_basic_auth:

SCANCODEIO_FETCH_BASIC_AUTH
^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can provide credentials for input URLs protected by Basic Authentication using
the ``host=user,password`` syntax::

    SCANCODEIO_FETCH_BASIC_AUTH="www.host1.com=user,password;www.host2.com=user,password;"

.. _scancodeio_settings_fetch_digest_auth:

SCANCODEIO_FETCH_DIGEST_AUTH
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can provide credentials for input URLs protected by Digest Authentication using
the ``host=user,password`` syntax::

    SCANCODEIO_FETCH_DIGEST_AUTH="www.host1.com=user,password;www.host2.com=user,password;"

.. _scancodeio_settings_fetch_headers:

SCANCODEIO_FETCH_HEADERS
^^^^^^^^^^^^^^^^^^^^^^^^

When authentication credentials can be provided through HTTP request headers, you can
use the following syntax::

    SCANCODEIO_FETCH_HEADERS="www.host1.com=Header1=value,Header2=value;"

Example for a GitHub private repository::

    SCANCODEIO_FETCH_HEADERS="raw.github.com=Authorization=token <YOUR_TOKEN>"

.. _scancodeio_settings_netrc_location:

SCANCODEIO_NETRC_LOCATION
^^^^^^^^^^^^^^^^^^^^^^^^^

If your credentials are stored in a
`.netrc <https://everything.curl.dev/usingcurl/netrc>`_ file, you can provide its
location on disk using::

    SCANCODEIO_NETRC_LOCATION="~/.netrc"

If you are deploying ScanCode.io using Docker and you wish to use a netrc file,
you can provide it to the Docker container by moving the netrc file to
``/etc/scancodeio/.netrc`` and then updating the ``.env`` file with the line::

    SCANCODEIO_NETRC_LOCATION="/etc/scancodeio/.netrc"

.. _scancodeio_settings_skopeo_credentials:

SCANCODEIO_SKOPEO_CREDENTIALS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can define the username and password for Skopeo to access containers private
registries using the ``host=user:password`` syntax::

  SCANCODEIO_SKOPEO_CREDENTIALS="host1=user:password,host2=user:password"

.. _scancodeio_settings_skopeo_authfile_location:

SCANCODEIO_SKOPEO_AUTHFILE_LOCATION
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Specify the path of the Skopeo authentication file using the following setting::

    SCANCODEIO_SKOPEO_AUTHFILE_LOCATION="/path/to/auth.json"
