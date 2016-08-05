Introduction
============

Nova is designed to audit the compliance and security level of a system. It is
composed of multiple modules, which ingest YAML configuration profiles to run a
single or series of audits against a system.

Two different installation methods are outlined below. The first method is more
stable (and therefore recommended). This method uses Salt's package manager to
track versioned, packaged updates to Hubble's components.

The second method installs directly from git. It should be considered bleeding
edge and possibly unstable.

Installation
============

Each of the four HubbleStack components have been packaged for use with Salt's
Package Manager (SPM). Note that all SPM installation commands should be done
on the *Salt Master*.

**Required Configuration**

Salt's Package Manager (SPM) installs files into `/srv/spm/{salt,pillar}`.
Ensure that this path is defined in your Salt Master's `file_roots`:

.. code-block:: yaml

    file_roots:
      - /srv/salt
      - /srv/spm/salt

.. note:: This should be the default value. To verify run: `salt-call config.get file_roots`

.. tip:: Remember to restart the Salt Master after making this change to the configuration.

Installation (Packages)
-----------------------

Installation is as easy as downloading and installing a package. (Note: in
future releases you'll be able to subscribe directly to our HubbleStack SPM
repo for updates and bugfixes!)

.. code-block:: shell

    wget https://spm.hubblestack.io/2016.7.0_RC1/hubblestack_nova-2016.7.0_RC1-1.spm
    spm local install hubblestack_nova-2016.7.0_RC1-1.spm

You should now be able to sync the new modules to your minion(s) using the
`sync_modules` Salt utility:

.. code-block:: shell

    salt \* saltutil.sync_modules

Once these modules are synced you are ready to run a HubbleStack Nova audit. 

Skip to [Usage].

Installation (Manual)
---------------------

Place `hubble.py <_modules/hubble.py>` in your ``_modules/`` directory in your Salt
fileserver (whether roots or gitfs) and sync it to the minion(s).

.. code-block:: shell

    git clone https://github.com/hubblestack/nova.git hubblestack-nova.git
    cd hubblestack-nova.git
    mkdir -p /srv/salt/_modules/
    cp _modules/hubble.py /srv/salt/_modules/
    cp -a hubblestack_nova /srv/salt/

    salt \* saltutil.sync_modules
    salt \* hubble.sync

Usage
=====

There are four primary functions in the hubble.py module:

1. ``hubble.sync`` will sync the ``hubblestack_nova/`` directory to the minion(s).
2. ``hubble.load`` will load the synced audit modules and their yaml configuration files. 
3. ``hubble.audit`` will audit the minion(s) using the YAML profile(s) you provide as comma-separated arguments
4. ``hubble.top`` will audit the minion(s) using the ``top.nova`` configuration.

``hubble.audit`` takes two optional arguments. The first is a comma-separated
list of paths.  These paths can be files or directories within the
``hubblestack_nova`` directory. The second argument allows for toggling Nova
configuration, such as verbosity, level of detail, etc.

If ``hubble.audit`` is run without targeting any audit configs or directories,
it will instead run ``hubble.top`` with no arguments.

``hubble.audit`` will return a list of audits which were successful, and a list
of audits which failed.

Here are some example calls:

.. code-block:: bash

    # Run the cve scanner and the CIS profile:
    salt \* hubble.audit cve.scan-v2,cis.centos-7-level-1-scored-v1

    # Run hubble.top with the default topfile (top.nova)
    salt \* hubble.top

    # Run all yaml configs and tags under salt://hubblestack_nova/foo/ and
    # salt://hubblestack_nova/bar, but only run audits with tags starting
    # with "CIS"
    salt \* hubble.audit foo,bar tags='CIS*'


Nova Topfiles
-------------

Nova topfiles look very similar to saltstack topfiles, except the top-level
key is always ``nova``, as nova doesn't have environments.

.. code-block:: yaml

    nova:
      '*':
        - cve.scan-v2
        - network.ssh
        - network.smtp
      'web*':
        - cis.centos-7-level-1-scored-v1
        - cis.centos-7-level-2-scored-v1
      'G@os_family:debian':
        - network.ssh
        - cis.debian-7-level-1-scored: 'CIS*'

Additionally, all nova topfile matches are compound matches, so you never
need to define a match type like you do in saltstack topfiles.

Each list item is a string representing the dot-separated location of a
yaml file which will be run with hubble.audit. You can also specify a
tag glob to use as a filter for just that yaml file, using a colon
after the yaml file (turning it into a dictionary). See the last two lines
in the yaml above for examples.

Examples:

.. code-block:: bash

    salt '*' hubble.top
    salt '*' hubble.top foo/bar/top.nova
    salt '*' hubble.top foo/bar.nova verbose=True


Compensating Control Configuration
----------------------------------

In some cases, your organization may want to skip certain audit checks for
certain hosts. This is supported via compensating control configuration.

You can skip a check globally by adding a ``control: <reason>`` key to the check
itself. This key should be added at the same level as ``description`` and
``trigger`` pieces of a check. In this case, the check will never run, and will
output under the ``Controlled`` results key.

Nova also supports separate control profiles, for more fine-grained control
using topfiles. You can use a separate YAML top-level key called ``control``.
Generally, you'll put this top-level key inside of a separate YAML file and
only include it in the top-data for the hosts for which it is relevant.

For these separate control configs, the audits will always run, whether they
are controlled or not. However, controlled audits which fail will be converted
from ``Failure`` to ``Controlled`` in a post-processing operation.

The control config syntax is as follows:

.. code-block:: yaml

    control:
      - CIS-2.1.4: This is the reason we control the check
      - some_other_tag:
          reason: This is the reason we control the check
      - a_third_tag_with_no_reason

Note that providing a reason for the control is optional. Any of the three
formats shown in the yaml list above will work.

Once you have your compensating control config, just target the yaml to the
hosts you want to control using your topfile. In this case, all the audits will
still run, but if any of the controlled checks fail, they will be removed from
``Failure`` and added to ``Controlled``, and will be treated as a Success for
the purposes of compliance percentage.


Schedule
--------

In order to run the audits once daily, you can use the following schedule:

.. code-block:: yaml

    schedule:
      nova_day:
        function: hubble.top
        seconds: 86400

Configuration
=============

Under the Hood
==============

1. The directory/environment in which nova searches for audit modules are
configurable via pillar. The defaults are shown below:

.. code-block:: yaml

    hubblestack:
      nova:
        saltenv: base
        dir: salt://hubblestack_nova

2. By default, ``hubble.audit`` will call ``hubble.load`` (which in turn calls
``hubble.sync``) in order to ensure that it is auditing with the most up-to-date
information. These operations are fairly fast, but if you want to avoid the
additional overhead, you can disable these behaviors via pillar (defaults are
shown, change to False to disable behaviors):

.. code-block:: yaml

    hubblestack:
      nova:
        autosync: True
        autoload: True

Development
===========

If you're interested in contributing to this project this section outlines the
structure and requirements for Nova audit module development.

Anatomy of a Nova audit module
------------------------------

.. code-block:: python

    # -*- encoding: utf-8 -*-
    '''
    Loader and primary interface for nova modules

    :maintainer: HubbleStack
    :maturity: 20160214
    :platform: Linux
    :requires: SaltStack

    '''
    from __future__ import absolute_import
    import logging

All Nova plugins should include the above header, expanding the docstring to
include full documentation


.. code-block:: python

    import fnmatch
    import salt.utils

    def __virtual__():
        if salt.utils.is_windows():
            return False, 'This audit module only runs on linux'
        return True


    def audit(data_list, tag, verbose=False, show_profile=False, debug=False):
        __tags__ = []
        for profile, data in data_list:
            # This is where you process the dictionaries passed in by hubble.py,
            # searching for data pertaining to this audit module. Modules which
            # require no data should use yaml which is empty except for a
            # top-level key, and should only do work if the top-level key is
            # found in the data

            # if show_profile is True, then we need to also inject the profile
            # in the data for each check so that it appears in verbose output
            pass

        ret = {'Success': [], 'Failure': []}
        for tag in __tags__:
            if fnmatch.fnmatch(tag, tags):
                # We should run this tag
                # <do audit stuff here>
                ret['Success'].append(tag)
        return ret


All Nova plugins require a ``__virtual__()`` function to determine module
compatibility, and an ``audit()`` function to perform the actual audit
functionality

The ``audit()`` function must take four arguments, ``data_list``, ``tag``,
``verbose``, ``show_profile``, and ``debug``. The ``data_list`` argument is a
list of dictionaries passed in by ``hubble.py``. ``hubble.py`` gets this data
from loading the specified yaml for the audit run. Your audit module should
only run if it finds its own data in this list. The ``tag`` argument is a glob
expression for which tags the audit function should run. It is the job of the
audit module to compare the ``tag`` glob with all tags supported by this module
and only run the audits which match. The ``verbose`` argument defines whether
additional information should be returned for audits, such as description and
remediation instructions. The ``show_profile`` argument tells whether the
profile should be injected into the verbose data for each check. The ``debug``
argument tells whether the module should log additional debugging information
at debug log level.

The return value should be a dictionary, with optional keys "Success",
"Failure", and "Controlled". The values for these keys should be a list of
one-key dictionaries in the form of ``{<tag>: <string_description>}``, or a
list of one-key dictionaries in the form of ``{<tag>: <data_dict>}`` (in the
case of ``verbose``).

Contribute
==========

If you are interested in contributing or offering feedback to this project feel
free to submit an issue or a pull request. We're very open to community
contribution.
