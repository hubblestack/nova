Nova
====

Nova plugins are designed specifically for auditing the compliance and security level
of an existing system. These plugins are designed to alow an administrator to
run security checks or even groups of security checks within their SaltStack
installation. This allows for real-time insight into the compliance level of
running systems.

Installation
============

Place `hubble.py <_modules/hubble.py>`_ in your ``_modules/`` directory in your Salt
fileserver (whether roots or gitfs) and sync it to the minion.

Create a ``hubblestack_nova`` directory in the root of your Salt fileserver's
``base`` environment. Inside of this directory, create a directory tree to
organize your audit modules. Place any desired audit modules into this
directory tree, along with any supporting files (yaml files, etc). Nova audits
are targeted via this directory structure, with an optional filter on tags

The directory/environment in which nova searches for audit modules are
configurable via pillar. The defaults are shown below:

.. code-block:: yaml

    hubblestack.nova.dir: salt://hubblestack_nova
    hubblestack.nova.saltenv: base

Usage
=====

There are three functions in the hubble.py module. ``hubble.sync`` will sync the
configured ``hubblestack_nova/`` directory to the minion. ``hubble.load`` will
load the synced audit modules and their yaml configuration files.  Finally,
``hubble.audit`` will run the audits.

By default, ``hubble.audit`` will call ``hubble.load`` (which in turn calls
``hubble.sync``) (in order to ensure that it is auditing with the most up-to-date
information. These operations are fairly fast, but if you want to avoid the
additional overhead, you can disable these behaviors via pillar (defaults are
shown, change to False to disable behaviors):

.. code-block:: yaml

    hubblestack.nova.autosync: True
    hubblestack.nova.autoload: True

``hubble.audit`` takes two optional arguments. The first is a comma-separated
list of paths.  These paths can be files or directories. If a path is a
directory, all modules below that directory will be run. If it is a file, that
file will be run.

The second argument is a glob pattern, against which audit tags will be
matched. All audits have an accompanying tag. Nova modules are designed to take
this argument, compare it to each tag that module handles, and only run those
which match the argument (using ``fnmatch``).

``hubble.audit`` will return a list of audits which were successful, and a list
of audits which failed.

Here are some example calls:

.. code-block:: bash

    # Run all yaml configs and tags under salt://hubblestack_nova/
    salt '*' hubble.audit

    # Run all yaml configs and tags under salt://hubblestack_nova/foo/
    # Will also run salt://hubblestack_nova/foo.yaml if it exists
    salt '*' hubble.audit modules=foo

    # Run all yaml configs and tags under salt://hubblestack_nova/foo/ and
    # salt://hubblestack_nova/bar, but only run audits with tags starting
    # with "CIS"
    salt '*' hubble.audit modules=foo,bar tags='CIS*'

Compensating Control Configuration
----------------------------------

In some cases, your organization may want to skip certain audit checks for
certain hosts. This is supported via compensating control configuration.

You can skip a check globally by adding a ``control: <reason>`` key to the check
itself. This key should be added at the same level as ``description`` and
``trigger`` pieces of a check. In this case, the check will never run, and will
be output under the ``Controlled`` results key.

For more fine-grained control using topfiles, you can use a separate yaml
top-level key called ``control``. Generally, you'll put this top-level key
inside of a separate yaml file and only include it in the top-data for the
hosts for which it is relevant.

The data is just a list of tags which will be converted from ``Failure`` to
``Controlled`` after the audits have been run. Reasons can also be provided,
and the format is such that additional features can be added later. Here is
some sample data:

.. code-block:: yaml

    control:
      - CIS-2.1.4: This is the reason we control the check
      - some_other_tag:
          reason: This is the reason we control the check
      - a_third_tag_with_no_reason

Once you have your compensating control config, just target the yaml to the
hosts you want to control using your topfile. In this case, all the audits will
still run, but if any of the controlled checks fail, they will be removed from
``Failure`` and added to ``Controlled``, and will be treated as a Success for
the purposes of compliance percentage.


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


    def audit(data_list, tag, verbose=False):
        __tags__ = []
        for data in data_list:
            # This is where you process the dictionaries passed in by hubble.py,
            # searching for data pertaining to this audit module. Modules which
            # require no data should use yaml which is empty except for a
            # top-level key, and should only do work if the top-level key is
            # found in the data
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

The ``audit()`` function must take three arguments, ``data_list``, ``tag`` and
``verbose``. The ``data_list`` argument is a list of dictionaries passed in by
``hubble.py``. ``hubble.py`` gets this data from loading the specified yaml for
the audit run. Your audit module should only run if it finds its own data in
this list. The ``tag`` argument is a glob expression for which tags the audit
function should run. It is the job of the audit module to compare the ``tag``
glob with all tags supported by this module and only run the audits which
match. The ``verbose`` argument defines whether additional information should
be returned for audits, such as description and remediation instructions.

The return value should be a dictionary, with two keys, "Success" and
"Failure".  The values for these keys should be a list of tags as strings, or a
list of dictionaries containing tags and other information for the audit (in
the case of ``verbose``).
