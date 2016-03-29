Nova
====

Nova plugins are designed specifically for auditing the compliance and security level
of an existing system. These plugins are designed to alow an administrator to
run security checks or even groups of security checks within their SaltStack
installation. This allows for real-time insight into the compliance level of
running systems.

Installation
============

Place `nova.py <_modules/nova.py>`_ in your ``_modules/`` directory in your Salt
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

There are three functions in the nova.py module. ``nova.sync`` will sync the
configured ``hubblestack_nova/`` directory to the minion. ``nova.load`` will
load the synced audit modules.  Finally, ``nova.audit`` will run the audits.

By default, ``nova.audit`` will call ``nova.load`` (which in turn calls
``nova.sync``) (in order to ensure that it is auditing with the most up-to-date
information. These operations are fairly fast, but if you want to avoid the
additional overhead, you can disable these behaviors via pillar (defaults are
shown, change to False to disable behaviors):

.. code-block:: yaml

    hubblestack.nova.autosync: True
    hubblestack.nova.autoload: True

``nova.audit`` takes two optional arguments. The first is a comma-separated
list of paths.  These paths can be files or directories. If a path is a
directory, all modules below that directory will be run. If it is a file, that
file will be run.

The second argument is a glob pattern, against which audit tags will be
matched. All audits have an accompanying tag. Nova modules are designed to take
this argument, compare it to each tag that module handles, and only run those
which match the argument (using ``fnmatch``).

``nova.audit`` will return a list of audits which were successful, and a list
of audits which failed.

Here are some example calls:

.. code-block:: bash

    # Run all modules and tags under salt://hubblestack_nova/
    salt '*' nova.audit

    # Run all modules and tags under salt://hubblestack_nova/foo/
    # Will also run salt://hubblestack_nova/foo.py if it exists
    salt '*' nova.audit modules=foo

    # Run all modules and tags under salt://hubblestack_nova/foo/ and
    # salt://hubblestack_nova/bar, but only run audits with tags starting
    # with "CIS"
    salt '*' nova.audit modules=foo,bar tags='CIS*'

Development
===========

If you're interested in contributing to this project this section outlines the
structure and requirements for Nova audit module development.

Anatomy of a Nova audit module
------------------------------

.. code-block:: python

    # -*- encoding: utf-8 -*-
    '''
    A simple Nova plugin

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

    __tags__ = []

    def __virtual__():
        if salt.utils.is_windows():
            return False, 'This audit module only runs on linux'
        global __tags__
        __tags__ = ['cis-foo', 'cis-bar', 'cis-baz']
        return True


    def audit(tags, verbose_failures=False):
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

The ``audit()`` function must take two arguments, ``tags`` and
``verbose_failures``. The ``tags`` argument is a glob expression for which tags
the audit function should run. It is the job of the audit module to compare the
``tags`` glob with all tags supported by this module and only run the audits
which match. The ``verbose_failures`` argument defines whether additional
information should be returned for failures, such as description and
remediation instructions.

The return value should be a dictionary, with two keys, "Success" and
"Failure".  The values for these keys should be a list of tags as strings, or a
list of dictionaries containing tags and other information for the audit (in
the case of ``verbose_failures``).
