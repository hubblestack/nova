Nova
====

Nova plugins are designed specifically for auditing the compliance and security level
of an existing system. These plugins are designed to alow an administrator to
run security checks or even groups of security checks within their SaltStack
installation. This allows for real-time insight into the compliance level of
running systems.

Installation
============


Development
===========

If you're interested in contributing to this project this section outlines the
structure and requirements for Nova plugin development.

Anatomy of a Nova plugin
------------------------

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


    def audit(tags):
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

The ``audit()`` function must take a single argument, ``tags``, which is a glob
expression for which tags the audit function should run. It is the job of the
audit module to compare the ``tags`` glob with all tags supported by this
module and only run the audits which match.

The return value should be a dictionary, with two keys, "Success" and
"Failure".  The values for these keys should be a list of tags as strings, or a
list of dictionaries containing tags and other information for the audit.
