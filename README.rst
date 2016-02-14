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

    def virtual():
        '''
        Compatibility Test
        '''
        if 'RedHat' in __salt__['grains.get']('os_family'):
            return True
        return False


All Nova plugins require a ``__virtual__()`` function to determine module compatibility.


.. code-block:: python

    def audit():
        '''
        Security check; return True or False
        '''
        ret = _grep('"/dev/shm"', '/etc/fstab')
        if 'noexec' in ret:
            return True
        else:
            return False

All Nova plugins require an ``audit()`` function, which will auto-execute when
called through Nova. return ``True`` for pass and return ``False`` for fail.
