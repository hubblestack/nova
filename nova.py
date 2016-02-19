# -*- encoding: utf-8 -*-
'''
Loader and primary interface for nova modules

:maintainer: basepi
:maturity: 20160218
:platform: All
:requires: SaltStack

'''
from __future__ import absolute_import
import logging


def audit(modules=None, tag=None):
    '''
    Primary entry point for audit calls.

    modules
        Comma-separated list of modules/directories to search for audit
        modules. Directories are dot-separated, much in the same way as Salt
        states. For individual module names, leave the .py extension off.  If a
        given path resolves to a python file, it will be treated as a single
        module. Otherwise it will be treated as a directory. All modules found
        in a recursive search of the specified directories will be included in
        the audit.

    tags
        Glob pattern string for tags to include in the audit. This way you can
        give a directory, and tell the system to only run the `CIS*`-tagged
        audit modules, for example.
    '''
    pass


def sync(saltenv=None):
    '''
    Sync the nove audit modules from the saltstack fileserver.

    The modules should be stored in the salt fileserver. By default nova will
    search the base environment for a top level ``hubblestack-nova`` directory

    Modules will just be cached in the normal minion cachedir

    saltenv
        Override the environment in which we should search for the nova modules
    '''
    pass


def load(sync=False):
    '''
    Load the synced audit modules.

    sync
        Whether to do a fresh sync before loading the modules. Defaults to
        False
    '''
    pass
