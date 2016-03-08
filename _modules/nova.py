# -*- encoding: utf-8 -*-
'''
Loader and primary interface for nova modules

:maintainer: basepi
:maturity: 20160218
:platform: All
:requires: SaltStack

TODO: High level documentation

Configuration:
    - hubblestack.nova.dir
    - hubblestack.nova.saltenv
'''
from __future__ import absolute_import
import logging

log = logging.getLogger(__name__)

import imp
import os

from salt.exceptions import CommandExecutionError
from salt.loader import LazyLoader


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


def sync():
    '''
    Sync the nove audit modules from the saltstack fileserver.

    The modules should be stored in the salt fileserver. By default nova will
    search the base environment for a top level ``hubblestack-nova`` directory,
    unless otherwise specified via pillar or minion config
    (``hubblestack.nova.dir``)

    Modules will just be cached in the normal minion cachedir

    Returns the minion's path to the cached directory

    CLI Examples:

    .. code-block:: bash

        salt '*' nova.sync
        salt '*' nova.sync saltenv=hubble
    '''
    nova_dir = __salt__['config.get']('hubblestack.nova.dir', 'hubblestack-nova')
    saltenv = __salt__['config.get']('hubblestack.nova.saltenv', 'base')

    # Support optional salt:// in config
    if 'salt://' in nova_dir:
        path = nova_dir
        _, _, nova_dir = nova_dir.partition('salt://')
    else:
        path = 'salt://{0}'.format(nova_dir)

    # Sync the files
    cached = __salt__['cp.cache_dir'](path, saltenv=saltenv)

    if cached and isinstance(cached, list):
        # Success! Trim the paths
        cachedir = _hubble_dir()
        ret = [relative.partition(cachedir)[2] for relative in cached]
        return ret
    else:
        if isinstance(cached, list):
            # Nothing was found
            return cached
        else:
            # Something went wrong, there's likely a stacktrace in the output
            # of cache_dir
            raise CommandExecutionError('An error occurred while syncing: {0}'
                                        .format(cached))


def _hubble_dir():
    '''
    Generate the local minion directory to which nova modules are synced
    '''
    nova_dir = __salt__['config.get']('hubblestack.nova.dir', 'hubblestack-nova')
    saltenv = __salt__['config.get']('hubblestack.nova.saltenv', 'base')
    cachedir = os.path.join(__opts__.get('cachedir'),
                            'files',
                            saltenv,
                            nova_dir)
    return cachedir


def load(sync=False):
    '''
    Load the synced audit modules.

    sync
        Whether to do a fresh sync before loading the modules. Defaults to
        False
    '''
    if not os.path.isdir(_hubble_dir()):
        if sync:
            sync_ret = sync()
        else:
            return False, 'No synced nova modules found, and sync=False'


class NovaLazyLoader(LazyLoader):
    '''
    Leverage the SaltStack LazyLoader so we don't have to reimplement
    everything. Note that in general, we'll just call _load_all, so this
    will not actually be a lazy loader, but leveraging the existing code is
    worth it.
    '''

    def __init__(self):
        super(NovaLazyLoader, self).__init__([_hubble_dir()],
                                             opts=__opts__,
                                             tag='nova')

    def refresh_file_mapping():
        '''
        Override the default refresh_file_mapping to look for nova files
        recursively, rather than only in a top-level directory
        '''
        # map of suffix to description for imp
        self.suffix_map = {}
        suffix_order = []  # local list to determine precedence of extensions
        for (suffix, mode, kind) in imp.get_suffixes():
            self.suffix_map[suffix] = (suffix, mode, kind)
            suffix_order.append(suffix)

        # create mapping of filename (without suffix) to (path, suffix)
        self.file_mapping = {}

        for mod_dir in self.module_dirs:
            for dirname, _, files in os.walk(mod_dir):
                for filename in files:
                    try:
                        if filename.startswith('_'):
                            # skip private modules
                            # log messages omitted for obviousness
                            continue
                        _, ext = os.path.splitext(filename)
                        fpath = os.path.join(dirname, filename)
                        f_noext = os.path.splitext(fpath.partition(mod_dir)[-1])
                        # Nova only supports .py
                        if ext not in ['.py']:
                            continue
                        if f_noext in self.disabled:
                            log.trace(
                                'Skipping {0}, it is disabled by configuration'.format(
                                filename
                                )
                            )
                            continue

                        # if we don't have it, we want it
                        elif f_noext not in self.file_mapping:
                            self.file_mapping[f_noext] = (fpath, ext)
                        # if we do, we want it if we have a higher precidence ext
                        else:
                            curr_ext = self.file_mapping[f_noext][1]
                            #log.debug("****** curr_ext={0} ext={1} suffix_order={2}".format(curr_ext, ext, suffix_order))
                            if curr_ext and suffix_order.index(ext) < suffix_order.index(curr_ext):
                                self.file_mapping[f_noext] = (fpath, ext)
                    except OSError:
                        continue
