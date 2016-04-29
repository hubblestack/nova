# -*- encoding: utf-8 -*-
'''
Loader and primary interface for nova modules

:maintainer: basepi
:maturity: 20160218
:platform: All
:requires: SaltStack

See README for documentation

Configuration:
    - hubblestack.nova.dir
    - hubblestack.nova.saltenv
    - hubblestack.nova.autoload
    - hubblestack.nova.autosync
'''
from __future__ import absolute_import
import logging

log = logging.getLogger(__name__)

import imp
import os
import sys
import six
import inspect
import yaml

import salt
import salt.utils
from salt.exceptions import CommandExecutionError
from salt.loader import LazyLoader

__nova__ = {}


def audit(configs='',
          tags='*',
          verbose=None,
          show_success=None,
          show_compliance=None):
    '''
    Primary entry point for audit calls.

    configs
        List (comma-separated or python list) of yaml configs/directories to
        search for audit data. Directories are dot-separated, much in the same
        way as Salt states. For individual config names, leave the .yaml
        extension off.  If a given path resolves to a python file, it will be
        treated as a single config. Otherwise it will be treated as a
        directory. All configs found in a recursive search of the specified
        directories will be included in the audit.

    tags
        Glob pattern string for tags to include in the audit. This way you can
        give a directory, and tell the system to only run the `CIS*`-tagged
        audits, for example.

    verbose
        Whether to show additional information about audits, including
        description, remediation instructions, etc. The data returned depends
        on the audit module. Defaults to False. Configurable via
        `hubblestack.nova.verbose` in minion config/pillar.

    show_success
        Whether to show successful audits in addition to failed audits.
        Defaults to True. Configurable via `hubblestack.nova.show_success` in
        minion config/pillar.

    show_compliance
        Whether to show compliance as a percentage (successful checks divided
        by total checks). Defaults to True. Configurable via
        `hubblestack.nova.show_compliance` in minion config/pillar.

    CLI Examples:

    .. code-block:: bash

        salt '*' hubble.audit foo
        salt '*' hubble.audit foo,bar tags='CIS*'
        salt '*' hubble.audit foo,bar.baz verbose=True
    '''
    if __salt__['config.get']('hubblestack.nova.autoload', True):
        load()
    if not __nova__:
        return False, 'No nova modules/data have been loaded.'

    if verbose is None:
        verbose = __salt__['config.get']('hubblestack.nova.verbose', False)
    if show_success is None:
        show_success = __salt__['config.get']('hubblestack.nova.show_success', True)
    if show_compliance is None:
        show_compliance = __salt__['config.get']('hubblestack.nova.show_compliance', True)

    if not isinstance(configs, list):
        # Convert string
        configs = configs.split(',')

    # Convert config list to paths, with leading slashes
    configs = [os.path.join(os.path.sep, os.path.join(*(con.split('.yaml')[0]).split('.')))
               for con in configs]

    results = {'Success': [], 'Failure': []}

    # Compile a list of audit data sets which we need to run
    to_run = set()
    for config in configs:
        for key in __nova__.__data__:
            if key.startswith(config):
                # Found a match, add the audit data to the set
                to_run.add(key)
    data_list = [__nova__.__data__[key] for key in to_run]
    log.trace('hubble.py data_list:')
    log.trace(data_list)
    # Run the audits
    # This is currently pretty brute-force -- we just run all the modules we
    # have available with the data list, so data will be processed multiple
    # times. However, for the scale we're working at this should be fine.
    # We can revisit if this ever becomes a big bottleneck
    for key, func in __nova__._dict.iteritems():
        try:
            ret = func(data_list, tags, verbose=verbose)
        except Exception as exc:
            if 'Errors' not in results:
                results['Errors'] = {}
            results['Errors'][key] = {'error': 'exception occurred',
                                      'data': str(exc)}
            continue
        else:
            if not isinstance(ret, dict):
                if 'Errors' not in results:
                    results['Errors'] = {}
                results['Errors'][key] = {'error': 'bad return type',
                                          'data': ret}
                continue

        # Compile the results
        results['Success'].extend(ret.get('Success', []))
        results['Failure'].extend(ret.get('Failure', []))

    total_audits = len(results['Success']) + len(results['Failure'])
    if show_compliance and total_audits:
        compliance = float(len(results['Success']))/total_audits
        compliance = int(compliance * 100)
        results['Compliance'] = '{0}%'.format(compliance)

    if not show_success:
        results.pop('Success')

    return results


def sync():
    '''
    Sync the nove audit modules from the saltstack fileserver.

    The modules should be stored in the salt fileserver. By default nova will
    search the base environment for a top level ``hubblestack_nova`` directory,
    unless otherwise specified via pillar or minion config
    (``hubblestack.nova.dir``)

    Modules will just be cached in the normal minion cachedir

    Returns the minion's path to the cached directory

    NOTE: This function will also clean out existing files at the cached
    location, as cp.cache_dir doesn't clean out old files

    CLI Examples:

    .. code-block:: bash

        salt '*' nova.sync
        salt '*' nova.sync saltenv=hubble
    '''
    log.debug('syncing nova modules')
    nova_dir = __salt__['config.get']('hubblestack.nova.dir', 'salt://hubblestack_nova')
    saltenv = __salt__['config.get']('hubblestack.nova.saltenv', 'base')

    # Support optional salt:// in config
    if 'salt://' in nova_dir:
        path = nova_dir
        _, _, nova_dir = nova_dir.partition('salt://')
    else:
        path = 'salt://{0}'.format(nova_dir)

    # Clean previously synced files
    __salt__['file.remove'](_hubble_dir())
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


def load():
    '''
    Load the synced audit modules.
    '''
    if __salt__['config.get']('hubblestack.nova.autosync', True):
        sync()
    if not os.path.isdir(_hubble_dir()):
        return False, 'No synced nova modules found'

    log.debug('loading nova modules')

    global __nova__
    __nova__ = NovaLazyLoader()

    ret = {'loaded': __nova__._dict.keys(),
           'missing': __nova__.missing_modules,
           'data': __nova__.__data__.keys(),
           'missing_data': __nova__.__missing_data__}
    return ret


def _hubble_dir():
    '''
    Generate the local minion directory to which nova modules are synced
    '''
    nova_dir = __salt__['config.get']('hubblestack.nova.dir', 'hubblestack_nova')
    # Support optional salt:// in config
    if 'salt://' in nova_dir:
        _, _, nova_dir = nova_dir.partition('salt://')
    saltenv = __salt__['config.get']('hubblestack.nova.saltenv', 'base')
    cachedir = os.path.join(__opts__.get('cachedir'),
                            'files',
                            saltenv,
                            nova_dir)
    return cachedir


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
        self.__data__ = {}
        self.__missing_data__ = {}
        self._load_all()

    def refresh_file_mapping(self):
        '''
        Override the default refresh_file_mapping to look for nova files
        recursively, rather than only in a top-level directory
        '''
        # map of suffix to description for imp
        self.suffix_map = {}
        suffix_order = []  # local list to determine precedence of extensions
        suffix_order.append('.yaml')
        for (suffix, mode, kind) in imp.get_suffixes():
            self.suffix_map[suffix] = (suffix, mode, kind)
            suffix_order.append(suffix)

        # create mapping of filename (without suffix) to (path, suffix)
        self.file_mapping = {}

        for mod_dir in self.module_dirs:
            for dirname, dirs, files in os.walk(mod_dir):
                if '.git' in dirs:
                    dirs.remove('.git')
                for filename in files:
                    try:
                        if filename.startswith('_'):
                            # skip private modules
                            # log messages omitted for obviousness
                            continue
                        _, ext = os.path.splitext(filename)
                        fpath = os.path.join(dirname, filename)
                        f_withext = fpath.partition(mod_dir)[-1]
                        # Nova only supports .py and .yaml
                        if ext not in ['.py', '.yaml']:
                            continue
                        if f_withext in self.disabled:
                            log.trace(
                                'Skipping {0}, it is disabled by configuration'.format(
                                filename
                                )
                            )
                            continue

                        # if we don't have it, we want it
                        elif f_withext not in self.file_mapping:
                            self.file_mapping[f_withext] = (fpath, ext)
                        # if we do, we want it if we have a higher precidence ext
                        else:
                            curr_ext = self.file_mapping[f_withext][1]
                            #log.debug("****** curr_ext={0} ext={1} suffix_order={2}".format(curr_ext, ext, suffix_order))
                            if curr_ext and suffix_order.index(ext) < suffix_order.index(curr_ext):
                                self.file_mapping[f_withext] = (fpath, ext)
                    except OSError:
                        continue

    def _load_module(self, name):
        '''
        Override the module load code
        '''
        mod = None
        fpath, suffix = self.file_mapping[name]
        self.loaded_files.add(name)
        if suffix == '.yaml':
            try:
                with open(fpath) as fh_:
                    data = yaml.safe_load(fh_)
            except Exception as exc:
                self.__missing_data__[name] = str(exc)
                return False

            self.__data__[name] = data
            return True
        try:
            sys.path.append(os.path.dirname(fpath))
            desc = self.suffix_map[suffix]
            # if it is a directory, we don't open a file
            with salt.utils.fopen(fpath, desc[1]) as fn_:
                mod = imp.load_module(
                    '{0}.{1}.{2}.{3}'.format(
                        self.loaded_base_name,
                        self.mod_type_check(fpath),
                        self.tag,
                        name
                    ), fn_, fpath, desc)

        except IOError:
            raise
        except ImportError as error:
            log.debug(
                'Failed to import {0} {1}:\n'.format(
                    self.tag, name
                ),
                exc_info=True
            )
            self.missing_modules[name] = str(error)
            return False
        except Exception as error:
            log.error(
                'Failed to import {0} {1}, this is due most likely to a '
                'syntax error:\n'.format(
                    self.tag, name
                ),
                exc_info=True
            )
            self.missing_modules[name] = str(error)
            return False
        except SystemExit as error:
            log.error(
                'Failed to import {0} {1} as the module called exit()\n'.format(
                    self.tag, name
                ),
                exc_info=True
            )
            self.missing_modules[name] = str(error)
            return False
        finally:
            sys.path.pop()

        mod.__grains__ = __grains__
        mod.__pillar__ = __pillar__
        mod.__opts__ = __opts__
        mod.__salt__ = __salt__

        # pack whatever other globals we were asked to
        for p_name, p_value in six.iteritems(self.pack):
            setattr(mod, p_name, p_value)

        module_name = name

        # Call a module's initialization method if it exists
        module_init = getattr(mod, '__init__', None)
        if inspect.isfunction(module_init):
            try:
                module_init(self.opts)
            except TypeError as e:
                log.error(e)
            except Exception:
                err_string = '__init__ failed'
                log.debug(
                    'Error loading {0}.{1}: {2}'.format(
                        self.tag,
                        module_name,
                        err_string),
                    exc_info=True)
                self.missing_modules[name] = err_string
                return False

        # if virtual modules are enabled, we need to look for the
        # __virtual__() function inside that module and run it.
        if self.virtual_enable:
            (virtual_ret, module_name, virtual_err) = self.process_virtual(
                mod,
                module_name,
            )
            if virtual_err is not None:
                log.debug('Error loading {0}.{1}: {2}'.format(self.tag,
                                                              module_name,
                                                              virtual_err,
                                                              ))

            # if process_virtual returned a non-True value then we are
            # supposed to not process this module
            if virtual_ret is not True:
                # If a module has information about why it could not be loaded, record it
                self.missing_modules[name] = virtual_err
                return False

        # If this is a proxy minion then MOST modules cannot work. Therefore, require that
        # any module that does work with salt-proxy-minion define __proxyenabled__ as a list
        # containing the names of the proxy types that the module supports.
        #
        # Render modules and state modules are OK though
        if 'proxy' in self.opts:
            if self.tag in ['grains', 'proxy']:
                if not hasattr(mod, '__proxyenabled__') or \
                        (self.opts['proxy']['proxytype'] not in mod.__proxyenabled__ and
                            '*' not in mod.__proxyenabled__):
                    err_string = 'not a proxy_minion enabled module'
                    self.missing_modules[name] = err_string
                    return False

        if getattr(mod, '__load__', False) is not False:
            log.info(
                'The functions from module {0!r} are being loaded from the '
                'provided __load__ attribute'.format(
                    module_name
                )
            )
        mod_dict = salt.utils.odict.OrderedDict()
        # In nova we only care about the audit() function, and we want to
        # store it with directory structure in the name.
        for attr in getattr(mod, '__load__', dir(mod)):
            if attr != 'audit':
                continue
            func = getattr(mod, attr)
            # Save many references for lookups
            self._dict[name] = func
            mod_dict[name] = func

        self.loaded_modules[name] = mod_dict
        return True
