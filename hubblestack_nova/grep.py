# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for using grep to verify settings in files

Supports both blacklisting and whitelisting patterns. Blacklisted patterns must
not be found in the specified file. Whitelisted patterns must be found in the
specified file.

:maintainer: HubbleStack
:maturity: 20160405
:platform: All
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'grep' key, it will
use that data.

Sample YAML data, with inline comments:


grep:
  whitelist: # or blacklist
    fstab_tmp_partition:  # unique ID
      data:
        CentOS Linux-6:  # osfinger grain
          - '/etc/fstab':  # filename
              tag: 'CIS-1.1.1'  # audit tag
              pattern: '/tmp'  # grep pattern
        '*':  # wildcard, will be run if no direct osfinger match
          - '/etc/fstab':
              tag: 'CIS-1.1.1'
              pattern: '/tmp'
      # The rest of these attributes are optional, and currently not used
      description: |
        The /tmp directory is intended to be world-writable, which presents a risk
        of resource exhaustion if it is not bound to a separate partition.
      alert: email
      trigger: state
'''
from __future__ import absolute_import
import logging

import fnmatch
import yaml
import os
import copy
import salt.utils

from distutils.version import LooseVersion

log = logging.getLogger(__name__)

__tags__ = None
__data__ = None


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    global __tags__
    global __data__
    yamldir = os.path.dirname(__file__)
    __data__ = _get_yaml(yamldir)
    __tags__ = _get_tags(__data__)
    return True


def audit(tags, verbose=False):
    '''
    Run the grep audits contained in the YAML files processed by __virtual__
    '''
    ret = {'Success': [], 'Failure': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                name = tag_data['name']
                audittype = tag_data['type']

                if 'pattern' not in tag_data:
                    log.error('No version found for grep audit {0}, file {1}'
                              .format(tag, name))
                    tag_data = copy.deepcopy(tag_data)
                    tag_data['error'] = 'No pattern found'.format(mod)
                    ret['Failure'].append(tag_data)
                    continue

                # Blacklisted packages (must not be installed)
                if audittype == 'blacklist':
                    if __salt__['file.grep'](name, tag_data['pattern']).get('stdout'):
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)

                # Whitelisted packages (must be installed)
                elif audittype == 'whitelist':
                    if __salt__['file.grep'](name, tag_data['pattern']).get('stdout'):
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)

    if not verbose:
        failure = set()
        success = set()

        for tag_data in ret['Failure']:
            tag = tag_data['tag']
            failure.add(tag)

        for tag_data in ret['Success']:
            tag = tag_data['tag']
            if tag not in failure:
                success.add(tag)

        ret['Success'] = list(success)
        ret['Failure'] = list(failure)

    return ret


def _get_yaml(dirname):
    '''
    Iterate over the current directory for all yaml files, read them in,
    merge them, and return the __data__
    '''
    ret = {}
    try:
        for yamlpath in os.listdir(dirname):
            if yamlpath.endswith('.yaml'):
                with open(os.path.join(dirname, yamlpath)) as fh_:
                    data = yaml.safe_load(fh_)
                _merge_yaml(ret, data)
    except:
        return {}
    return ret


def _merge_yaml(ret, data):
    '''
    Merge two yaml dicts together at the grep:blacklist and grep:whitelist level
    '''
    if 'grep' not in ret:
        ret['grep'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('grep', {}):
            if topkey not in ret['grep']:
                ret['grep'][topkey] = {}
            ret['grep'][topkey].update(data['grep'][topkey])
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for toplist, toplevel in data.get('grep', {}).iteritems():
        # grep:blacklist
        for audit_id, audit_data in toplevel.iteritems():
            # grep:blacklist:telnet
            tags_dict = audit_data.get('data', {})
            # grep:blacklist:telnet:data
            tags = tags_dict.get(distro, tags_dict.get('*', []))
            # grep:blacklist:telnet:data:Debian-8
            for item in tags:
                for name, tag in item.iteritems():
                    tag_data = {}
                    # Whitelist could have a dictionary, not a string
                    if isinstance(tag, dict):
                        tag_data = copy.deepcopy(tag)
                        tag = tag_data.pop('tag')
                    if tag not in ret:
                        ret[tag] = []
                    formatted_data = {'name': name,
                                      'tag': tag,
                                      'module': 'grep',
                                      'type': toplist}
                    formatted_data.update(tag_data)
                    formatted_data.update(audit_data)
                    formatted_data.pop('data')
                    ret[tag].append(formatted_data)
    return ret
