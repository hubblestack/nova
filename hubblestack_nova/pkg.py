# -*- encoding: utf-8 -*-
'''
A simple Nova plugin

:maintainer: HubbleStack
:maturity: 20160325
:platform: All
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'pkg' key, it will
use that data.

Sample YAML data, with inline comments:


pkg:
  # Must not be installed
  blacklist:
    # Unique ID for this set of audits
    telnet:
      data:
        # 'osfinger' grain, for multiplatform support
        CentOS Linux-6:
          # pkg name : tag
          - 'telnet': 'CIS-2.1.1'
        # Catch-all, if no osfinger match was found
        '*':
          # pkg name : tag
          - 'telnet': 'telnet-bad'
      # description/alert/trigger are currently ignored, but may be used in the future
      description: 'Telnet is evil'
      alert: email
      trigger: state
  # Must be installed, no version checking (yet)
  whitelist:
    rsh:
      data:
        CentOS Linux-6:
          - 'rsh': 'CIS-2.1.3'
          - 'rsh-server': 'CIS-2.1.4'
        CentOS Linux-7:
          - 'rsh': 'CIS-2.1.3'
          - 'rsh-server': 'CIS-2.1.4'
        '*':
          - 'rsh-client': 'CIS-5.1.2'
          - 'rsh-redone-client': 'CIS-5.1.2'
          - 'rsh-server': 'CIS-5.1.3'
          - 'rsh-redone-server': 'CIS-5.1.3'
      description: 'RSH is evil'
      alert: email
      trigger: state

'''
from __future__ import absolute_import
import logging

import fnmatch
import yaml
import os
import salt.utils

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
    Run the pkg audits contained in the YAML files processed by __virtual__
    '''
    ret = {'Success': [], 'Failure': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                name = tag_data['name']
                audittype = tag_data['type']

                # Blacklisted packages (must not be installed)
                if audittype == 'blacklist':
                    if __salt__['pkg.version'](name):
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)

                # Whitelisted packages (must be installed)
                elif audittype == 'whitelist':
                    if __salt__['pkg.version'](name):
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

    if not show_success:
        ret.pop('Success')
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
    Merge two yaml dicts together at the pkg:blacklist and pkg:whitelist level
    '''
    if 'pkg' not in ret:
        ret['pkg'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('pkg', {}):
            if topkey not in ret['pkg']:
                ret['pkg'][topkey] = {}
            ret['pkg'][topkey].update(data['pkg'][topkey])
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for toplist, toplevel in data.get('pkg', {}).iteritems():
        # pkg:blacklist
        for audit_id, audit_data in toplevel.iteritems():
            # pkg:blacklist:telnet
            tags_dict = audit_data.get('data', {})
            # pkg:blacklist:telnet:data
            tags = tags_dict.get(distro, tags_dict.get('*', []))
            # pkg:blacklist:telnet:data:Debian-8
            for item in tags:
                for name, tag in item.iteritems():
                    if tag not in ret:
                        ret[tag] = []
                    ret[tag].append({'name': name,
                                     'tag': tag,
                                     'type': toplist,
                                     'data': audit_data})
    return ret
