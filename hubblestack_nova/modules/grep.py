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
              match_output: 'nodev'  # string to check for in output of grep command (optional)
              grep_args:  # extra args to grep
                - '-E'
                - '-i'
                - '-B2'
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


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    return True


def audit(data_list, tags, verbose=False):
    '''
    Run the grep audits contained in the YAML files processed by __virtual__
    '''
    __data__ = {}
    for data in data_list:
        _merge_yaml(__data__, data)
    __tags__ = _get_tags(__data__)

    log.trace('grep audit __data__:')
    log.trace(__data__)
    log.trace('grep audit __tags__:')
    log.trace(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                name = tag_data['name']
                audittype = tag_data['type']

                if 'pattern' not in tag_data:
                    log.error('No version found for grep audit {0}, file {1}'
                              .format(tag, name))
                    tag_data = copy.deepcopy(tag_data)
                    tag_data['error'] = 'No pattern found'.format(mod)
                    ret['Failure'].append(tag_data)
                    continue

                grep_args = tag_data.get('grep_args', [])
                if isinstance(grep_args, str):
                    grep_args = [grep_args]

                # Blacklisted packages (must not be installed)
                if audittype == 'blacklist':
                    grep_ret = __salt__['file.grep'](name,
                                                     tag_data['pattern'],
                                                     *grep_args).get('stdout')

                    found = False
                    if grep_ret:
                        found = True
                    if 'match_output' in tag_data and tag_data['match_output'] not in grep_ret:
                        found = False

                    if found:
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)

                # Whitelisted packages (must be installed)
                elif audittype == 'whitelist':
                    grep_ret = __salt__['file.grep'](name,
                                                     tag_data['pattern'],
                                                     *grep_args).get('stdout')

                    found = False
                    if grep_ret:
                        found = True
                    if 'match_output' in tag_data and tag_data['match_output'] not in grep_ret:
                        found = False

                    if found:
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)

    if not verbose:
        failure = []
        success = []
        controlled = []

        tags_descriptions = set()

        for tag_data in ret['Failure']:
            tag = tag_data['tag']
            description = tag_data.get('description')
            if (tag, description) not in tags_descriptions:
                failure.append({tag: description})
                tags_descriptions.add((tag, description))

        tags_descriptions = set()

        for tag_data in ret['Success']:
            tag = tag_data['tag']
            description = tag_data.get('description')
            if (tag, description) not in tags_descriptions:
                success.append({tag: description})
                tags_descriptions.add((tag, description))

        control_reasons = set()

        for tag_data in ret['Controlled']:
            tag = tag_data['tag']
            control_reason = tag_data.get('control', '')
            description = tag_data.get('description')
            if (tag, description, control_reason) not in control_reasons:
                tag_dict = {'description': description,
                        'control': control_reason}
                controlled.append({tag: tag_dict})
                control_reasons.add((tag, description, control_reason))

        ret['Controlled'] = controlled
        ret['Success'] = success
        ret['Failure'] = failure

    if not ret['Controlled']:
        ret.pop('Controlled')

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
                ret['grep'][topkey] = []
            for key, val in data['grep'][topkey].iteritems():
                ret['grep'][topkey].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for toplist, toplevel in data.get('grep', {}).iteritems():
        # grep:blacklist
        for audit_dict in toplevel:
            # grep:blacklist:0
            for audit_id, audit_data in audit_dict.iteritems():
                # grep:blacklist:0:telnet
                tags_dict = audit_data.get('data', {})
                # grep:blacklist:0:telnet:data
                tags = tags_dict.get(distro, tags_dict.get('*', []))
                # grep:blacklist:0:telnet:data:Debian-8
                if isinstance(tags, dict):
                    # malformed yaml, convert to list of dicts
                    tmp = []
                    for name, tag in tags.iteritems():
                        tmp.append({name: tag})
                    tags = tmp
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
