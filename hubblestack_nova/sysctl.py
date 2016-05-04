# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for using sysctl to verify sysctl parameter

:maintainer: HubbleStack
:maturity: 20160417
:platform: CentOS-6 and CentOS-7
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'sysctl' key, it will
use that data.

Sample YAML data, with inline comments:

sysctl:
  randomize_va_space:  # unique ID
    data:
      'CentOS-6':  #osfinger grain
        - 'kernel.randomize_va_space':  #sysctl param to check
            tag: 'CIS-1.6.3'  #audit tag
            match_output: '2'   #expected value of the checked parameter
      'CentOS-7':
        - 'kernel.randomize_va_space':
            tag: 'CIS-1.6.2'
            match_output: '2'
    description: 'Enable Randomized Virtual Memory Region Placement (Scored)'
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
    Run the sysctl audits contained in the YAML files processed by __virtual__
    '''
    __data__ = {}
    for data in data_list:
        _merge_yaml(__data__, data)
    __tags__ = _get_tags(__data__)

    log.trace('service audit __data__:')
    log.trace(__data__)
    log.trace('service audit __tags__:')
    log.trace(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}

    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            passed = True
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                name = tag_data['name']
                match_output = tag_data['match_output']

                salt_ret = __salt__['sysctl.get'](name)
                if not salt_ret:
                    passed = False
                if str(salt_ret).startswith('error'):
                    passed = False
                if str(salt_ret) != str(match_output):
                    passed = False
            if passed:
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

    if len(ret['Controlled']) == 0: ret.pop('Controlled')

    return ret


def _merge_yaml(ret, data):
    '''
    Merge two yaml dicts together
    '''
    if 'sysctl' not in ret:
        ret['sysctl'] = []
    for key, val in data.get('sysctl', {}).iteritems():
        ret['sysctl'].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for audit_dict in data.get('sysctl', []):
        for audit_id, audit_data in audit_dict.iteritems():
            tags_dict = audit_data.get('data', {})
            tags = tags_dict.get(distro, [])
            if isinstance(tags, dict):
                # malformed yaml, convert to list of dicts
                tmp = []
                for name, tag in tags.iteritems():
                    tmp.append({name: tag})
                tags = tmp
            for item in tags:
                for name, tag in item.iteritems():
                    if isinstance(tag, dict):
                        tag_data = copy.deepcopy(tag)
                        tag = tag_data.pop('tag')
                    if tag not in ret:
                        ret[tag] = []
                    formatted_data = {'name': name,
                                      'tag': tag,
                                      'module': 'sysctl'}
                    formatted_data.update(tag_data)
                    formatted_data.update(audit_data)
                    formatted_data.pop('data')
                    ret[tag].append(formatted_data)
    return ret
