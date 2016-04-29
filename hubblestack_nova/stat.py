# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for using stat to verify settings over files

:maintainer: HubbleStack
:maturity: 20160417
:platform: CentOS-6 and CentOS-7
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'stat' key, it will
use that data.

Sample YAML data, with inline comments:


stat:
  grub_conf_own:  # unique ID
    data:
      'CentOS-6':  # osfinger grain
        - '/etc/grub.conf':  # filename
            tag: 'CIS-1.5.1'  #audit tag
            user: 'root'  #expected owner
            uid: 0        #expected uid owner
            group: 'root'  #expected group owner
            gid: 0          #expected gid owner
      'CentOS Linux-7':
        - '/etc/grub2/grub.cfg':
            tag: 'CIS-1.5.1'
            user: 'root'
            uid: 0
            group: 'root'
            gid: 0
    # The rest of these attributes are optional, and currently not used
    description: 'Grub must be owned by root'
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
    Run the stat audits contained in the YAML files processed by __virtual__
    '''
    __data__ = {}
    for data in data_list:
        _merge_yaml(__data__, data)
    __tags__ = _get_tags(__data__)

    log.trace('service audit __data__:')
    log.trace(__data__)
    log.trace('service audit __tags__:')
    log.trace(__tags__)

    ret = {'Success': [], 'Failure': []}

    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                name = tag_data['name']
                expected = {}
                for e in ['mode', 'user', 'uid', 'group', 'gid']:
                    if e in tag_data:
                        expected[e] = tag_data[e]

                #getting the stats using salt
                salt_ret = __salt__['file.stats'](name)
                if not salt_ret:
                    if None in expected.values():
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)
                    continue

                passed = True
                for e in expected.keys():
                    r = salt_ret[e]
                    if e == 'mode' and r != '0':
                        r = r[1:]
                    if str(expected[e]) != str(r):
                        passed = False

                if passed:
                    ret['Success'].append(tag_data)
                else:
                    ret['Failure'].append(tag_data)

    if not verbose:
        failure = []
        success = []

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

        ret['Success'] = success
        ret['Failure'] = failure

    return ret



def _merge_yaml(ret, data):
    '''
    Merge two yaml dicts together
    '''
    if 'stat' not in ret:
        ret['stat'] = []
    for key, val in data.get('stat', {}).iteritems():
        ret['stat'].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for audit_dict in data.get('stat', []):
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
                                      'module': 'stat'}
                    formatted_data.update(tag_data)
                    formatted_data.update(audit_data)
                    formatted_data.pop('data')
                    ret[tag].append(formatted_data)
    return ret
