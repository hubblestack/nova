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

__tags__ = None
__data__ = None


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    global __tags__
    global __data__
    yamldir = os.path.dirname(__file__)
    if not yamldir:
        yamldir = '.'
    __data__ = _get_yaml(yamldir)
    __tags__ = _get_tags(__data__)
    return True


def audit(tags, verbose=False):
    '''
    Run the sysctl audits contained in the YAML files processed by __virtual__
    '''
    ret = {'Success': [], 'Failure': []}

    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            passed = True
            for tag_data in __tags__[tag]:
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
    if 'sysctl' not in ret:
        ret['sysctl'] = {}
    for topkey in data.get('sysctl', {}):
        if topkey not in ret['sysctl']:
            ret['sysctl'][topkey] = {}
        ret['sysctl'][topkey].update(data['sysctl'][topkey])
    return ret

def _get_yaml(dirname):
    ret = {}
    try:
        for yamlpath in os.listdir(dirname):
            if yamlpath.endswith('.yaml') or yamlpath.endswith('.yml'):
                with open(os.path.join(dirname, yamlpath)) as fh_:
                    data = yaml.safe_load(fh_)
                _merge_yaml(ret, data)
    except:
        return {}
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for audit_id, audit_data in data.get('sysctl', {}).iteritems():
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