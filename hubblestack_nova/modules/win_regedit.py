#regedit.py
# -*- encoding: utf-8 -*-
'''
Loader and primary interface for nova modules

:maintainer: HubbleStack
:maturity: 20160505
:platform: Windows
:requires: SaltStack
:TODO:
'''
from __future__ import absolute_import
import logging

import fnmatch
import copy
import salt.utils

try:
    HAS_WINDOWS_MODULES = True
except ImportError:
    HAS_WINDOWS_MODULES = False

log = logging.getLogger(__name__)
__virtualname__ = 'regedit'


def __virtual__():
    if not salt.utils.is_windows() or not HAS_WINDOWS_MODULES:
        return False, 'This audit module only runs on Windows'
    return True


def audit(data_list, tags, verbose=False):
    '''
    Run the regedit audits contained in the YAML files processed by __virtual__
    '''
    __data__ = {}
    for data in data_list:
        _merge_yaml(__data__, data)
    __tags__ = _get_tags(__data__)
    log.trace('regedit audit __data__:')
    log.trace('__data__')
    log.trace('regedit audit __tags__:')
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

                # Blacklisted audit (do not include)
                if audittype == 'blacklist':
                    #put blacklist stuff here
                    found = False
                    if regedit_ret:
                        found = True
                    if 'match_output' in tag_data and tag_data['match_output'] not in regedit_ret:
                        found = False

                    if found:
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)

                # Whitelisted packages (must be installed)
                elif audittype == 'whitelist':
                    regedit_ret = _find_option_value_in_reg(tag_data['hive'],
                                                            tag_data['reg_key'],
                                                            tag_data['name'])
                    if 'binary' in tag_data['value_type']:
                        regedit_ret = _binary_convert(regedit_ret)
                    if 'multi' in tag_data['value_type']:
                        regedit_ret = _multi_convert(regedit_ret)
                    if tag_data['value_type'] in ['less', 'more', 'equal']:
                        regedit_ret = _get_operation(regedit_ret,
                                                     tag_data['value_type'],
                                                     tag_data['match_output'])

                    found = False
                    if regedit_ret:
                        found = True
                    if 'match_output' in tag_data and tag_data['match_output'] not in regedit_ret:
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


def _find_option_value_in_reg(reg_hive, reg_key, reg_value):
    '''
    helper function to retrieve Windows registry settings for a particular
    option
    '''
    reg_result = __salt__['reg.read_value'](reg_hive, reg_key, reg_value)
    return reg_result['vdata']


def _merge_yaml(ret, data):
    '''
    Merge two yaml dicts together at the regedit:blacklist and
    regedit:whitelist level
    '''
    if 'regedit' not in ret:
        ret['regedit'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('regedit', {}):
            if topkey not in ret['regedit']:
                ret['regedit'][topkey] = []
            for key, val in data['regedit'][topkey].iteritems():
                ret['regedit'][topkey].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfullname')
    for toplist, toplevel in data.get('regedit', {}).iteritems():
        # regedit:whitelist
        for audit_dict in toplevel:
            for audit_id, audit_data in audit_dict.iteritems():
                # regedit:whitelist:PasswordComplexity
                tags_dict = audit_data.get('data', {})
                # regedit:whitelist:PasswordComplexity:data
                tags = None
                for osfinger in tags_dict:
                    if osfinger == '*':
                        continue
                    osfinger_list = [finger.strip() for finger in osfinger.split(',')]
                    for osfinger_glob in osfinger_list:
                        if fnmatch.fnmatch(distro, osfinger_glob):
                            tags = tags_dict.get(osfinger)
                            break
                    if tags is not None:
                        break
                # If we didn't find a match, check for a '*'
                if tags is None:
                    tags = tags_dict.get('*', [])
                # regedit:whitelist:PasswordComplexity:data:Debian-8
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
                                          'module': 'regedit',
                                          'type': toplist}
                        formatted_data.update(tag_data)
                        formatted_data.update(audit_data)
                        formatted_data.pop('data')
                        ret[tag].append(formatted_data)
    return ret


def _binary_convert(val, **kwargs):
    '''
    converts a reg dword 1/0 value to the strings enable/disable
    '''
    if val is not None:
        if val == 1 or val == "1":
            return 'Enabled'
        if val == 0 or val == "0":
            return 'Disabled'
    else:
        return 'Not Defined'


def _multi_convert(val, **kwargs):
    '''
    converts an audit setting # (0, 1, 2, 3) to the string text
    '''

    if val is not None:
        if val == 0 or val == "0":
            return 'No auditing'
        elif val == 1 or val == "1":
            return 'Success'
        elif val == 2 or val == "2":
            return 'Failure'
        elif val == 3 or val == "3":
            return 'Success, Failure'
        else:
            return 'Invalid Auditing Value'
    else:
        return 'Not Defined'


def _get_operation(current, operator, evaluator):
    if 'less' in operator:
        if current <= evaluator:
            return evaluator
    elif 'more' in operator:
        if current >= evaluator:
            return evaluator
    elif 'equal' in operator:
        if current == operator:
            return evaluator
    return False
