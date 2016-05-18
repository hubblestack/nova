#secedit.py
# -*- encoding: utf-8 -*-
'''
Loader and primary interface for nova modules

:maintainer: HubbleStack
:maturity: 20160426
:platform: Windows
:requires: SaltStack
:TODO: Add support for Privilege Rights and Registry Values
'''
from __future__ import absolute_import
import logging

import fnmatch
import yaml
import os
import copy
import salt.utils

try:
    import uuid
    import codecs
    HAS_WINDOWS_MODULES = True
except ImportError:
    HAS_WINDOWS_MODULES = False

log = logging.getLogger(__name__)
__virtualname__ = 'secedit'

def __virtual__():
    if not salt.utils.is_windows() or not HAS_WINDOWS_MODULES:
        return False, 'This audit module only runs on Windows'
    return True


def audit(data_list, tags, verbose=False):
    '''
    Run the secedit audits contained in the YAML files processed by __virtual__
    '''
    __data__ = {}
    for data in data_list:
        _merge_yaml(__data__, data)
    __tags__ = _get_tags(__data__)
    log.trace('secedit audit __data__:')
    log.trace('__data__')
    log.trace('secedit audit __tags__:')
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
                    secedit_ret = _find_option_value_in_seceditfile(tag_data['name'])
                    if 'binary' in tag_data['value_type']:
                        secedit_ret = _binary_convert(secedit_ret)
                    elif 'multi' in tag_data['value_type']:
                        secedit_ret = _multi_convert(secedit_ret)
                    elif 'less' or 'more' or 'equal' in tag_data['value_type']:
                        secedit_ret = _get_operation(secedit_ret,
                                                     tag_data['value_type'],
                                                     tag_data['match_output'])

                    found = False
                    if secedit_ret:
                        found = True
                    if 'match_output' in tag_data and tag_data['match_output'] not in secedit_ret:
                        found = False

                    if found:
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)

                # Whitelisted packages (must be installed)
                elif audittype == 'whitelist':
                    secedit_ret = _find_option_value_in_seceditfile(tag_data['name'])
                    if 'binary' in tag_data['value_type']:
                        secedit_ret = _binary_convert(secedit_ret)
                    if 'multi' in tag_data['value_type']:
                        secedit_ret = _multi_convert(secedit_ret)
                    if tag_data['value_type'] in ['less', 'more', 'equal']:
                        secedit_ret = _get_operation(secedit_ret,
                                                     tag_data['value_type'],
                                                     tag_data['match_output'])
                    if 'priv' in tag_data['value_type']:
                        if 'no one' in tag_data['match_output']:
                            if secedit_ret is None or 'Not Defined' in secedit_ret:
                                secedit_ret = 'no one'

                    found = False
                    if secedit_ret:
                        found = True
                    if 'match_output' in tag_data and tag_data['match_output'] not in secedit_ret:
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


def _find_option_value_in_seceditfile(option):
    '''
    helper function to dump/parse a `secedit /export` file for a particular
    option
    '''
    try:
        _d = uuid.uuid4().hex
        _tfile = '{0}\\{1}'.format(__salt__['config.get']('cachedir'), 'salt-secedit-dump-{0}.txt'.format(_d))
        _ret = __salt__['cmd.run']('secedit /export /cfg {0}'.format(_tfile))
        if _ret:
            _reader = codecs.open(_tfile, 'r', encoding='utf-16')
            _secdata = _reader.readlines()
            _reader.close()
            _ret = __salt__['file.remove'](_tfile)
            for _line in _secdata:
                if _line.startswith(option):
                    return _line.split('=')[1].strip()
        else:
            return 'Not Defined'
    except:
        log.debug('error occurred while trying to get secedit data')
        return False, None


def _merge_yaml(ret, data):
    '''
    Merge two yaml dicts together at the secedit:blacklist and
    secedit:whitelist level
    '''
    if 'secedit' not in ret:
        ret['secedit'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('secedit', {}):
            if topkey not in ret['secedit']:
                ret['secedit'][topkey] = []
            for key, val in data['secedit'][topkey].iteritems():
                ret['secedit'][topkey].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfullname')
    for toplist, toplevel in data.get('secedit', {}).iteritems():
        # secedit:whitelist
        for audit_dict in toplevel:
            for audit_id, audit_data in audit_dict.iteritems():
                # secedit:whitelist:PasswordComplexity
                tags_dict = audit_data.get('data', {})
                # secedit:whitelist:PasswordComplexity:data
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
                # secedit:whitelist:PasswordComplexity:data:Debian-8
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
                                          'module': 'secedit',
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
        if len(val) <= 2:
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
