# win_gp.py
'''
Loader and primary interface for nova modules

:maintainer: HubbleStack
:maturity: 20160526
:platform: Windows
:requires: SaltStack
:TODO:
'''

from __future__ import absolute_import
import copy
import fnmatch
import logging
import salt.utils


log = logging.getLogger(__name__)
__virtualname__ = 'win_gp'


def __virtual__():
    if not salt.utils.is_windows():
        return False, 'This audit module only runs on windows'
    return True


def audit(data_list, tags, verbose=False):
    '''Runs auditpol on the local machine and audits the return data
    with the CIS yaml processed by __virtual__'''
    __data__ = {}
    __gpdata__ = _get_gp_templates()
    for data in data_list:
        _merge_yaml(__data__, data)
    __tags__ = _get_tags(__data__)
    log.trace('firewall audit __data__:')
    log.trace(__data__)
    log.trace('firewall audit __tags__:')
    log.trace(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                name = tag_data['name']
                audit_type = tag_data['type']
                match_output = tag_data['match_output'].lower()

                # Blacklisted audit (do not include)
                if 'blacklist' in audit_type:
                    if name not in __gpdata__:
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)

                # Whitelisted audit (must include)
                if 'whitelist' in audit_type:
                    if name in __gpdata__:
                        audit_value = True
                        secret = _translate_value_type(audit_value, tag_data['value_type'], match_output)
                        if secret:
                            ret['Success'].append(tag_data)
                        else:
                            ret['Failure'].append(tag_data)
                    else:
                        log.debug('When trying to audit the firewall section,'
                                  ' the yaml contained incorrect data for the key')

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
            if (tag, description, control_reason) not in tags_descriptions:
                tag_dict = {'description': description,
                            'control': control_reason}
                controlled.append({tag: description})
                control_reasons.add((tag, description, control_reason))

        ret['Controlled'] = controlled
        ret['Success'] = success
        ret['Failure'] = failure

    if not ret['Controlled']:
        ret.pop('Controlled')

    return ret


def _merge_yaml(ret, data):
    '''
    Merge two yaml dicts together at the secedit:blacklist and
    secedit:whitelist level
    '''
    if __virtualname__ not in ret:
        ret[__virtualname__] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get(__virtualname__, {}):
            if topkey not in ret[__virtualname__]:
                ret[__virtualname__][topkey] = []
            for key, val in data[__virtualname__][topkey].iteritems():
                ret[__virtualname__][topkey].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfullname')
    for toplist, toplevel in data.get(__virtualname__, {}).iteritems():
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
                # secedit:whitelist:PasswordComplexity:data:Windows 2012
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
                                          'module': 'win_auditpol',
                                          'type': toplist}
                        formatted_data.update(tag_data)
                        formatted_data.update(audit_data)
                        formatted_data.pop('data')
                        ret[tag].append(formatted_data)
    return ret


def _get_gp_templates():
    domain_check = ['system.get_domain_workgroup']()
    if 'workgroup' in domain_check:
        return False
    else:
        domain_check = domain_check['domain']
    list = ['cmd.run']('Get-ChildItem //domain_check/SYSVOL/domain_check | Format-List -Property '
                                'Name, SID', shell='powershell', python_shell=True)
    return list

def _translate_value_type(current, value, evaluator):
    if 'equal' in value:
        if current == evaluator:
            return True
        else:
            return False
