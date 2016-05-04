# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for using iptables to verify firewall rules

:maintainer: HubbleStack
:maturity: 20160503
:platform: Linux
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'firewall' key, it will
use that data.

Sample YAML data, with inline comments:


firewall:
  whitelist:    # whitelist or blacklist

    ssh:    # unique id
      data:
        tag: 'FIREWALL-TCP-22'  # audit tag
        table: 'filter' #iptables table to check
        chain: INPUT    # INPUT / OUTPUT / FORWARD
        rule: '-p tcp --dport 22 -m state --state ESTABLISHED,RELATED -j ACCEPT'    # rule to check
        family: 'ipv4'  # iptables family
      description: 'ssh iptables rule check' # description of the check
      # The rest of these attributes are optional, and currently not used
      alert: email
      trigger: state
'''

from __future__ import absolute_import
import logging

import fnmatch
import copy
import salt.utils

log = logging.getLogger(__name__)

__tags__ = None
__data__ = None


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    if not salt.utils.which('iptables'):
        return (False, 'The iptables execution module cannot be loaded: iptables not installed.')
    return True


def audit(data_list, tags, verbose=False):
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
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                rule = tag_data['rule']
                table = tag_data['table']
                chain = tag_data['chain']
                family = tag_data['family']

                salt_ret = __salt__['iptables.check'](table=table, chain=chain, rule=rule, family=family)

                if salt_ret not in (True, False):
                    log.error(salt_ret)
                    passed = False
                else:
                    passed = salt_ret

                if tag_data['type'] == 'blacklist':
                    passed = not passed

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
            if (tag, control_reason) not in control_reasons:
                controlled.append({tag: control_reason})
                control_reasons.add((tag, control_reason))

        ret['Controlled'] = controlled
        ret['Success'] = success
        ret['Failure'] = failure

    return ret


def _merge_yaml(ret, data):
    '''
    Merge two yaml dicts together at the pkg:blacklist and pkg:whitelist level
    '''
    if 'firewall' not in ret:
        ret['firewall'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('firewall', {}):
            if topkey not in ret['firewall']:
                ret['firewall'][topkey] = []
            for key, val in data['firewall'][topkey].iteritems():
                ret['firewall'][topkey].append({key: val})
    return ret


def _get_tags(data):
    ret = {}
    for toplist, toplevel in data.get('firewall', {}).iteritems():
        for audit_dict in toplevel:
            for audit_id, audit_data in audit_dict.iteritems():
                tags_dict = audit_data.get('data', {})
                tag = tags_dict.pop('tag')
                if tag not in ret:
                    ret[tag] = []
                formatted_data = copy.deepcopy(tags_dict)
                formatted_data['type'] = toplist
                formatted_data['tag'] = tag
                formatted_data['module'] = 'firewall'
                formatted_data.update(audit_data)
                formatted_data.pop('data')
                ret[tag].append(formatted_data)
    return ret
