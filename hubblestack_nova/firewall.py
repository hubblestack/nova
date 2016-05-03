from __future__ import absolute_import
import logging

import fnmatch
import copy
import salt.utils

from distutils.version import LooseVersion

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

    ret = {'Success': [], 'Failure': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
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
