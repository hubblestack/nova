from __future__ import absolute_import
import logging

import fnmatch
import copy

log = logging.getLogger(__name__)

__tags__ = None
__data__ = None

def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    if not salt.utils.which('iptables'):
        return (False, 'The iptables execution module cannot be loaded: iptables not installed.')
    return True


def _merge_yaml(ret, data):
    if 'openssl' not in ret:
        ret['openssl'] = {}
    for key, val in data.get('openssl', {}).iteritems():
        ret['openssl'].append({key: val})
    return ret


def _get_tags(data):
    ret = {}
    for audit_dict in data.get('openssl', {}):
        pprint(audit_dict)
        for audit_id, audit_data in audit_dict.iteritems():
            tags_dict = audit_data.get('data', {})
            tag = tags_dict.pop('tag')
            if tag not in ret:
                ret[tag] = []
            formatted_data = copy.deepcopy(tags_dict)
            formatted_data['tag'] = tag
            formatted_data['module'] = 'openssl'
            formatted_data.update(audit_data)
            formatted_data.pop('data')
            ret[tag].append(formatted_data)
    return ret
