from __future__ import absolute_import
import logging

import fnmatch
import yaml
import os
import salt.utils

log = logging.getLogger(__name__)

__tags__ = None
__data__ = None


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    global __tags__
    global __data__
    yamldir = os.path.dirname(__file__)
    __data__ = _get_yaml(yamldir)
    __tags__ = _get_tags(__data__)
    return True


def audit(tags):
    ret = {'Success': [], 'Failure': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            name = __tags__[tag]['name']
            audittype = __tags__[tag]['type']
            if audittype == 'blacklist':
                if __salt__['pkg.version']:
                    ret['Failure'].append(tag)
                else:
                    ret['Success'].append(tag)
            elif audittype == 'whitelist':
                if __salt__['pkg.version']:
                    ret['Success'].append(tag)
                else:
                    ret['Failure'].append(tag)
    return ret


def _get_yaml(dirname):
    '''
    Iterate over teh current directory for all yaml files, read them in,
    merge them, and return the __data__
    '''
    ret = {}
    try:
        for yamlpath in os.listdir(dirname):
            if yamlpath.endswith('.yaml'):
                with open(os.path.join(dirname, yamlpath)) as fh_:
                    data = yaml.safe_load(fh_)
                _merge_yaml(ret, data)
    except:
        return {}
    return ret


def _merge_yaml(ret, data):
    '''
    Merge two yaml dicts together at the pkg:blacklist and pkg:whitelist level
    '''
    if 'pkg' not in ret:
        ret['pkg'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('pkg', {}):
            if topkey not in ret['pkg']:
                ret['pkg'][topkey] = {}
            ret['pkg'][topkey].update(data['pkg'][topkey])
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for toplist, toplevel in data.get('pkg', {}).iteritems():
        # pkg:blacklist
        for audit_id, audit_data in toplevel.iteritems():
            # pkg:blacklist:telnet
            tags_dict = audit_data.get('data', {})
            # pkg:blacklist:telnet:data
            tags = tags_dict.get(distro, tags_dict.get('*', []))
            # pkg:blacklist:telnet:data:Debian-8
            for item in tags:
                for name, tag in item.iteritems():
                    ret[tag] = {'name': name,
                                'tag': tag,
                                'type': toplist,
                                'data': audit_data}
    return ret
