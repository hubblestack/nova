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
    Run the grep audits contained in the YAML files processed by __virtual__
    '''
    pass


def _merge_yaml(ret, data):
    '''
    Merge two yaml dicts together
    '''
    if 'stat' not in ret:
        ret['stat'] = {}
    for topkey in data.get('stat', {}):
        if topkey not in ret['stat']:
            ret['stat'][topkey] = {}
        ret['stat'][topkey].update(data['stat'][topkey])
    return ret


def _get_yaml(dirname):
    '''
    Iterate over the current directory for all yaml files, read them in,
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


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for audit_id, audit_data in data.get('stat', {}).iteritems():
        tags_dict = audit_data.get('data', {})
        tags = tags_dict.get(distro, tags_dict.get('*', []))
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
