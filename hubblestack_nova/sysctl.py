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