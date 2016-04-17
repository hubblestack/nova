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
            for tag_data in __tags__[tag]:
                name = tag_data['name']
                match_output = tag_data['match_output']

                salt_ret = __salt__['sysctl.get'](name)
                if not salt_ret:
                    ret['Failure'].append(tag_data)
                if str(salt_ret).startswith('error'):
                    ret['Failure'].append(tag_data)
                if str(salt_ret) == str(match_output):
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