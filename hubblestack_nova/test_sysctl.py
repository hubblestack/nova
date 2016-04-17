import yaml
import os
from pprint import pprint


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


if __name__ == "__main__":
    pprint(_get_yaml('.'))