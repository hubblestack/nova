# -*- encoding: utf-8 -*-
'''
pkg auditing
'''

import yaml

DISTRO = 'CentOS Linux-7'

__virtualname__ = 'hubble.pkg'

def __virtual__():
    '''
    Load the module
    '''
    return True


def audit():

    ret = {}

    with open('/srv/salt/_nova/nova-pkg.yaml') as fh_:
        audit = yaml.safe_load(fh_)
    
    for k,v in audit['pkg']['blacklist'].iteritems():
        if DISTRO in v['data']:
            for benchmark in v['data'][DISTRO]:
                for item in benchmark.items():
                    check = item[0]
                    tags = item[1]
                    ret[check] = __salt__['pkg.version'](check)
                    if ret[check]:
                        ret[check] = 'Failed ' + tags
                    else:
                        ret[check] = 'Passed ' + tags
        else:
            print 'Check not supported'

    return ret
