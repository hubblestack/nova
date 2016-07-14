# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for FreeBSD pkgng audit

:maintainer: HubbleStack / cedwards
:maturity: 2016.7.0
:platform: FreeBSD
:requires: SaltStack

'''
from __future__ import absolute_import
import logging

log = logging.getLogger(__name__)


def __virtual__():
    if 'FreeBSD' not in __grains__['os']:
        return False, 'This audit module only runs on FreeBSD'
    return True


def audit(data_list, tags, verbose=False):
    '''
    Run the pkg.audit command
    '''
    ret = {'Success': [], 'Failure': []}

    __tags__ = []
    for data in data_list:
        if 'pkgng_audit' in data:
            __tags__ = ['pkgng_audit']
            break

    log.trace('pkgng audit __tags__:')
    log.trace(__tags__)

    if not __tags__:
        # No yaml data found, don't do any work
        return ret

    salt_ret = __salt__['pkg.audit']()
    if '0 problem(s)' not in salt_ret:
        ret['Failure'].append(salt_ret)
    else:
        ret['Success'].append(salt_ret)

    return ret
