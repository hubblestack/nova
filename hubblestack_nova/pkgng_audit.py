# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for FreeBSD pkgng audit

:maintainer: HubbleStack
:maturity: 20160421
:platform: FreeBSD
:requires: SaltStack
'''
from __future__ import absolute_import
import logging

log = logging.getLogger(__name__)

__tags__ = None


def __virtual__():
    if 'FreeBSD' not in __grains__['os']:
        return False, 'This audit module only runs on FreeBSD'
    global __tags__
    __tags__ = ['freebsd-pkg-audit']
    return True


def audit(tags, verbose=False):
    '''
    Run the pkg.audit command
    '''
    ret = {'Success': [], 'Failure': []}

    salt_ret = __salt__['pkg.audit']()
    if '0 problem(s)' not in salt_ret:
        ret['Failure'].append(salt_ret)
    else:
        ret['Success'].append(salt_ret)

    return ret
