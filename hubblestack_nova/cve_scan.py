# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for FreeBSD pkgng audit

:maintainer: HubbleStack
:maturity: 20160428
:platform: Unix
:requires: SaltStack
'''
from __future__ import absolute_import
import salt.utils
import logging

log = logging.getLogger(__name__)


def __virtual__():
    return True


def audit(data_list, tags, verbose=False):
    '''
    Run the network.netstat command
    '''
    ret = {'Success': [], 'Failure': []}

    __tags__ = []
    __feed__ = ''
    for data in data_list:
        if 'cve_scan' in data:
            __tags__ = ['cve_scan']
            for k,v in data.items():
                __feed__ = v
            break

    if not __tags__:
        # No yaml data found, don't do any work
        return ret

    ret['Failure'].append(__salt__['oscap.scan'](__feed__))
    return ret
