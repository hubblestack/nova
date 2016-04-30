# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for FreeBSD pkgng audit

:maintainer: HubbleStack
:maturity: 20160428
:platform: Unix
:requires: SaltStack
'''
from __future__ import absolute_import
import logging

log = logging.getLogger(__name__)


def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on Unix'
    return True


def audit(data_list, tags, verbose=False):
    '''
    Run the network.netstat command
    '''
    ret = {'Success': [], 'Failure': []}

    __tags__ = []
    for data in data_list:
        if 'netstat' in data:
            __tags__ = ['netstat']
            break

    if not __tags__:
        # No yaml data found, don't do any work
        return ret

    return __salt__['network.netstat']()
