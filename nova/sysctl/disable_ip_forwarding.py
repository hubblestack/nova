# -*- encoding: utf-8 -*-
'''
:rational: Setting the flag to 0 ensures that a server with multiple interfaces
(for example, a hard proxy), will never be able to forward packets, and
therefore, never serve as a router.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibility: all

'''
from __future__ import absolute_import
from nova import *
import logging


def __virtual__():
    '''
    Compatibility Check
    '''
    if 'Linux' in __salt__['grains.get']('kernel'):
        return True
    return False


def audit():
    ret = _sysctl('net.ipv4.ip_forward')
    if '0' in ret:
        return True
    return False
