# -*- encoding: utf-8 -*-
'''
:rational: IPtables provides extra protection for the Linux system by limiting
communications in and out of the box to specific IPv4 addresses and ports.

:maintainer: HubbleStack
:maturity: 20160216
:depends: SaltStack
:platform: Linux / FreeBSD
:compatibility: RedHat

'''
from __future__ import absolute_import
from nova import *
import logging


def __virtual__():
    '''
    Compatibility Check
    '''
    if 'RedHat' or 'FreeBSD' in __salt__['grains.get']('os_family'):
        return True
    return False


def audit():
    if _service('firewalld'):
        return True
    if _service('iptables'):
        return True
    if _service('pf'):
        return True
    return False
