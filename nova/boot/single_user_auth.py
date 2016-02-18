# -*- encoding: utf-8 -*-
'''
:rational: Requiring authentication in single user mode prevents an unauthorized
user from rebooting the system into single user to gain root privileges without
credentials.

:maintainer: HubbleStack
:maturity: 20160216
:depends: SaltStack
:platform: Linux
:compatibility: RedHat

'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    '''
    Compatibility Check
    '''
    if 'RedHat' in __salt__['grains.get']('os_family'):
        return True
    return False


def audit():
    ret = _grep('"^SINGLE"', '/etc/sysconfig/init')
    if 'sulogin' in ret:
        return True
    elif 'sushell' in ret:
        return False
    return False
