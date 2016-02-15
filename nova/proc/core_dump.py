# -*- encoding: utf-8 -*-
'''
:rational: Setting a hard limit on core dumps prevents users from overriding the
soft variable. If core dumps are required, consider setting limits for user
groups (see limits.conf(5)). In addition, setting the fs.suid_dumpable variable
to 0 will prevent setuid programs from dumping core.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibility: all

'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    '''
    Compatibility Test
    '''
    if 'Linux' in __salt__['grains.get']('kernel'):
        return True
    return False


def audit():
    ret1 = _grep('"hard core"', '/etc/security/limits.conf')
    ret2 = _sysctl('fs.suid_dumpable')
    if (ret1 and (ret2 == '0')):
        return True
    return False
