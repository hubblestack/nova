# -*- encoding: utf-8 -*-
'''
:rational: IPtables provides extra protection for the Linux system by limiting
communications in and out of the box to specific IPv4 addresses and ports.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibility: RedHat

'''
from __future__ import absolute_import
from nova import *
import logging


def __virtual__():
    '''
    Compatibility Check
    '''
    if 'RedHat' in __salt__['grains.get']('os_family'):
        return True
    return False


def audit():
    if 'systemctl' in CHKCONFIG:
        ret = _chkconfig('firewalld')
    if 'chkconfig' in CHKCONFIG:
        ret = _chkconfig('iptables')

    if '3:on' in ret:
        return True
    elif 'enabled' in ret:
        return True
    elif 'No such file or directory' in ret:
        return False
    return False
