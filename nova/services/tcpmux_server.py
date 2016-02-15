# -*- encoding: utf-8 -*-
'''
:rational: tcpmux-server can be abused to circumvent the server's host based
firewall.  Additionally, tcpmux-server can be leveraged by an attacker to
effectively port scan the server.

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
    ret = _chkconfig('tcpmux-server')
    if 'No such file or directory' in ret:
        return True
    elif 'off' in ret:
        return True
    elif 'enabled' in ret:
        return False
    return False
