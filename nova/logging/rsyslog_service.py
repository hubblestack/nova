# -*- encoding: utf-8 -*-
'''
:rational: It is important to ensure that syslog is turned off so that it does
not interfere with the rsyslog service.

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
    ret = _chkconfig('rsyslog')
    if '3:on' in ret:
        return True
    elif 'enabled' in ret:
        return True
    elif 'No such file or directory' in ret:
        return False
    return False
