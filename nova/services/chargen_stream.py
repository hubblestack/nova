# -*- encoding: utf-8 -*-
'''
:rational: Disabling this service will reduce the remote attack surface of the
system.

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
    ret = _chkconfig('chargen-stream')
    if 'No such file or directory' in ret:
        return True
    elif 'off' in ret:
        return True
    elif 'enabled' in ret:
        return False
    return False
