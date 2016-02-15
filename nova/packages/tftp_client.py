# -*- encoding: utf-8 -*-
'''
:rational: It is recommended that TFTP be removed, unless there is a specific
need for TFTP (such as a boot server). In that case, use extreme caution when
configuring the services.

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
    ret = _rpmquery('tftp')
    if 'not installed' in ret:
        return True
    return False
