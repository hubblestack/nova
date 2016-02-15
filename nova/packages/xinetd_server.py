# -*- encoding: utf-8 -*-
'''
:rational: If there are no xinetd services required, it is recommended that the
daemon be deleted from the system.

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
    ret = _rpmquery('xinetd')
    if 'not installed' in ret:
        return True
    return False
