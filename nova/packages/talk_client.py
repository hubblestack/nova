# -*- encoding: utf-8 -*-
'''
:rational: The software presents a security risk as it uses unencrypted
protocols for communication.

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
    ret = _rpmquery('talk')
    if 'not installed' in ret:
        return True
    return False
