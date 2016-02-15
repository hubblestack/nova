# -*- encoding: utf-8 -*-
'''
:rational: Enabling any feature that can protect against buffer overflow attacks
enhances the security of the system.

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
    Compatibility Check
    '''
    if 'Linux' in __salt__['grains.get']('kernel'):
        return True
    return False


def audit():
    ret = _sysctl('kernel.exec-shield')
    if '1' in ret:
        return True
    return False
