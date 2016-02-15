# -*- encoding: utf-8 -*-
'''
Unless your organization specifically requires graphical login access via X
Windows, remove it to reduce the potential attack surface.

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
    ret = _grep('"^id"', '/etc/inittab')
    if 'id:3:initdefault' in ret:
        return True
    elif 'id:5:initdefault' in ret:
        return False
    return False
