# -*- encoding: utf-8 -*-
'''
:rational:The telnet protocol is insecure and unencrypted. The use of an
unencrypted transmission medium could allow an authorized user to steal
credentials. The ssh package provides an encrypted session and stronger security
and is included in most Linux distributions.

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
    if 'Linux' in __salt__['grains.get']('kernel'):
        return True
    return False


def audit():
    ret = _rpmquery('telnet')
    if 'not installed' in ret:
        return True
    return False
