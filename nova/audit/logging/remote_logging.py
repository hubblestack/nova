# -*- encoding: utf-8 -*-
'''
:rational: Storing log data on a remote host protects log integrity from local
attacks. If an attacker gains root access on the local system, they could tamper
with or remove log data that is stored on the local system

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
    ret = _grep('"^*.* @"', '/etc/rsyslog.conf')
    if ret:
        return True
    return False
