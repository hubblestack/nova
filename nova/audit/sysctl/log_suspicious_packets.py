# -*- encoding: utf-8 -*-
'''
:rational: Enabling this feature and logging these packets allows an
administrator to investigate the possibility that an attacker is sending spoofed
packets to their server.

:maintainer: HubbleStack
:maturity: 20160216
:depends: SaltStack
:platform: Linux
:compatibility: all

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
    ret1 = _sysctl('net.ipv4.conf.all.log_martians')
    ret2 = _sysctl('net.ipv4.conf.default.log_martians')
    if ('1' in ret1 and '1' in ret2):
        return True
    return False
