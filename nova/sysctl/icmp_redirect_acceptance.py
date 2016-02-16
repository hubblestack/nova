# -*- encoding: utf-8 -*-
'''
:rational: Attackers could use bogus ICMP redirect messages to maliciously alter
the system routing tables and get them to send packets to incorrect networks and
allow your system packets to be captured.

:maintainer: HubbleStack
:maturity: 20160212
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
    ret1 = _sysctl('net.ipv4.conf.all.accept_redirects')
    ret2 = _sysctl('net.ipv4.conf.default.accept_redirects')
    if ('0' in ret1 and '0' in ret2):
        return True
    return False
