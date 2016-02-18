# -*- encoding: utf-8 -*-
'''
:rational: Attackers use SYN flood attacks to perform a denial of service
attacked on a server by sending many SYN packets without completing the three
way handshake. This will quickly use up slots in the kernel's half-open
connection queue and prevent legitimate connections from succeeding. SYN cookies
allow the server to keep accepting valid connections, even if under a denial of
service attack.

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
    if '1' in _sysctl('net.ipv4.tcp_syncookies'):
        return True
    return False
