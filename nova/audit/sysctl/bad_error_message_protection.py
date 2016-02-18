# -*- encoding: utf-8 -*-
'''
:rational: Some routers (and some attackers) will send responses that violate
RFC-1122 and attempt to fill up a log file system with many useless error
messages.

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
    if '1' in _sysctl('net.ipv4.icmp_ignore_bogus_error_response'):
        return True
    return False
