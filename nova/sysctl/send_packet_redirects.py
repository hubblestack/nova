# -*- encoding: utf-8 -*-
'''
:rational: An attacker could use a compromised host to send invalid ICMP
redirects to other router devices in an attempt to corrupt routing and have
users access a system set up by the attacker as opposed to a valid system.

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
    ret1 = _sysctl('net.ipv4.conf.all.send_redirects')
    ret2 = _sysctl('net.ipv4.conf.default.send_redirects')
    if ('0' in ret1 and '0' in ret2):
        return True
    return False
