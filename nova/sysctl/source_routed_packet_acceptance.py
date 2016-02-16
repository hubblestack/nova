# -*- encoding: utf-8 -*-
'''
:rational: Setting net.ipv4.conf.all.accept_source_route and
net.ipv4.conf.default.accept_source_route to 0 disables the system from
accepting source routed packets. Assume this server was capable of routing
packets to Internet routable addresses on one interface and private addresses on
another interface. Assume that the private addresses were not routable to the
Internet routable addresses and vice versa. Under normal routing circumstances,
an attacker from the Internet routable addresses could not use the server as a
way to reach the private address servers. If, however, source routed packets
were allowed, they could be used to gain access to the private address systems
as the route could be specified, rather than rely on routing protocols that did
not allow this routing.

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
    ret1 = _sysctl('net.ipv4.conf.all.accept_source_route')
    ret2 = _sysctl('net.ipv4.conf.default.accept_source_route')
    if ('0' in ret1 and '0' in ret2):
        return True
    return False
