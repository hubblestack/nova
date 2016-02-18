# -*- encoding: utf-8 -*-
'''
:rational: Accepting ICMP echo and timestamp requests with broadcast or
multicast destinations for your network could be used to trick your host into
starting (or participating) in a Smurf attack. A Smurf attack relies on an
attacker sending large amounts of ICMP broadcast messages with a spoofed source
address.  All hosts receiving this message and responding would send echo-reply
messages back to the spoofed address, which is probably not routable. If many
hosts respond to the packets, the amount of traffic on the network could be
significantly multiplied.

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
    if '1' in _sysctl('net.ipv4.icmp_echo_ignore_broadcasts'):
        return True
    return False
