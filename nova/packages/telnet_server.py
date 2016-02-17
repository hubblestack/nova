# -*- encoding: utf-8 -*-
'''
:rational: The telnet protocol is insecure and unencrypted. The use of an
unencrypted transmission medium could allow a user with access to sniff network
traffic the ability to steal credentials. The ssh package provides an encrypted
session and stronger security and is included in most Linux distributions.

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
    if not salt.utils.is_windows():
        return True
    return False


def audit():
    if not _package('telnet-server'):
        return True
    return False
