# -*- encoding: utf-8 -*-
'''
:rational: tcpmux-server can be abused to circumvent the server's host based
firewall.  Additionally, tcpmux-server can be leveraged by an attacker to
effectively port scan the server.

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
    if not _service('tcpmux-server'):
        return True
    return False
