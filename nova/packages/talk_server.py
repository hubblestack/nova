# -*- encoding: utf-8 -*-
'''
:rational: The software presents a security risk as it uses unencrypted
protocols for communication.

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
    if not _package('talk-server'):
        return True
    return False
