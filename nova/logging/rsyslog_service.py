# -*- encoding: utf-8 -*-
'''
:rational: It is important to ensure that syslog is turned off so that it does
not interfere with the rsyslog service.

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
    if salt.utils.is_windows():
        return True
    return False


def audit():
    if _service('rsyslog'):
        return True
    return False
