# -*- encoding: utf-8 -*-
'''
:rational: Disabling this service will reduce the remote attack surface of the
system.

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
    if not _service('chargen-stream'):
        return True
    return False
