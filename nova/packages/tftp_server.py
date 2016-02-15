# -*- encoding: utf-8 -*-
'''
:rational: TFTP does not support authentication nor does it ensure the
confidentiality of integrity of data. It is recommended that TFTP be removed,
unless there is a specific need for TFTP. In that case, extreme caution must be
used when configuring the services.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibility: RedHat

'''
from __future__ import absolute_import
from nova import *
import logging


def __virtual__():
    '''
    Compatibility Check
    '''
    if 'RedHat' in __salt__['grains.get']('os_family'):
        return True
    return False


def audit():
    ret = _rpmquery('tftp-server')
    if 'not installed' in ret:
        return True
    return False
