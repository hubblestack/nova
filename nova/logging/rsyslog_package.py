# -*- encoding: utf-8 -*-
'''
:rational: The security enhancements of rsyslog such as connection-oriented
(i.e. TCP) transmission of logs, the option to log to database formats, and the
encryption of log data en route to a central logging server) justify installing
and configuring the package.

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
    ret = _rpmquery('rsyslog')
    if 'not installed' in ret:
        return False
    return True
