# -*- encoding: utf-8 -*-
'''
:rational: The security enhancements of rsyslog such as connection-oriented
(i.e. TCP) transmission of logs, the option to log to database formats, and the
encryption of log data en route to a central logging server) justify installing
and configuring the package.

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
    if not _package('rsyslog'):
        return True
    return False
