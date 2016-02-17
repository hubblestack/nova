# -*- encoding: utf-8 -*-
'''
:rational: The NIS service is inherently an insecure system that has been
vulnerable to DOS attacks, buffer overflows and has poor authentication for
querying NIS maps. NIS generally has been replaced by such protocols as
Lightweight Directory Access Protocol (LDAP). It is recommended that the service
be removed.

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
    if not _package('ypbind'):
        return True
    return False
