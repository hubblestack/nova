# -*- encoding: utf-8 -*-
'''
:rational: The NIS service is inherently an insecure system that has been
vulnerable to DOS attacks, buffer overflows and has poor authentication for
querying NIS maps. NIS generally has been replaced by such protocols as
Lightweight Directory Access Protocol (LDAP). It is recommended that the service
be removed.

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
    ret = _rpmquery('ypbind')
    if 'not installed' in ret:
        return True
    return False
