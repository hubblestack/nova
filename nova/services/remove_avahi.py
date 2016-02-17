# -*- encoding: utf-8 -*-
'''
:rational: Since servers are not normally used for printing, this service is not
needed unless dependencies require it. If this is the case, disable the service
to reduce the potential attack surface. If for some reason the service is
required on the server, follow the recommendations in sub-sections 3.2.1 - 3.2.5
to secure it.

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
    if not _service('avahi-daemon'):
        return True
    return False
