# -*- encoding: utf-8 -*-
'''
:rational: It is recommended that physical systems and virtual guests lacking
direct access to the physical host's clock be configured as NTP clients to
synchronize their clocks (especially to support time sensitive security
mechanisms like Kerberos). This also ensures log files have consistent time
records across the enterprise, which aids in forensic investigations.

:maintainer: HubbleStack
:maturity: 20160212
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
    if 'Linux' in __salt__['grains.get']('kernel'):
        return True
    return False


def audit():
    ret = _grep('"restrict default"', '/etc/ntp.conf')
    if ret:
        return True
    return False
