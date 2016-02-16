# -*- encoding: utf-8 -*-
'''
:rational: Granting write access to this directory for non-privileged users
could provide them the means for gaining unauthorized elevated privileges.
Granting read access to this directory could give an unprivileged user insight
in how to gain elevated privileges or circumvent auditing controls.

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
    ret = _stat('/etc/cron.daily')
    if '600 0 0' in ret:
        return True
    return False
