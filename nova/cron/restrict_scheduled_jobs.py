# -*- encoding: utf-8 -*-
'''
:rational: On many systems, only the system administrator is authorized to
schedule cron jobs. Using the cron.allow file to control who can run cron jobs
enforces this policy. It is easier to manage an allow list than a deny list. In
a deny list, you could potentially add a user ID to the system and forget to add
it to the deny files.

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
    ret1 = _stat('/etc/cron.deny')
    ret2 = _stat('/etc/at.deny')
    ret3 = _stat('/etc/cron.allow')
    ret4 = _stat('/etc/at.allow')
    if (('600 0 0' in ret3 and '600 0 0' in ret4) and
       ('cannot stat' in ret1 and 'cannot stat' in ret2)):
        return True
    return False
