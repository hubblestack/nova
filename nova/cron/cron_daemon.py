# -*- encoding: utf-8 -*-
'''
:rational: While there may not be user jobs that need to be run on the system,
the system does have maintenance jobs that may include security monitoring that
have to run and crond is used to execute them.

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
    ret = _chkconfig('crond')
    if '3:on' in ret:
        return True
    elif 'enabled' in ret:
        return True
    elif 'No such file or directory' in ret:
        return False
    return False
