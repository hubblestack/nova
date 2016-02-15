# -*- encoding: utf-8 -*-
'''
Requiring authentication in single user mode prevents an unauthorized user from
rebooting the system into single user to gain root privileges without
credentials.
'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    '''
    Compatibility Check'
    '''
    if 'RedHat' in __salt__['grains.get']('os_family'):
        return True
    return False


def audit():
    ret = _grep('"^PROMPT"', '/etc/sysconfig/init')
    if ('no' or 'NO') in ret:
        return True
    elif ('yes' or 'YES') in ret:
        return False

