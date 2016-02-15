# -*- coding: utf-8 -*-
'''
:rational: Setting this option on a file system prevents users from introducing
privileged programs onto the system and allowing non-root users to execute them.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibility: all

'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    if 'Linux' in __salt__['grains.get']('kernel'):
        return __virtualname__
    return False


def audit():
    ret = _grep('"/dev/shm"', '/etc/fstab')
    if 'nosuid' in ret:
        return True
    return False

