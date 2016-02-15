# -*- coding: utf-8 -*-
'''
:rational: Since the /dev/shm filesystem is not intended to support devices, set
this option to ensure that users cannot attempt to create special devices in
/dev/shm partitions.

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
    ret = _grep('"/home"', '/etc/fstab')
    if 'nodev' in ret:
        return True
    return False

