# -*- coding: utf-8 -*-
'''
Since the /var directory may contain world-writable files and directories, there
is a risk of resource exhaustion if it is not bound to a separate partition.

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
        return True
    return False


def audit():
    ret = _grep('"^/var"', '/etc/fstab')
    if '/var/tmp' in ret:
        return True
    return False
