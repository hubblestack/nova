# -*- coding: utf-8 -*-
'''
There are two important reasons to ensure that system logs are stored on a
separate partition: protection against resource exhaustion (since logs can grow
quite large) and protection of audit data.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibilyt: all

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
    if '/var/log' in ret:
        return True
    return False
