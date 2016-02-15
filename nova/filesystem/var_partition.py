# -*- coding: utf-8 -*-
'''
Since the /var directory may contain world-writable files and directories, there
is a risk of resource exhaustion if it is not bound to a separate partition.
'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    if 'Linux' in __salt__['grains.get']('kernel'):
	return __virtualname__
    return False


def audit():
    ret = _grep('"/var"', '/etc/fstab')
    if ret:
        return True
    else:
        return False

