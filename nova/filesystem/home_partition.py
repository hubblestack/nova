# -*- coding: utf-8 -*-
'''
If the system is intended to support local users, create a separate partition
for the /home directory to protect against resource exhaustion and restrict the
type of files that can be stored under /home.
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
    if ret:
        return True
    return False

