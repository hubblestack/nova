# -*- encoding: utf-8 -*-
'''
This feature prevents the ability to delete or rename files in world writable
directories (such as /tmp) that are owned by another user.
'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    if 'Linux' in __salt__['grains.get']('kernel'):
	return __virtualname__
    return False


def audit():
    cmd = "df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null"
    ret = __salt__['cmd.run'](cmd, python_shell=True)
    if not ret:
        return True
    else:
        return False
