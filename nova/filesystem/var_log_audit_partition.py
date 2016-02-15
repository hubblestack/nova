# -*- coding: utf-8 -*-
'''
There are two important reasons to ensure that data gathered by auditd is
stored on a separate partition: protection against resource exhaustion (since
the audit.log file can grow quite large) and protection of audit data. The
audit daemon calculates how much free space is left and performs actions based
on the results. If other processes (such as syslog) consume space in the same
partition as auditd, it may not perform as desired.
'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    if 'Linux' in __salt__['grains.get']('kernel'):
        return __virtualname__
    return False


def audit():
    ret = _grep('"/var/log/audit"', '/etc/fstab')
    if ret:
        return True
    else:
        return False

