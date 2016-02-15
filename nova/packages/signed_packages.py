# -*- encoding: utf-8 -*-
'''
:rational: It is important to ensure that an RPM's package signature is always
checked prior to installation to ensure that the software is obtained from a
trusted source.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibility: RedHat

'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    if 'RedHat' in __salt__['grains.get']('os_family'):
        return True
    return False


def audit():
    ret = _grep('gpgcheck=0', '/etc/yum.repos.d/*.repo', shell=True)
    if ret:
        return False
    return True
