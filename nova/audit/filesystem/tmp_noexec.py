# -*- coding: utf-8 -*-
'''
:rational: Since the /tmp filesystem is only intended for temporary file
storage, set this option to ensure that users cannot run executable binaries
from /tmp.

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
    ret = _grep('"/tmp"', '/etc/fstab')
    if 'noexec' in ret:
        return True
    return False
