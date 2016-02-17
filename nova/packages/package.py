# -*- encoding: utf-8 -*-
'''
:maintainer: HubbleStack
:maturity: 20160217
:depends: SaltStack
:platform: Linux
:compatibility: all

'''
from __future__ import absolute_import
from nova import *
import logging


def __virtual__():
    '''
    Compatibility Check
    '''
    if not salt.utils.is_windows():
        return True
    return False


def audit():
    packages = __salt__['photon.get']('package:deny', [])
    for pkg in packages:
        if not _package_check(pkg):
            return True
        return False
