# -*- encoding: utf-8 -*-
'''
These legacy service contain numerous security exposures and have been replaced
with the more secure SSH package.
'''
from __future__ import absolute_import
from nova import *
import logging


def __virtual__():
    if 'RedHat' in __salt__['grains.get']('os_family'):
        return True
    return False


def audit():
    ret = _rpmquery('rsh-server')
    if 'not installed' in ret:
        return True
    return False

