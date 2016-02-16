# -*- encoding: utf-8 -*-
'''
:rational: Cron jobs may include critical security or administrative functions
that need to run on a regular basis. Use this daemon on machines that are not up
24x7, or if there are jobs that need to be executed after the system has been
brought back up after a maintenance window.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibility: RedHat

'''
from __future__ import absolute_import
from nova import *
import logging


def __virtual__():
    '''
    Compatibility Check
    '''
    if 'RedHat' in __salt__['grains.get']('os_family'):
        return True
    return False


def audit():
    ret = _rpmquery('cronie-anacron')
    if 'not installed' in ret:
        return False
    return True
