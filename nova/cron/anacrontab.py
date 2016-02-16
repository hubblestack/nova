# -*- encoding: utf-8 -*-
'''
:rational: This file contains information on what system jobs are run by
anacron.  Write access to these files could provide unprivileged users with the
ability to elevate their privileges. Read access to these files could provide
users with the ability to gain insight on system jobs that run on the system and
could provide them a way to gain unauthorized privileged access.

:maintainer: HubbleStack
:maturity: 20160212
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
    if 'Linux' in __salt__['grains.get']('kernel'):
        return True
    return False


def audit():
    ret = _stat('/etc/anacrontab')
    if '600 0 0' in ret:
        return True
    return False
