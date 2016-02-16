# -*- encoding: utf-8 -*-
'''
:rational: Granting write access to this directory for non-privileged users
could provide them the means to gain unauthorized elevated privileges. Granting
read access to this directory could give an unprivileged user insight in how to
gain elevated privileges or circumvent auditing controls. In addition, it is a
better practice to create a white list of users who can execute at jobs versus a
blacklist of users who can't execute at jobs as a system administrator will
always know who can create jobs and does not have to worry about remembering to
add a user to the blacklist when a new user id is created.

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
    ret = _stat('/etc/at.allow')
    if '600 0 0' in ret:
        return True
    return False
