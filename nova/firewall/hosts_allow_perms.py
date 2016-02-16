# -*- encoding: utf-8 -*-
'''
:rational: It is critical to ensure that the /etc/hosts.allow file is protected
from unauthorized write access. Although it is protected by default, the file
permissions could be changed either inadvertently or through malicious actions.

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
    ret = _stat('/etc/hosts.allow')
    if '644' in ret:
        return True
    return False
