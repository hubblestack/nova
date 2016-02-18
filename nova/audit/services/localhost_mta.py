# -*- encoding: utf-8 -*-
'''
:rational: The software for all Mail Transfer Agents is complex and most have a
long history of security issues. While it is important to ensure that the system
can process local mail messages, it is not necessary to have the MTA's daemon
listening on a port unless the server is intended to be a mail server that
receives and processes mail from other systems.

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
    cmd = 'netstat -an | grep LIST | grep ":25[[:space:]]"'
    ret = __salt__['cmd.run'](cmd, python_shell=True)
    if '127.0.0.1' in ret:
        return True
    return True
