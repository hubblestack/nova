# -*- encoding: utf-8 -*-
'''
:rational: These legacy clients contain numerous security exposures and have
been replaced with the more secure SSH package. Even if the server is removed,
it is best to ensure the clients are also removed to prevent users from
inadvertently attempting to use these commands and therefore exposing their
credentials. Note that removing the rsh package removes the clients for rsh, rcp
and rlogin.

:maintainer: HubbleStack
:maturity: 20160216
:depends: SaltStack
:platform: Linux
:compatibility: all

'''
from __future__ import absolute_import
from nova import *
import logging


def virtual():
    '''
    Compatibility Check
    '''
    if not salt.utils.is_windows():
        return True
    return False


def audit():
    if not _package('rsh'):
        return True
    return False
