# -*- encoding: utf-8 -*-
'''
:rational: These legacy service contain numerous security exposures and have
been replaced with the more secure SSH package.

:maintainer: HubbleStack
:maturity: 20160216
:depends: SaltStack
:platform: Linux
:compatibility: all

'''
from __future__ import absolute_import
from nova import *
import logging


def __virtual__():
    if not salt.utils.is_windows():
        return True
    return False


def audit():
    if not _package('rsh-server'):
        return True
    return False
