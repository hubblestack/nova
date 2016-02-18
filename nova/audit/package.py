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

NOVA = {}
NOVA['Success'] = []
NOVA['Failure'] = []


def __virtual__():
    '''
    Compatibility Check
    '''
    if not salt.utils.is_windows():
        return True
    return False


def audit(tag=None):
    for name, meta in pillar.get('pkg:blacklist'):
        if not _package_check(name):
            return NOVA['Success'].append(meta['tag'])
        return NOVA['Failure'].append(meta['tag'])
