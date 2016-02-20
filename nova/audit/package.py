# -*- encoding: utf-8 -*-
'''
:maintainer: HubbleStack
:maturity: 20160219
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
    for name, meta in __nova__.get('pkg').get('blacklist'):
        if not _package_check(name):
            NOVA['Success'].append(meta['tag'])
        NOVA['Failure'].append(meta['tag'])
    return NOVA
