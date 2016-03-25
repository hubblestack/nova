# -*- coding: utf-8 -*-
'''
HubbleStack: Compliance for DevOps
==================================

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: all

Hubble is a compliance auditing and remediation tool.
'''

from __future__ import absolute_import
import logging

import salt.utils

# Set up logging
log = logging.getLogger(__name__)
__virtualname__ = 'pkg'


def __virtual__():
    '''
    Set the virtual pkg module if the os is openSUSE
    '''
    if __grains__.get('os_family', '') != 'Suse':
        return (False, "Module zypper: non SUSE OS not suppored by zypper package manager")
    # Not all versions of Suse use zypper, check that it is available
    if not salt.utils.which('zypper'):
        return (False, "Module zypper: zypper package manager not found")
    return __virtualname__


def audit(*packages, **kwargs):
    '''
    '''
    return __salt__['lowpkg.verify'](*packages, **kwargs)
