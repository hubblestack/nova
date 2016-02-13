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
    Confine this module to rpm based systems
    '''
    if not salt.utils.which('rpm'):
        return (False, 'The rpm execution module failed to load: rpm binary is not in the path.')
    try:
        os_grain = __grains__['os'].lower()
        os_family = __grains__['os_family'].lower()
    except Exception:
        return (False, 'The rpm execution module failed to load: failed to detect os or os_family grains.')

    enabled = ('amazon', 'xcp', 'xenserver')

    if os_family in ['redhat', 'suse'] or os_grain in enabled:
        return __virtualname__
    return (False, 'The rpm execution module failed to load: only available on redhat/suse type systems '
        'or amazon, xcp or xenserver.')


def audit(*packages, **kwargs):
    '''
    '''
    return __salt__['lowpkg.verify'](*packages, **kwargs)
