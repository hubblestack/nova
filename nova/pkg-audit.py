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
    FreeBSD only

    Load on FreeBSD 10 and greater.
    Load on DragonFly BSD.
    Load on FreeBSD 9 when config option
    ``providers:pkg`` is set to 'pkgng'.
    '''
    if __grains__['kernel'] == 'DragonFly':
        return __virtualname__
    if __grains__['os'] == 'FreeBSD' and float(__grains__['osrelease']) >= 10:
        return __virtualname__
    if __grains__['os'] == 'FreeBSD' and \
            float(__grains__['osmajorrelease']) == 9:
        providers = {}
        if 'providers' in __opts__:
            providers = __opts__['providers']
        log.debug('__opts__.providers: {0}'.format(providers))
        if providers and 'pkg' in providers and providers['pkg'] == 'pkgng':
            log.debug('Configuration option \'providers:pkg\' is set to '
                '\'pkgng\', using \'pkgng\' in favor of \'freebsdpkg\'.')
            return __virtualname__
    return (False,
            'The pkgng execution module cannot be loaded: only available '
            'on FreeBSD 10 or FreeBSD 9 with providers.pkg set to pkgng.')


def audit(jail=None, chroot=None):
    '''
    Audits installed packages against known vulnerabilities
    '''
    return __salt__['pkg.audit'](jail, chroot)


def check(jail=None,
          chroot=None,
          depends=False,
          recompute=False,
          checksum=False):
    '''
    Sanity checks installed packages
    '''
    return __salt__['pkg.check'](jail,chroot,depends,recompute,checksum)

