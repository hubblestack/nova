# -*- encoding: utf-8 -*-
'''
Setting the umask to 027 will make sure that files created by daemons will not
be readable, writable or executable by any other than the group and owner of the
daemon process and will not be writable by the group of the daemon process. The
daemon process can manually override these settings if these files need
additional permission.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibility: RedHat

'''
from __future__ import absolute_import
from nova import *
import logging


def __virtual__():
    '''
    Compatibility Check
    '''
    if 'RedHat' in __salt__['grains.get']('os_family'):
        return True
    return False


def audit():
    ret = _grep('"umask"', '/etc/sysconfig/init')
    if 'umask 027' in ret:
        return True
   return False
