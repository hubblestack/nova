# -*- encoding: utf-8 -*-
'''
Requiring a boot password upon execution of the boot loader will prevent an
unauthorized user from entering boot parameters or changing the boot partition.
This prevents users from weakening security (e.g. turning off SELinux at boot
time).
'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    if 'RedHat' in __salt__['grains.get']('os_family'):
        return __virtualname__
    return False


def audit():
    if 'systemctl' in CHKCONFIG:
        ret = _grep('"^password"', '/boot/grub2/grub.cfg')
    elif 'chkconfig' in CHKCONFIG:
        ret = _grep('"^password"', '/etc/grub.conf')

    if ret:
        return True
    else:
        return False

