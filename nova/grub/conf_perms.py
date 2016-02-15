# -*- encoding: utf-8 -*-
'''
Setting the permissions to read and write for root only prevents non-root users
from seeing the boot parameters or changing them. Non-root users who read the
boot parameters may be able to identify weaknesses in security upon boot and be
able to exploit them.
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
        ret = _stat('/boot/grub2/grub.cfg')
    elif 'chkconfig' in CHKCONFIG:
        ret = _stat('/etc/grub.conf')

    if '600' in ret:
        return True
    return False

