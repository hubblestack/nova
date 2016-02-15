# -*- coding: utf-8 -*-
'''
Since the /tmp directory is intended to be world-writable, there is a risk of
resource exhaustion if it is not bound to a separate partition. In addition,
making /tmp its own file system allows an administrator to set the noexec
option on the mount, making /tmp useless for an attacker to install executable
code. It would also prevent an attacker from establishing a hardlink to a
system setuid program and wait for it to be updated. Once the program was
updated, the hardlink would be broken and the attacker would have his own copy
of the program. If the program happened to have a security vulnerability, the
attacker could continue to exploit the known flaw.

:maintainer: HubbleStack
:maturity: 20160212
:depends: SaltStack
:platform: Linux
:compatibility: all

'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    if 'Linux' in __salt__['grains.get']('kernel'):
        return True
    return False


def audit():
    ret = _grep('"/tmp"', '/etc/fstab')
    if ret:
        return True
    return False
