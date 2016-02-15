# -*- encoding: utf-8 -*-
'''
Randomly placing virtual memory regions will make it difficult for to write
memory page exploits as the memory placement will be consistently shifting.
'''
from __future__ import absolute_import
from audit import *
import logging


def __virtual__():
    '''
    Compatibility Check
    '''
    if 'Linux' in __salt__['grains.get']('kernel'):
        return True
    return False


def audit():
    ret = _sysctl('kernel.randomize_va_space')
    if '2' in ret:
        return True
    return False

