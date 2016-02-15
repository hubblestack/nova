# -*- coding: utf-8 -*-
'''
Global helper functions
'''
from __future__ import absolute_import

import logging
import salt.utils

LOG = logging.getLogger(__name__)

GREP = salt.utils.which('egrep')
STAT = salt.utils.which('stat')
SYSCTL = salt.utils.which('sysctl')
RPMQUERY = salt.utils.which('rpm')

if salt.utils.which('chkconfig'):
    CHKCONFIG = salt.utils.which('chkconfig')
if salt.utils.which('systemctl'):
    CHKCONFIG = salt.utils.which('systemctl')


def _grep(pattern, filename, shell=False):
    cmd = '{0} {1} {2}'.format(GREP, pattern, filename)
    return __salt__['cmd.run'](cmd, python_shell=shell)


def _stat(filename):
    '''
    Standard function for all ``stat`` commands.
    '''
    cmd = '{0} {1} {2}'.format(STAT, '-L -c "%a %u %g"', filename)
    return __salt__['cmd.run'](cmd, python_shell=False)


def _sysctl(keyname):
    cmd = '{0} {1}'.format(SYSCTL, keyname)
    return __salt__['cmd.run'](cmd, python_shell=False)


def _rpmquery(package):
    cmd = '{0} {1} {2}'.format(RPMQUERY, '-q', package)
    return __salt__['cmd.run'](cmd, python_shell=False)


def _chkconfig(service):
    if 'systemctl' in CHKCONFIG:
        cmd = '{0} {1} {2}'.format(CHKCONFIG, 'is-enabled', service)
    elif 'chkconfig' in CHKCONFIG:
        cmd = '{0} {1} {2}'.format(CHKCONFIG, '--list', service)
    return __salt__['cmd.run'](cmd, python_shell=False)

