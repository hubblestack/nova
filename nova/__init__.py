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


def _grep(pattern, filename, shell=False):
    cmd = '{0} {1} {2}'.format(GREP, pattern, filename)
    return __salt__['cmd.run'](cmd, python_shell=shell)


def _stat(filename, shell=False):
    cmd = '{0} {1} {2}'.format(STAT, '-L -c "%a %u %g"', filename)
    return __salt__['cmd.run'](cmd, python_shell=shell)


def _sysctl(keyname):
    return __salt__['sysctl.get'](keyname)


def _package(package):
    return __salt__['pkg.version'](package)


def _service(service):
    return __salt__['service.status'](service)
