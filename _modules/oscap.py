# -*- coding: utf-8 -*-
'''
OpenSCAP scanner execution module.

:maintainer: Christer Edwards (christer.edwards@gmail.com)
:maturity: 20160426
:platform: Linux
:requires: SaltStack

:upstream: http://open-scap.org

This execution module uses the openSCAP scanner utility and an argument of an
XML guide. The returned data should be a dictionary of the cmd output.

On CentOS the package is: openscap-scanner

Configurable options would be:
  show_success: True/False

This version requires the file be stored in /root/ (because I'm being lazy).
Afterwards the command is run as:

.. code-block:: shell

    cd /root/
    wget http://www.redhat.com/security/data/metrics/com.redhat.rhsa-all.xccdf.xml
    wget http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml

    salt centos\* oscap.scan com.redhat.rhsa-all.xccdf.xml


Roadmap:
  * hubblestack_nova file-server support
  * top.nova mapping for feed profiles
  * abstraction to a Hubble Nova module
  * performance improvements
  * feed-type via args (oval vs xccdf) / autodetection
  * support ubuntu, debian, centos, rhel, suse
    * support already exists for FreeBSD (via pkg audit)
  * safer handling of results and report output (.xml and .html)
  * cmd output or results.xml parsing and custom reporting
'''
from __future__ import absolute_import

# Import python libs
import logging

from salt import utils

__virtualname__ = 'oscap'

log = logging.getLogger(__name__)

_OSCAP = utils.which('oscap')


def __virtual__():
    '''
    Compatible with Linux & requires oscap binary
    '''
    return True


def scan(data, result='results.xml', report='report.html'):
    '''
    scan function
    '''
    ret = {}
    cmd = '{0} xccdf eval --results {1} --report {2} {3}'.format(_OSCAP, result, report, data)
    salt_ret = __salt__['cmd.run'](cmd, python_shell=False)

    return salt_ret
