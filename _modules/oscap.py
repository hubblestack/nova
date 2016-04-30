# -*- coding: utf-8 -*-
'''
OpenSCAP scanner execution module.

:maintainer: Christer Edwards (christer.edwards@gmail.com)
:maturity: 20160430
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
import salt.minion
import salt.fileclient

from salt import utils

__virtualname__ = 'oscap'

log = logging.getLogger(__name__)

_OSCAP = utils.which('oscap')


def __virtual__():
    '''
    Compatible with Linux & requires oscap binary
    '''
    return True


def scan(path):
    '''
    scan function
    '''
    ret = {'Vulnerabilities': [], 'Total': ''}

    cmd = '{0} oval eval {1}'.format(_OSCAP, path)
    log.debug(cmd)
    salt_ret = __salt__['cmd.run_all'](cmd, python_shell=False)

    ## Definition oval:com.redhat.rhsa:def:20140675: false
    items = salt_ret['stdout'].split('\n')
    for item in items:
        if 'true' in item:
            if 'rhsa' in item:
                rhsa = item.split(':')[3]
                year = item.split(':')[3][:4]
                num = item.split(':')[3][4:]
                url = 'https://rhn.redhat.com/errata/RHSA-' + year + '-' + num + '.html'
                ret['Vulnerabilities'].append('RHSA-' + item.split(':')[3] + ' : ' + url)

    ret['Total'] = len(ret['Vulnerabilities'])
    return ret
