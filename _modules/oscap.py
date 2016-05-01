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

On CentOS the packages are: openscap-scanner openscap

Configurable options would be:
  show_success: True/False

This version requires the file be stored in /root/ (because I'm being lazy).
Afterwards the command is run as:

.. code-block:: shell

    wget http://www.redhat.com/security/data/oval/com.redhat.rhsa-RHELX.xml

    salt centos\* oscap.scan salt://com.redhat.rhsa-RHELX.xml


Roadmap:
  * top.nova mapping for feed profiles
  * performance improvements
  * feed-type via args (oval vs xccdf) / autodetection
  * support ubuntu, debian, centos, rhel, suse
    * support already exists for FreeBSD (via pkg audit)
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


def scan(filename):
    '''
    scan function
    '''
    if not filename.startswith('salt://'):
        filename = 'salt://' + filename
    if filename.startswith('salt://'):
        cached_source = __salt__['cp.cache_file'](filename)

    ret = {'Vulnerabilities': []}

    cmd = '{0} oval eval {1}'.format(_OSCAP, cached_source)
    salt_ret = __salt__['cmd.run_all'](cmd, python_shell=False)

    items = salt_ret['stdout'].split('\n')
    for item in items:
        if 'true' in item:
            if 'rhsa' in item:
                rhsa = item.split(':')[3]
                year = item.split(':')[3][:4]
                num = item.split(':')[3][4:]
                url = 'https://rhn.redhat.com/errata/RHSA-' + year + '-' + num + '.html'
                ret['Vulnerabilities'].append('RHSA-' + rhsa + ' : ' + url)

    return ret
