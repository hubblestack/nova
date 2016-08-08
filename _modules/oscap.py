# -*- coding: utf-8 -*-
'''
OpenSCAP scanner execution module.

:maintainer: HubbleStack / cedwards
:maturity: 2016.7.0
:platform: RedHat
:requires: SaltStack
:upstream: http://open-scap.org

This execution module uses the openSCAP scanner utility and an argument of an
XML guide. The returned data should be a dictionary of the cmd output.

The packages are: openscap-scanner openscap

Configurable options would be:
  show_success: True/False

.. code-block:: yaml

    cve_scan: https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml

'''
from __future__ import absolute_import

# Import python libs
import logging

# Import salt libs
from salt.ext.six.moves.urllib.parse import urlparse  # pylint: disable=no-name-in-module
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
    parsed = urlparse(filename)
    if not parsed.scheme:
        filename = 'salt://' + filename
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
