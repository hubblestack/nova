# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for FreeBSD pkgng audit

:maintainer: HubbleStack
:maturity: 20160623
:platform: Unix
:requires: SaltStack
'''
from __future__ import absolute_import

import copy
import logging

import salt.utils

log = logging.getLogger(__name__)


def __virtual__():
    if 'network.netstat' in __salt__:
        return True
    return False, 'No network.netstat function found'


def audit(data_list, tags, verbose=False):
    '''
    Run the network.netstat command
    '''
    ret = {'Success': [], 'Failure': []}

    __tags__ = {}
    for data in data_list:
        if 'netstat' in data:
            for check, check_args in data['netstat'].iteritems():
                if 'address' in check_args:
                    tag_args = copy.deepcopy(check_args)
                    tag_args['id'] = check
                    __tags__[check_args['address']] = tag_args

    if not __tags__:
        # No yaml data found, don't do any work
        return ret

    for address_data in __salt__['network.netstat']():
        address = address_data['local-address']
        if address in __tags__:
            success_data = {address: __tags__[address]}
            if verbose:
                success_data.update(address_data)
            ret['Success'].append(success_data)
        else:
            failure_data = {address: {'program': address_data['program']}}
            if verbose:
                failure.data.update(address_data)
            ret['Failure'].append(failure_data)

    return ret
