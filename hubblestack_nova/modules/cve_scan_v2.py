'''

:maintainer: HubbleStack
:maturity: 20160214
:platform: Linux
:requires: SaltStack


Sample YAML data, without inline comments:

cve_scan_v2:
    ttl:
    url: salt://
'''
from __future__ import absolute_import
import logging

import salt
import salt.utils
import salt.utils.http

from distutils.version import LooseVersion
from datetime import datetime
from time import time as current_time

def __virtual__():
    return True



def audit(data_list, tags, verbose=False):

    
    os = __grains__['os']
    os_version = __grains__['osmajorrelease']

    cache = {}
    
    # Go through data_list and check if 
    #   < 1 day old cache is in any yaml file
    for data in data_list:

        if "cve_scan_v2" in data:
            if "cache" not in data["cve_scan_v2"]:
                continue

            cached_scans = data["cve_scan_v2"]["cache"] # cve_scan_v2:cache
            
            if os not in cached_scans:
                continue

            cached_data = cached_scans[os] # cve_scan_v2:cache:CentOS

            curr_datetime = datetime.fromtimestamp(current_time)

            try:
                cached_timestamp = float(cached_data["timestamp"]) # cve_scan_v2:cache:CentOS:timestamp
            except ValueError, e:
                #yaml not formatted correctly
                continue

            last_datetime = datetime.fromtimestamp(cached_timestamp)
            time_delta = curr_datetime - last_datetime

            if time_delta.days >= 1:
                continue

            else:
                #Found cache less than 1 day old
                cache = cached_data.get("data", {})
                if cache != {}: 
                    break
    
    ret = {'Success':[], 'Failure':[]}   

    #Check if cache less than 1 day old exists, and make sure its not empty results.
    if cache and cache != ret:
        return cache 
    
    affected_pkgs = _get_cve_vulnerabilities(os, osmajorrelease)
    local_pkgs = __salt__['pkg.list_pkgs']()
    
    
    for pkgObj in affected_pkgs:

        if pkgObj.get_pkg() in local_pkgs:

            local_version = LooseVersion(local_pkgs[pkgObj.get_pkg()])
            affected_version = LooseVersion(pkgObj.get_version())

            if pkgObj.get_operator == 'lt':
                if local_version < affected_version:
                    ret['Failure'].append(pkgObj.report())
                else:
                    ret['Success'].append(pkgObj.get_pkg())
            
            elif pkgObj.get_operator() == 'le':
                if local_version <= affected_version:
                    ret['Failure'].append(pkgObj.report())
                else:
                    ret['Success'].append(pkgObj.get_pkg())

    




def _get_cve_vulnerabilities(os, os_version):
    """
    Returns list of vulnerable package objects.
    """
    
    vulnerable_pkgs = []

    try:
        cve_query = salt.utils.http.query(
            'http://vulners.com/api/v3/search/lucene/?query=type:%s' % os.lower(),
            decode_type='json'
        )
    except Exception: # Ask about error handling...
        return
    
    if cve_query['result'].lower() != 'ok':
        return
    
    for report in cve_query['data']['search']:
        reporter = report['_source']['reporter']
        cve_list = report['_source']['cvelist']
        href = report['_source']['href']
        for pkg in report['_source']['affectedPackages']:
            if pkg['OSVersion'] in ['any', osmajorrelease]:
                vulnerable_pkg.append(vulnerablePkg(pkg['packageName'],pkg['packageVersion'], pkg['operator'], reporter, href, cve_list))   
        
    return vulnerable_pkgs


class vulnerablePkg:
    def __init__(self, pkg, pkg_version, operator, reporter, href, cve_list):
        self.pkg = pkg
        self.pkg_version = pkg_version
        self.operator = operator
        self.href = href
        self.cve_list = cve_list
        self.reporter = reporter
    def get_pkg(self):
        return self.pkg
    def get_version(self):
        return self.pkg_version
    def get_operator(self):
        return self.operator
    def get_cve_list(self):
        def_copy = copy.copy(self.cve_list)
        return def_copy
    def get_reporter(self):
        return self.reporter
    def report(self):
        return {
            'reporter': self.get_reporter(),
            'operator': self.get_operator(),
            'cve_list': self.get_cve_list(),
            'pkg': self.get_pkg()
        }
