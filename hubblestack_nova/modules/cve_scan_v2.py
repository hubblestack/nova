'''

:maintainer: HubbleStack
:maturity: 20160214
:platform: Linux
:requires: SaltStack


Sample YAML data

cve_scan_v2:
    ttl: 86400
    url: http://vulners.com/api/v3/search/lucene/
'''
from __future__ import absolute_import
import logging

import salt
import salt.utils
import salt.utils.http
import requests


import json
import os

from distutils.version import LooseVersion
from datetime import datetime
from time import time as current_time
import time
log = logging.getLogger(__name__)

log.error("LOG START:")
def __virtual__():
    return True

def audit(data_list, tags, verbose=False):
     
    os_name = __grains__['os'].lower()
    log.error(os_name)
    cache = {}
    
    # Go through data_list and check if 
    #   < 1 day old cache is in any yaml file
    for data in data_list:

        if 'cve_scan_v2' in data:

            ttl = data['cve_scan_v2']['ttl']
            url = data['cve_scan_v2']['url']
            log.error(str(ttl) + url)
            cache = _get_cache(ttl, url)
            log.error("got past cache and got %s", cache)
            if cache.get('result', None) == 'OK':
                master_json = cache
                break

    # Query the api.
    if not cache:

        is_next_page = True
        page_num = 0
        
        # Hit the api, incrementing the offset due to the page until 
        #   we get all the results together in one dictionary.
        try:
            while is_next_page:
                
                offset = page_num * 20
                page_num += 1
                cve_query = requests.get(
                    '%s?query=order:last 10 days&type:%s&skip=%s' % (url, os_name,offset))
                
                cve_json = json.loads(cve_query.text)
                
                if len(cve_json['data']['search']) < 20:
                    is_next_page = False

                if page_num == 1:
                    master_json = cve_json
                    ###### For testing just use one page
                    # break ######## TODO : REMOVE ME 
                    continue

                master_json = _build_json(master_json, cve_json)
                if page_num == 1:
                    log.error(master_json)
        except Exception as exc: # Ask about error handling...
            print exc
            return

        #Cache results.
        try:
            with open('/var/cache/salt/minion/files/base/cve/%s.json' % os_name, 'w') as cache_file:
                json.dump(master_json, cache_file) 
		log.err("cached the json")
        except Exception as exc:
            print exc, 'wasn\'t able to cache the query.'
                    
    ret = {'Success':[], 'Failure':[]}   
    
    affected_pkgs = _get_cve_vulnerabilities(master_json)
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
    return ret
def _get_cve_vulnerabilities(query_results):
    '''
    Returns list of vulnerable package objects.
    '''
    
    vulnerable_pkgs = []

    
    if query_results['result'].lower() != 'ok':
        return
    
    for report in query_results['data']['search']:
        #data:search
        log.error(type(report))
	if type(report) == list:
            log.error(report[0])
        if 'affectedPackages' not in report['_source']:
            continue
        reporter = report['_source']['reporter']
        cve_list = report['_source']['cvelist']
        href = report['_source']['href']
        score = report['_source']['cvss']['score']
               

        for pkg in report['_source']['affectedPackages']:
            #data:search:_source:affectedPackages
            if pkg['OSVersion'] in ['any', str(__grains__['osmajorrelease'])]: # Check if os version matches grains
                vulnerable_pkg.append(vulnerablePkg(pkg['packageName'],pkg['packageVersion'], score, pkg['operator'], reporter, href, cve_list))   
        
    return vulnerable_pkgs

def _get_cache(ttl, url):
    '''
    If url contains valid cache, returns it,
        Else returns empty dictionary.
    '''

    if url.startswith('salt://'):
        path_to_json = url[len('salt://'):]
        ########## TODO ##############
    elif url.startswith('http://') or url.startswith('https://'):
        # Check if we have a valid cached version.
        path_to_cache = '/var/cache/salt/minion/files/base/cve/%s.json' % __grains__['os'].lower

        try:
            cached_time = os.path.getmtime(path_to_cache)
        except OSError:
            return {}
        if current_time - cached_time < ttl:
            try:
                with open(path_to_cache) as json_file:
                    return json.load(json_file)
            except Exception:
                return {}
        else:
            return {}

def _build_json(master_json, next_page):
    
    next_page_search = next_page['data']['search']
    master_json['data']['search'].append(next_page_search)
    return master_json


class vulnerablePkg:
    def __init__(self, pkg, pkg_version, score, operator, reporter, href, cve_list):
        self.pkg = pkg
        self.pkg_version = pkg_version
        self.score = score
        self.operator = operator
        self.href = href
        self.cve_list = cve_list
        self.reporter = reporter
    def get_pkg(self):
        return self.pkg
    def get_version(self):
        return self.pkg_version
    def get_score(self):
        return sel.score
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
            'score': self.get_score(),
            'cve_list': self.get_cve_list(),
            'pkg': self.get_pkg()
        }
