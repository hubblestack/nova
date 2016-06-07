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
import requests


import json
import os

from distutils.version import LooseVersion
from datetime import datetime
from time import time as current_time

log = logging.getLogger(__name__)

def __virtual__():
    return True

def audit(data_list, tags, verbose=False):
    global cache_path
    os_name = __grains__['os'].lower() 
    cache_path = '/var/cache/salt/minion/files/base/cve/%s.json' % (os_name)
    cache = {}
    #Make cache directory and all parent directories
    # if it doesn't exist.
    if not os.path.exists(os.path.dirname(cache_path)):
        os.makedirs(os.path.dirname(cache_path))
  
    # Go through data_list and check if 
    #   < 1 day old cache is in any yaml file
    for data in data_list:

        if 'cve_scan_v2' in data:

            ttl = data['cve_scan_v2']['ttl']
            url = data['cve_scan_v2']['url']
            if url.startswith('https'):
                url.replace('https', 'http', 1)
            cache = _get_cache(ttl, url)
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
                url_final = '%s?query=type:%s&order:last year&skip=%s' % (url,os_name, offset)
                log.error(url_final)
                cve_query = requests.get(url_final)
                cve_json = json.loads(cve_query.text)
                
                if len(cve_json['data']['search']) < 20:
                    is_next_page = False

                if page_num == 1:
                    master_json = cve_json
                    ###### For testing just use one page
                    # break ######## TODO : REMOVE ME 
                    continue
              
                master_json = _build_json(master_json, cve_json)
        except Exception as exc: # Ask about error handling...
            return

        #Cache results.
        try:
            with open(cache_path, 'w') as cache_file:
                json.dump(master_json, cache_file) 
        except IOError as exc:
            log.error('The results weren\'t able to be cached')
                    
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
        
        reporter = report['_source']['reporter']
        cve_list = report['_source']['cvelist']
        href = report['_source']['href']
        score = report['_source']['cvss']['score']
        
        #Scan includes affectedSoftware, we only support pkgs.            
        if 'affectedPackage' not in report['_source']:
            continue

        for pkg in report['_source']['affectedPackage']:
            #data:search:_source:affectedPackages
            
            if pkg['OSVersion'] in ['any', str(__grains__['osmajorrelease'])]: # Check if os version matches grains
                pkgObj = vulnerablePkg(pkg['packageName'], pkg['packageVersion'], score, pkg['operator'], reporter, href, cve_list)
                vulnerable_pkgs.append(pkgObj)   
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
        try:
            cached_time = os.path.getmtime(cache_path)
        except OSError:
            return {}
        if current_time() - cached_time < ttl:
            log.error("please print")
            time.sleep(2)
            try:
                with open(cache_path) as json_file:
                    json_load = json.load(json_file)
                    return json_load
            except IOError as e: 
                return {}
        else:
            return {}

def _build_json(master_json, next_page):
    
    next_page_search = next_page['data']['search']
    master_json['data']['search'].extend(next_page_search)
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
