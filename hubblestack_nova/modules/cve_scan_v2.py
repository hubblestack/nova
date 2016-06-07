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
import copy
import re

import json
import os

from distutils.version import LooseVersion
from datetime import datetime
from time import time as current_time

log = logging.Logger(__name__)

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
    local_pkgs = __salt__['pkg.list_pkgs'](versions_as_list=True)
    
    for pkgObj in affected_pkgs:
##TODO: eventually should switch the loop to go through just the local_pkgs and check if it\'s in the affected packages.. much more effecient, but have to restructure affected_packages to be dictionary of pkg_name --> pkgObj
        if pkgObj.get_pkg() in local_pkgs:
            affected_version = pkgObj.get_version()
            # In order to do compare LooseVersions, eliminate trailing 'el<#>'
            if re.search('.el\d$', affected_version):
                affected_version = affected_version[:-4]
            for local_version in local_pkgs[pkgObj.get_pkg()]:
                # In order to do compare LooseVersions, eliminate trailing 'el<#>'
                if re.search('.el\d$', local_version):
                    local_version = local_version[:-4]
                if _is_vulnerable(local_version, affected_version, pkgObj.get_operator()):
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
        
        for pkg in report['_source']['affectedPackage']:
            #data:search:_source:affectedPackages
            
            if pkg['OSVersion'] in ['any', str(__grains__['osmajorrelease'])]: # Check if os version matches grains
                pkgObj = vulnerablePkg(pkg['packageName'], pkg['packageVersion'], score, pkg['operator'], reporter, href, cve_list)
                vulnerable_pkgs.append(pkgObj)   
    return vulnerable_pkgs

def _is_vulnerable(local_version, affected_version, operator):
    '''
    Given two version strings, and operator
        returns whether the package is vulnerable or not.
    '''
    # Get rid of prefix if version number has one, ex '1:3.4.52'
    if ':' in local_version:
         local_version = local_version[local_version.index(':')+1:]
    #Compare from higher order to lower order based on '-' split.
    local_version_split = local_version.split('-')
    affected_version_split = affected_version.split('-')
    for order_index in range(len(local_version_split)):
        local_version_obj = LooseVersion(local_version_split[order_index])
        affected_version_obj = LooseVersion(affected_version_split[order_index])
        #Check lower order bits if higher order are equal.
        if local_version == affected_version:
            continue
        #Return when highest order version is not equal.

        elif local_version_obj > affected_version_obj:
            return False
        elif local_version_obj < affected_version_obj:
            return True
        
    else:
        # The packages are equal if the code has gotten to here.
        #     Now return based on the operator.
        if operator == 'le':
            return True
        elif operator == 'lt':
            return False        
    



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
        self.pkg_version = pkg_version
        self.score = score
        if operator not in ['lt', 'le']:
            log.error('pkg:%s contains an operator that\'s not supported and waschange to < ')
            operator = 'lt'
        self.operator = operator
        self.href = href
        self.cve_list = cve_list
        self.reporter = reporter
    def get_pkg(self):
        return self.pkg
    def get_version(self):
        return self.pkg_version
    def get_score(self):
        return self.score
    def get_operator(self):
        return self.operator
    def get_cve_list(self):
        def_copy = copy.copy(self.cve_list)
        return def_copy
    def get_reporter(self):
        return self.reporter
    def get_href(self):
        return self.href
    def report(self):
        return {
            'href': self.get_href(),
            'version': self.get_version(),
            'reporter': self.get_reporter(),
            'score': self.get_score(),
            'cve_list': self.get_cve_list(),
            'pkg': self.get_pkg()
        }
