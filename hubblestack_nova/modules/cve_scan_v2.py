'''

:maintainer: HubbleStack
:maturity: 20160214
:platform: Linux
:requires: SaltStack

Using the vulners.com api, this cve scan module checks your machine
for packages with known and reported vulnerabilities.

Future addition:
    Using salt:// url as the source of the vulnerabilites
    Using a more efficient caching method so we just add on new
        vulnerabilities and not re-query an entire year back
    Restructure loop to go through local pkgs and check if in known
        vulnerabilties, not vice versa like it is now


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

log = logging.getLogger(__name__)

def __virtual__():
    return not salt.utils.is_windows()

def audit(data_list, tags, verbose=False):

    os_name = __grains__['os'].lower() 
    cache_path = '/var/cache/salt/minion/cve_scan_cache/%s.json' % (os_name)
    cache = {}
    #Make cache directory and all parent directories
    # if it doesn't exist.
    if not os.path.exists(os.path.dirname(cache_path)):
        os.makedirs(os.path.dirname(cache_path))
    
    ttl = None
    url = None

    # Go through yaml to check for cve_scan_v2,
    #    if its present, check for a cached version 
    #    of the scan.
    for data in data_list:

        if 'cve_scan_v2' in data:

            ttl = data['cve_scan_v2']['ttl']
            url = data['cve_scan_v2']['url']
            # Requests only handles http:// requests   
            if url.startswith('https'):
                url.replace('https', 'http', 1)
            cache = _get_cache(ttl, url, cache_path)
            if cache.get('result', None) == 'OK':
                master_json = cache
                break

    # If we don't find our module in the yaml
    if url == None:
        return {} 

    # Query the api.
    if not cache:

        is_next_page = True
        page_num = 0
        query_size = 5000
        
        # Hit the api, incrementing the page offset until 
        #   we get all the results together in one dictionary.

        while is_next_page:
            
            offset = page_num * query_size
            page_num += 1 
            url_final = '%s?query=type:%s&order:last year&skip=%s&size=%s' % (url, os_name, offset, query_size)
            cve_query = requests.get(url_final)
            cve_json = json.loads(cve_query.text)
            
            # Default number of searches per page is 20 so 
            #    if we have less than that we know this is 
            #    our last page.
            if len(cve_json['data']['search']) < query_size:
                is_next_page = False

            # First page is beginning of master_json that we build on
            if page_num == 1:
                master_json = cve_json
                continue
            
            master_json = _build_json(master_json, cve_json)
    

        #Cache results.
        try:
            with open(cache_path, 'w') as cache_file:
                json.dump(master_json, cache_file) 
        except IOError as exc:
            log.error('The results weren\'t able to be cached')
                    
    ret = {'Success':[], 'Failure':[]}   
    
    affected_pkgs = _get_cve_vulnerabilities(master_json)
    local_pkgs = __salt__['pkg.list_pkgs'](versions_as_list=True)
    
    for local_pkg in local_pkgs:
        vulnerable = False
        if local_pkg in affected_pkgs:
            vulnerable_pkg_list = affected_pkgs[local_pkg]
            for local_version in local_pkgs[local_pkg]:
                for affected_obj in affected_pkgs[local_pkg]: 
                    if _is_vulnerable(local_version, affected_obj.pkg_version, affected_obj.operator):
                        if not vulnerable:
                            vulnerable = affected_obj
                        else:
                            if _is_vulnerable(vulnerable.pkg_version, affected_obj.pkg_version, 'lt'):
                                vulnerable = affected_obj
            if not vulnerable:
                if local_pkg not in ret['Success']:
                    ret['Success'].append(local_pkg)
            else:
                ret['Failure'].append(vulnerable.report()) 
        else:
            if local_pkg not in ret['Success']:
                ret['Success'].append(local_pkg)
    ret['Success'].sort()
    return ret            


def _get_cve_vulnerabilities(query_results):
    '''
    Returns list of vulnerable package objects.
    ### TODO ### return map of pkg->pkg_obj for more efficient loop structure
    '''
    
    vulnerable_pkgs = {}

    # Make sure query was successful
    if query_results['result'].lower() != 'ok':
        return
    
    # Get os version to only add vulnerabilites that apply to local system 
    osmajorrelease = __grains__.get('osmajorrelease', None)
    osrelease = __grains__.get('osrelease', None)

    for report in query_results['data']['search']:
               
        #data:search
        reporter = report['_source']['reporter']
        cve_list = report['_source']['cvelist']
        href = report['_source']['href']
        score = report['_source']['cvss']['score']
        
        for pkg in report['_source']['affectedPackage']:
            #data:search:_source:affectedPackages
            if pkg['OSVersion'] in ['any', osmajorrelease, osrelease]: # Check if os version matches grains
                pkg_obj = vulnerablePkg(pkg['packageName'], pkg['packageVersion'], score, pkg['operator'], reporter, href, cve_list)
                if pkg_obj.pkg not in vulnerable_pkgs:
                    vulnerable_pkgs[pkg_obj.pkg] = [pkg_obj]
                else:
                    #TODO add some logic that checks that this vulnerability has not been added already, logic may just include an equals condition in the vulnerablePkg class
                    vulnerable_pkgs[pkg_obj.pkg].append(pkg_obj)
                    
    return vulnerable_pkgs


def _is_vulnerable(local_version, affected_version, operator):
    '''
    Given two version strings, and operator
        returns whether the package is vulnerable or not.
    '''
    # Get rid of prefix if version number has one, ex '1:3.4.52'
    if ':' in local_version:
         _, _, local_version = local_version.partition(':')

    # In order to do compare LooseVersions, eliminate trailing 'el<#>'
    if re.search('.el\d$', affected_version):
        affected_version = affected_version[:-4]
    if re.search('.el\d$', local_version):
        local_version = local_version[:-4]

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
    

def _get_cache(ttl, url, cache_path):
    '''
    If url contains valid cache, returns it,
        Else returns empty dictionary.
    ###TODO### more effective caching method, return
            historic data and only query for new vulnerabilites
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
                    loaded_json = json.load(json_file)
                    return loaded_json
            except IOError as e: 
                return {}
        else:
            return {}


def _build_json(master_json, current_page):
    '''
    Adds all the search elements from current page
        to our master json file and returns
    '''
    current_page_search = current_page['data']['search']
    master_json['data']['search'].extend(current_page_search)
    return master_json


class vulnerablePkg:
    '''
    Object representing a vulnverable pkg for the current operating system.
    '''
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


    def get_cve_list(self):
        def_copy = copy.copy(self.cve_list)
        return def_copy


    def report(self):
        return {
            'href': self.href,
            'affected_version': self.pkg_version,
            'reporter': self.reporter,
            'score': self.score,
            'cve_list': self.get_cve_list(),
            'affected_pkg': self.pkg
        }
