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

import json
import os
from distutils.version import LooseVersion
from time import time as current_time
from zipfile import ZipFile
import copy
import re
import requests

import salt
import salt.utils



log = logging.getLogger(__name__)

def __virtual__():
    return not salt.utils.is_windows()

def audit(data_list, tags, verbose=False):

    os_name = __grains__['os'].lower()
    cached_zip = '/var/cache/salt/minion/cve_scan_cache/%s.zip' % (os_name)
    cached_json = '/var/cache/salt/minion/cve_scan_cache/%s.json' % (os_name)
    cache = {}
    #Make cache directory and all parent directories
    # if it doesn't exist.
    if not os.path.exists(os.path.dirname(cached_json)):
        os.makedirs(os.path.dirname(cached_json))

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
            cache = _get_cache(ttl, url, cached_json)
	    if cache:
		master_json = cache
    # If we don't find our module in the yaml
    if url is None:
        return {}

    # Query the api.
    if not cache:

        is_next_page = True
        page_num = 0
        query_size = 500

        # Hit the api, incrementing the page offset until
        #   we get all the results together in one dictionary.

        if 'vulners' in url:
            if not url.endswith('/'):
                url += '/'

            url_final = '%s?type=%s' % (url, os_name)
            cve_query = requests.get(url_final)
            if cve_query.status_code != 200:
                log.trace('Vulners request was not successful.')
            try:
                with open(cached_zip, 'w') as zip_attachment:
                    zip_attachment.write(cve_query.content)
                zip_file = ZipFile(cached_zip)
                zip_file.extractall(os.path.dirname(cached_zip))          
                os.remove(cached_zip)
		with open(cached_json, 'r') as json_file:
                    master_json = json.load(json_file)
            except IOError as ioe:
                log.error('The json was not able to be extracted from vulners.')
                raise ioe
        else:
            cve_query = requests.get(url)
            if cve_query.status_code != 200:
                log.trace('Vulners request was not successful.')
            master_json = json.loads(cve_query.text)

            #Cache results.
            try:
                with open(cached_json, 'w') as cache_file:
                    json.dump(master_json, cache_file)
            except IOError:
                log.error('The cve results weren\'t able to be cached')

    ret = {'Success':[], 'Failure':[]}

    affected_pkgs = _get_cve_vulnerabilities(master_json)
    local_pkgs = __salt__['pkg.list_pkgs'](versions_as_list=True)

    for local_pkg in local_pkgs:
        vulnerable = False
        if local_pkg in affected_pkgs:
            for local_version in local_pkgs[local_pkg]:
                for affected_obj in affected_pkgs[local_pkg]:
                    if _is_vulnerable(local_version, affected_obj.pkg_version, affected_obj.operator):
                        if not vulnerable:
                            vulnerable = affected_obj
                        else:
                            if _is_vulnerable(vulnerable.pkg_version, affected_obj.pkg_version, 'lt'):
                                vulnerable = affected_obj
            if vulnerable:
                ret['Failure'].append(vulnerable.report())
    return ret


def _get_cve_vulnerabilities(query_results):
    '''
    Returns list of vulnerable package objects.
    '''

    vulnerable_pkgs = {}

    # Get os version to only add vulnerabilites that apply to local system
    osmajorrelease = __grains__.get('osmajorrelease', None)
    osrelease = __grains__.get('osrelease', None)

    for report in query_results:

        #data:search
        reporter = report['_source']['reporter']
        cve_list = report['_source']['cvelist']
        href = report['_source']['href']
        score = report['_source']['cvss']['score']

        for pkg in report['_source']['affectedPackage']:
            #data:search:_source:affectedPackages
            if pkg['OSVersion'] in ['any', osmajorrelease, osrelease]: #Only use matching os
                pkg_obj = vulnerablePkg(pkg['packageName'], pkg['packageVersion'], score, \
                                            pkg['operator'], reporter, href, cve_list)
                if pkg_obj.pkg not in vulnerable_pkgs:
                    vulnerable_pkgs[pkg_obj.pkg] = [pkg_obj]
                else:
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

    for (order_index, local_version_str) in enumerate(local_version_split):

        local_version_obj = LooseVersion(local_version_str)
        affected_version_obj = LooseVersion(affected_version_split[order_index])

        #Check lower order bits if higher order are equal.
        if local_version == affected_version:
            continue

        #Return when highest order version is not equal.
        elif local_version_obj > affected_version_obj:
            return False
        elif local_version_obj < affected_version_obj:
            return True

    # The packages are equal if the code has gotten to here.
    #     Now return based on the operator.
    if operator == 'le':
        return True
    elif operator == 'lt':
        return False


def _get_cache(ttl, url, cache_path):
    '''
    If url contains valid cache, returns it,
        Else returns empty list.
    '''

    if url.startswith('http://') or url.startswith('https://'):
        # Check if we have a valid cached version.
        try:
            cached_time = os.path.getmtime(cache_path)
        except OSError:
            return []
        if current_time() - cached_time < ttl:
            try:
                with open(cache_path) as json_file:
                    loaded_json = json.load(json_file)
                    return loaded_json
            except IOError:
                return []
        else:
            return []


class vulnerablePkg:
    '''
    Object representing a vulnverable pkg for the current operating system.
    '''
    def __init__(self, pkg, pkg_version, score, operator, reporter, href, cve_list):
        self.pkg = pkg
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
