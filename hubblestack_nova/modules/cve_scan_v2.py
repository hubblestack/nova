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
    url: http://vulners.com/api/v3/archive/collection/
'''
from __future__ import absolute_import
import logging

import json
import os
from distutils.version import LooseVersion
from time import time as current_time
from zipfile import ZipFile
import re
import requests

import salt
import salt.utils



log = logging.getLogger(__name__)

def __virtual__():
    return not salt.utils.is_windows()

def audit(data_list, tags, verbose=False):

    os_version = __grains__.get('osmajorrelease', None)
    if os_version is None:
        os_version = __grains__.get('osrelease', None)
    os_name = __grains__['os'].lower()

    # The filenames will omit the period in version, if it exists.
    saved_filename = '%s_%s.json' % (os_name, os_version.replace('.', ''))
    cached_zip = '/var/cache/salt/minion/cve_scan_cache/%s.zip' % saved_filename
    cached_json = '/var/cache/salt/minion/cve_scan_cache/%s.json' % saved_filename
    cache = {}
    # Make cache directory and all parent directories if it doesn't exist.
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
            cache = _get_cache(ttl, cached_json)

    # If we don't find our module in the yaml
    if url is None:
        return {}

    if cache: # Valid cached file
        master_json = cache
    else: # Query the url for cve's
        if url.startswith('http://') or url.startswith('https://'):
            if 'vulners.com' in url:
                # Vulners api can only handles http:// requests from request.get
                if url.startswith('https'):
                    url.replace('https', 'http', 1)
                # Format the url for the request based on operating system.
                if url.endswith('/'):
                    url = url[:-1]
                url_final = '%s/api/v3/archive/distributive/?os=%s&version=%s' % (url, os_name, os_version)
                cve_query = requests.get(url_final)
                # Confirm that the request was valid.
                if cve_query.status_code != 200:
                    log.error('Vulners request was not successful.')
                # Save vulners zip attachment in cache location and extract json
                try:
                    with open(cached_zip, 'w') as zip_attachment:
                        zip_attachment.write(cve_query.content)
                    zip_file = ZipFile(cached_zip)
                    zip_file.extractall(os.path.dirname(cached_zip))
                    os.remove(cached_zip)
                    with open(cached_json, 'r') as json_file:
                        master_json = json.load(json_file)
                except IOError as ioe:
                    log.error('The json zip attachment was not able to be extracted from vulners.')
                    raise ioe
            else: # Not a vulners request, external source for cve's
                cve_query = requests.get(url)
                if cve_query.status_code != 200:
                    log.error('URL request was not successful.')
                    raise Exception('The url given is invalid.')
                master_json = json.loads(cve_query.text)
            #Cache results.
            try:
                with open(cached_json, 'w') as cache_file:
                    json.dump(master_json, cache_file)
            except IOError:
                log.error('The cve results weren\'t able to be cached')
        elif url.startswith('salt://'):
            # Cache the file
            cache_file = __salt__['cp.get_file'](url, cached_json)
            if cache_file:
                master_json = json.load(open(cache_file))
            else:
                raise IOError('The file was not able to be retrieved from the salt file server.')


    ret = {'Success':[], 'Failure':[]}

    affected_pkgs = _get_cve_vulnerabilities(master_json, os_version)
    # Dictionary of {pkg_name: list(pkg_versions)}
    local_pkgs = __salt__['pkg.list_pkgs'](versions_as_list=True)

    # Check all local packages against cve vulnerablities in affected_pkgs
    for local_pkg in local_pkgs:
        vulnerable = None
        if local_pkg in affected_pkgs:
            # There can be multiple versions for a single local package, check all
            for local_version in local_pkgs[local_pkg]:
                # There can be multiple cve announcements for a single package, check against all
                for affected_obj in affected_pkgs[local_pkg]:
                    affected_version = affected_obj.pkg_version
                    if _is_vulnerable(local_version, affected_version, affected_obj.operator):
                        # If the local pkg hasn't been found as vulnerable yet, vulnerable is None
                        if not vulnerable:
                            affected_obj.oudated_version = local_version
                            vulnerable = affected_obj
                        # If local_pkg has already been marked affected, vulnerable is set. We
                        #   want to report the most recent cve, so check if the new affected_pkg
                        #   version # is greater than the previously found vulnerability.
                        else:
                            if _is_vulnerable(vulnerable.pkg_version, affected_version, 'lt'):
                                # If affected_obj version is > vulnerable, reassign vulnerable
                                affected_obj.oudated_version = local_version
                                vulnerable = affected_obj
            if vulnerable:
                ret['Failure'].append(vulnerable.report())
    return ret


def _get_cve_vulnerabilities(query_results, os_version):
    '''
    Returns list of vulnerable package objects.
    '''

    vulnerable_pkgs = {}

    for report in query_results:

        #data:search
        reporter = report['_source']['reporter']
        cve_list = report['_source']['cvelist']
        href = report['_source']['href']
        score = report['_source']['cvss'].get('score', 0)

        for pkg in report['_source']['affectedPackage']:
            #data:search:_source:affectedPackages
            if pkg['OSVersion'] in ['any', os_version]: #Only use matching os
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
    if re.search(r'.el\d$', affected_version):
        affected_version = affected_version[:-4]
    if re.search(r'.el\d$', local_version):
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


def _get_cache(ttl, cache_path):
    '''
    If url contains valid cache, returns it,
        Else returns empty list.
    '''
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
        self.oudated_version = None


    def report(self):
        '''
        Return the dictionary of what should be reported in failures.
        '''
        uid = self.pkg + '-' + self.pkg_version
        report = {
            'href': self.href,
            'affected_version': self.pkg_version,
            'reporter': self.reporter,
            'score': self.score,
            'cve_list': self.cve_list,
            'affected_pkg': self.pkg,
            'local_version': self.oudated_version
        }
        return {uid: report}

