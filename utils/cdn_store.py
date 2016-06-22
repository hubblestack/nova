'''
This module saves all cve scans for each distribution in a json file.
    Pulls cve scans from www.vulners.com/api/v3
'''

import requests
import json
from zipfile import ZipFile
import os

def main():
    '''
    Calls helpers and saves results.
    '''
    distro_list = ['centos', 'ubuntu', 'debian', 'redhat']
    for distro in distro_list:
        _save_json(distro)
        


def _save_json(os_name):
    '''
    Returns json from vulner.com api for specified os_name
    '''
    url_final = 'http://www.vulners.com/api/v3/archive/collection/?type=%s' % os_name
    cve_query = requests.get(url_final)
    _zip = '%s.zip' % os_name
    _json = '%s.json' % os_name
    # Confirm that the request was valid.
    if cve_query.status_code != 200:
        log.error('Vulners request was not successful.')
    # Save vulners zip attachment in cache location and extract json
    try:
        with open(_zip, 'w') as zip_attachment:
            zip_attachment.write(cve_query.content)
        zip_file = ZipFile(_zip)
        zip_file.extractall(os.path.dirname(_zip))
        os.remove(_zip)
        with open(_json, 'r') as json_file:
            master_json = json.load(json_file)
        print 'Saved: %s.json\n' % os_name
    except Exception, e:
        print 'Error saving: %s' % os_name
        print e

main()
