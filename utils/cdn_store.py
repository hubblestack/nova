'''
This module saves all cve scans for each distribution in a json file.
    Pulls cve scans from www.vulners.com/api/v3
'''

import requests
import json
from zipfile import ZipFile
import os
import sys

def main():
    '''
    Tries to save cve scans for inputs. Valid inputs are dis
    '''
    if len(sys.argv) == 1:
        print "No distributions were given to store."
    for distro in sys.argv[1:]:
        try:
            _save_json(distro)
        except Exception, e:
            print 'Error saving: %s' % distro
            print e


def _save_json(distro):
    '''
    Returns json from vulner.com api for specified distro.
    Throws exceptions when erros occured to be caught by main.
    '''
    for i, char in enumerate(distro):
        try:
            int(char)
            version = distro[i:].lower()
            distro_name = distro[:i].lower()
            print 'Getting cve\'s for %s version %s' % (distro_name, version)
            break
        except ValueError:
            continue
    else:
        raise Exception('No version number given in distro.')
    url_final = 'http://www.vulners.com/api/v3/archive/distributive/?os=%s&version=%s' % (distro_name, version)
    cve_query = requests.get(url_final)
    _zip = '%s_%s.zip' % (distro_name, version)
    _json = '%s_%s.json' % (distro_name, version)
    # Confirm that the request was valid.
    cve_query.raise_for_status()
    # Save vulners zip attachment in cache location and extract json
    with open(_zip, 'w') as zip_attachment:
        zip_attachment.write(cve_query.content)
    zip_file = ZipFile(_zip)
    zip_file.extractall(os.path.dirname(_zip))
    os.remove(_zip)
    with open(_json, 'r') as json_file:
        master_json = json.load(json_file)
    print 'Saved: %s' % _zip


main()
