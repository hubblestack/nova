import urllib2
import json

def main():
    distro_list = ['centos', 'ubuntu', 'debian']
    for distro in distro_list:
        unencoded_json = get_json(distro)
        json.dump(unencoded_json, open('distro_json/%s.json' % distro, 'w')) ## Path to directory here
        print 'Saved: %s.json' % distro

def get_json(os_name):
    '''
    Returns json from vulner.com api for specified os_name
    '''
    is_next_page = True
    page_num = 0
    query_size = 500

    while is_next_page:
        offset = page_num * query_size
        page_num += 1 
        print "Grabbing page: %s of %s" % (page_num, os_name)
        url_final = 'http://vulners.com/api/v3/search/lucene/?query=type:%s&skip=%s&size=%s' % (os_name, offset, query_size)
        cve_query = urllib2.urlopen(url_final)
        cve_json = json.load(cve_query)
        
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


def _build_json(master_json, current_page):
    '''
    Adds all the search elements from current page
        to our master json file and returns
    '''
    current_page_search = current_page['data']['search']
    master_json['data']['search'].extend(current_page_search)
    return master_json

main()