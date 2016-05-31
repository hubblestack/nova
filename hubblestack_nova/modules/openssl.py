from __future__ import absolute_import
import logging

import fnmatch
import copy
import salt.utils

import ssl

try:
    import OpenSSL
    _HAS_OPENSSL = True
except ImportError:
    _HAS_OPENSSL = False

log = logging.getLogger(__name__)

__tags__ = None
__data__ = None

def __virtual__():
    if salt.utils.is_windows():
        return False, 'This audit module only runs on linux'
    if not salt.utils.which('iptables'):
        return (False, 'The iptables execution module cannot be loaded: iptables not installed.')
    if not _HAS_OPENSSL:
        return (False, 'The python-OpenSSL library is missing')
    return True


def _merge_yaml(ret, data):
    if 'openssl' not in ret:
        ret['openssl'] = {}
    for key, val in data.get('openssl', {}).iteritems():
        ret['openssl'].append({key: val})
    return ret


def _get_tags(data):
    ret = {}
    for audit_dict in data.get('openssl', {}):
        pprint(audit_dict)
        for audit_id, audit_data in audit_dict.iteritems():
            tags_dict = audit_data.get('data', {})
            tag = tags_dict.pop('tag')
            if tag not in ret:
                ret[tag] = []
            formatted_data = copy.deepcopy(tags_dict)
            formatted_data['tag'] = tag
            formatted_data['module'] = 'openssl'
            formatted_data.update(audit_data)
            formatted_data.pop('data')
            ret[tag].append(formatted_data)
    return ret


def _load_x509(source, port=443, from_file=False):
    if not from_file:
        cert = _load_x509_from_endpoint(source, port)
    else:
        cert = _load_x509_from_file(source)
    return cert


def _load_x509_from_endpoint(server, port=443):
    try:
        cert = ssl.get_server_certificate((server, port))
    except Exception:
        cert = None
    if not cert:
        return None

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    except OpenSSL.crypto.Error:
        x509 = None
    return x509


def _load_x509_from_file(cert_file_path):
    try:
        cert_file = open(cert_file_path)
    except IOError:
        return None

    try:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_file.read())
    except OpenSSL.crypto.Error:
        x509 = None
    return x509
