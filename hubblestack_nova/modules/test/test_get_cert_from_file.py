import imp

openssl = imp.load_source('openssl', '../openssl.py')

assert openssl._get_cert_from_file('random/file') == None
