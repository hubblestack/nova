'''
A simple script for testing the syntax of the files.
It uses just the messages of the reading and parsing exceptions in the yaml library.
Run the script multiple times until you solve all the syntax errors in the file.

Usage: check_yaml.py <yaml_file_to_check>
'''


import yaml
import sys

if len(sys.argv) != 2:
    print 'Usage: %s <yaml_file_to_check>' % (sys.argv[0])
    exit(1)

try:
    f = open(sys.argv[1])
except IOError as e:
    print "I/O error(%s): %s" % (e.errno, e.strerror)
    exit(1)

try:
    yaml.safe_load(f)
    print 'YAML syntax is OK'
    exit(0)
except yaml.reader.ReaderError as e:
    print "YAML reader error: %s" % (e)
    exit(1)
except yaml.parser.ParserError as e:
    print "YAML parser error: %s" % (e)
    exit(1)
