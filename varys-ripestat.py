#!/usr/bin/env python

import urllib2
import sys

url = "https://stat.ripe.net/data/%s/data.json?resource=%s"
services = ["network-info", "prefix-overview", "routing-status", "visibility", "bgp-state"]

if len(sys.argv) <= 1:
    print >>sys.stderr, "Usage: %s resource ..." % sys.argv[0]

for resource in sys.argv[1:]:
    print resource
    print ""
    for service in services:
        print service
        request = urllib2.Request(url % (service, resource))
        conn = urllib2.urlopen(request)
        print conn.read()
        print ""
    print ""
    print "-----------------"
    print ""
