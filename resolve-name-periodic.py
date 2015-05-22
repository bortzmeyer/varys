#!/usr/bin/python

""" Python code to start a RIPE Atlas periodic UDM (User-Defined
Measurement). This one is for running DNS to resolve a name from many
places, in order to survey local cache poisonings, effect of
hijackings and other DNS rejuvenation effects.

You'll need an API key in ~/.atlas/auth.

After launching the measurement, you have to download the results and
to analyze them.

Stephane Bortzmeyer <bortzmeyer@nic.fr>
"""

import json
import sys
import time
import datetime
import base64
import getopt
import collections

# DNS Python http://www.dnspython.org/
import dns.message

import RIPEAtlas

requested = 500
qtype = 'A'
duration = datetime.timedelta(hours=24)

class Set():
    def __init__(self):
        self.total = 0

def usage(msg=None):
    if msg:
        print >>sys.stderr, msg
    print >>sys.stderr, "Usage: %s domain-name" % sys.argv[0]
    # TODO: allow longer durations
    # TODO: allow DO/notDO
    # TODO: allow to specify the interval (240 s default?)
    print >>sys.stderr, """Options are:
    --help or -h : this message
    --type or -t : query type (default is %s)
    --requested=N or -r N : requests N probes (default is %s)
    """ % (qtype, requested)

try:
    optlist, args = getopt.getopt (sys.argv[1:], "r:t:h",
                               ["requested=", "type=", "help"])
    for option, value in optlist:
        if option == "--type" or option == "-t":
            qtype = value
        elif option == "--requested" or option == "-r":
            requested = int(value)
        elif option == "--help" or option == "-h":
            usage()
            sys.exit(0)
        else:
            # Should never occur, it is trapped by getopt
            usage("Unknown option %s" % option)
            sys.exit(1)
except getopt.error, reason:
    usage(reason)
    sys.exit(1)

if len(args) != 1:
    usage()
    sys.exit(1)

domainname = args[0]

start_time_obj = datetime.datetime.utcnow()
end_time_obj = start_time_obj + duration
# Be careful, Atlas requires an integer in the JSON object
# We do not use strftime('%s')) because
# http://bugs.python.org/issue12750 and
# http://stackoverflow.com/questions/11743019/convert-python-datetime-to-epoch-with-strftime
start_time_unix = int((start_time_obj - datetime.datetime(1970,1,1)).total_seconds())
end_time_unix = int((end_time_obj - datetime.datetime(1970,1,1)).total_seconds())

data = { "definitions": [{ "type": "dns", "af": 4, "is_oneoff": False, 
                           "use_probe_resolver": True, "query_argument": domainname,
                           "description": "DNS resolution of %s" % domainname,
                           "query_class": "IN", "query_type": qtype, 
                           "recursion_desired": True}],
         "probes": [{"requested": requested, "type": "area", "value": "WW"}],
         "start_time": start_time_unix,
         "stop_time": end_time_unix}
print data
  
measurement = RIPEAtlas.Measurement(data,
                                    lambda delay: sys.stderr.write(
        "Sleeping %i seconds...\n" % delay))

print "Measurement #%s for %s/%s uses %i probes" % \
      (measurement.id, domainname, qtype, measurement.num_probes)

