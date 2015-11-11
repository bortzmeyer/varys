#!/usr/bin/python

""" Python code to analyze a DNS periodic measurement, such as one launched by Varys.

You'll need an API key in ~/.atlas/auth.

Stephane Bortzmeyer <bortzmeyer@nic.fr>
"""

import json
import sys
import time
import string
import base64
import getopt
import os
import collections

# DNS Python http://www.dnspython.org/
import dns.message

import RIPEAtlas

# Default values
verbose = False

class Set():
    def __init__(self):
        self.total = 0

def usage(msg=None):
    if msg:
        print >>sys.stderr, msg
    print >>sys.stderr, "Usage: %s measurement-ID" % sys.argv[0]
    print >>sys.stderr, """Options are:
    --help or -h : this message
    --verbose or -v : more talkative"""

def utc_string(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))
    
try:
    optlist, args = getopt.getopt (sys.argv[1:], "hv",
                               ["help", "verbose"])
    for option, value in optlist:
        if option == "--help" or option == "-h":
            usage()
            sys.exit(0)
        elif option == "--verbose" or option == "-v":
            verbose = True
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

measurement_id = args[0]

filename = "./%s.json" % measurement_id
measurement = RIPEAtlas.Measurement(data=None, id=measurement_id)
if os.path.exists(filename):
    results = json.load(open(filename))
else:
    results = measurement.results(wait=False)

probes = 0
tests = 0
successes = 0
errors = 0

sets = collections.defaultdict(Set)
probes_sets = collections.defaultdict(Set)
rcodes_sets = collections.defaultdict(Set)
qnames_sets = collections.defaultdict(Set)
types_sets = collections.defaultdict(Set)

start_time = sys.maxint
stop_time = 0

# TODO check result["msm_name"] is "Tdig"?
for result in results:
    probe_id = result["prb_id"]
    probes_sets[probe_id].total += 1
    for result_i in result["resultset"]:
        tests += 1
        if result_i["time"] < start_time:
            start_time = result_i["time"] 
        if result_i["time"] > stop_time:
            stop_time = result_i["time"] 
        if not result_i.has_key("error"):
            successes += 1 
            answer = result_i["result"]["abuf"] + "=="
            content = base64.b64decode(answer)
            msg = dns.message.from_wire(content)
            rcodes_sets[msg.rcode()].total += 1
            if msg.rcode() == dns.rcode.NOERROR:
                for rrset in msg.question:
                    qnames_sets[rrset.name].total += 1
                for rrset in msg.answer:
                    types_sets[rrset[0].rdtype].total += 1
                    for rdata in rrset:
                        pass
        else:
            errors += 1

if len(qnames_sets) > 1:
    print >>sys.stderr, "More than one domain name in queries!"
    sys.exit(1)    
if verbose:
    print "Queries for \"%s\": %i results on %i probes, %i errors" % (qnames_sets.keys()[0], tests, len(probes_sets), \
                                                                  errors)
    print "From %s to %s (UTC)" % (utc_string(start_time), utc_string(stop_time))
    print "Return codes:"
    for rcode in rcodes_sets:
        print "%s: %s (%.2f %%)" % (dns.rcode.to_text(rcode), rcodes_sets[rcode].total, rcodes_sets[rcode].total*100.0/successes)
    print "Response types:"
    for type in types_sets:
        print "%s: %s" % (dns.rdatatype.to_text(type), types_sets[type].total)
