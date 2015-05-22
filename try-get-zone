#!/bin/sh

set -e 

# Tries to download a DNS zone file by testing one after the other all
# its authoritative name servers. 

# Stephane Bortzmeyer <bortzmeyer@nic.fr> + code from Tristan Le Guern
# <tleguern@bouledef.eu>

sigint() {
	echo Bye
	exit 1
}

trap sigint INT

unset LANG
unset LC_MESSAGES

if [ -z "$1" ]; then
   echo "Usage: $0 zone [storage-directory]" >&2
   exit 1
fi

# Where to put the downloaded zone
if [ -z "$2" ]; then
    if [ -d $HOME/System/DNS/zonefiles ]; then
	use_date=1
	basedir=$HOME/System/DNS/zonefiles 
    else
	use_date=0
	basedir=$HOME/tmp
	if [ ! -d $basedir ]; then
	    mkdir $basedir
	fi
    fi
else
    use_date=0
    basedir=$2
fi

zone=$1
if [ $zone != "." ]; then
    qualifiedzone=${zone}.
fi
if nameservers=$(dig +nodnssec +short NS ${qualifiedzone}) && [ -z "$nameservers" ]; then
    echo "Unknown zone $zone or DNS resolution not working" >&2
    exit 1
fi
tmp=$(mktemp /tmp/.try-get-zone.XXXXXXXXXX)
for ns in $nameservers; do
    if ! dig @${ns} AXFR ${qualifiedzone} > $tmp 2>&1; then
	echo "Error with ${ns}" >&2
	continue
    fi
    if ! egrep "Transfer failed|connection timed out|Name or service not known|connection refused|network unreachable|host unreachable|end of file|communications error|couldn't get address" $tmp > /dev/null; then 
	if [ $use_date = 1 ]; then
	    filename=${basedir}/${zone}-$(date +%Y-%m-%d).db
        else
	    filename=${basedir}/${zone}.db
        fi
	if [ -e $filename ]; then
	    echo "$filename already exists, leaving zone in $tmp" >&2
	    exit 1
	fi
	# TODO: some escaping, if the zone name contains funny characters?
	mv $tmp $filename
	echo "Got $zone from $ns, saved in $filename"
	exit 0
    fi
done
echo "No willing nameservers from which to transfer $zone" >&2
exit 2
