#!/bin/sh

# Rough personal tool: use at your own risk

# Gather information about a domain name. Mostly used to get data
# during a domain name hijacking. See the README for details.
# Stephane Bortzmeyer <bortzmeyer@nic.fr>

# Varys does not try to detect if you have the required commands. If
# you don't, you'll get an error message in the output file, period.

# TODO
# * curl to retrieve the Web pages

# Parameters
BASEDIR=$HOME/System/DNS/varys
CODEDIR=$HOME/System/DNS/varys-code
ATLASCODE=$HOME/Programmation/RIPE-Atlas/ripe-atlas-community-contrib
export PYTHONPATH=$ATLASCODE
export TZ=UTC
DIG="dig +nodnssec +noedns +bufsize=0 +retries=3"

# Settings that you can modify on the command-line

# Requires credentials in ~/.atlas/auth
# Depends on the RIPEAtlas Python package https://github.com/RIPE-Atlas-Community/ripe-atlas-community-contrib
atlas=0 # Not on by default because it takes time

recursive=0 # Not on by default because it may pollute caches

# Depends on the local DNSZviz executable
# DNSviz http://dnsviz.net/ and https://github.com/dnsviz/
dnsviz=1

# Depends on the local Zonemaster executable
# https://github.com/dotse/zonemaster
zonemaster=1

# Requires credentials in ~/.isc-dnsdb-query.conf plus the CLI tool from DNSDB
dnsdb=1

# Requires credentials in ~/.circl.conf
circl=1

# Requires credentials in ~/.flint.conf
dns360=1

ipinfo=1

# TODO: query the DNS LGs

# Where to put the downloaded zone
if [ ! -d $BASEDIR ]; then
    echo "Cannot find data directory $BASEDIR" >&2
    exit 1
fi
if [ ! -d $CODEDIR ]; then
    echo "Cannot find code directory $CODEDIR" >&2
    exit 1
fi

orig=$@
temp=$(getopt -o "ardilzcv" -- "$@")
if [ $? != 0 ]; then
    echo "Usage: $0 [-a] [-r] [-d] [-i] |-z] [-v] domain-name" >&2
    exit 1
fi
eval set -- "$temp"
while true ; do
        case "$1" in
                -a) atlas=1; shift;;
                -r) recursive=1; shift;;
                -d) dnsdb=0; shift;;
		-l) circl=0; shift;;
		-c) dns360=0; shift;;
                -i) ipinfo=0; shift;;
		-z) zonemaster=0; shift;;
		-v) dnsviz=0; shift;;
                --) shift ; break ;;
                *) echo "Internal error!" >&2 ; exit 1 ;;
        esac
done

if [ -z "$1" ]; then
   echo "Usage: $0 domain-name [host-name]" >&2
   exit 1
fi
if [ ! -z "$3" ]; then
   echo "Usage: $0 domain-name [host-name]" >&2
   exit 1
fi

if [ $atlas = 1 ] && [ ! -d $ATLASCODE ]; then
    echo "Cannot find Atlas directory $ATLASCODE" >&2
    exit 1
fi

# TODO: authorize IDN
domain=$(echo $1 | tr 'A-Z' 'a-z')
host=$(echo $2 | tr 'A-Z' 'a-z')
if [ "$host" = "" ]; then
    host=$domain
fi
date=$(date -u --rfc-3339=seconds | sed 's/ /T/')
cd $BASEDIR
if ! git status > /dev/null 2>&1; then
    echo "$PWD is not a git working copy" >&2
    exit 1
fi
dir=$domain/$date
mkdir -p $dir || (echo "Cannot create $dir" >&2; exit 1)
git add $dir || (echo "Cannot git add $dir" >&2; exit 1)
cd $dir
printf "Analysis of \"$domain\" on $(date) with options \"$orig\" \n" > README
printf "Add here any comments or analysis about these data\n**************\n\n" >> README
git add README

(date; hostname -f; id; ifconfig) > metadata.out 2>&1
git add metadata.out

echo "" >> metadata.out
echo "External IP address from ipify.org:" >> metadata.out
# https://www.ipify.org/
externalip=$(curl -s 'https://api.ipify.org/')
if [ "$externalip" != "" ]; then
    printf "%s\n" $externalip >> metadata.out 2>&1
    dig -x "$externalip" >> metadata.out 2>&1
    whois "$externalip" >> metadata.out 2>&1
else
    echo "Failure when contacting ipify.org" >> metadata.out
fi

(date; echo ""; whois $domain) > whois.out 2>&1
git add whois.out

${DIG} NS $domain >  dns-domain.out 2>&1
${DIG} SOA $domain >>  dns-domain.out 2>&1
${DIG} A $domain >>  dns-domain.out 2>&1
${DIG} AAAA $domain >>  dns-domain.out 2>&1
git add dns-domain.out

# https://github.com/bortzmeyer/check-soa
(date; echo ""; check-soa -i $domain) > check-soa.out 2>&1
git add check-soa.out 

ns=$(${DIG} +short NS $domain | head -n 1)
if [ -z "$ns" ]; then
    echo "Cannot find name servers for $domain" > dns-domain-auth.out 
else
    ${DIG} @$ns NS $domain >  dns-domain-auth.out 2>&1
    ${DIG} @$ns SOA $domain >>  dns-domain-auth.out 2>&1
    ${DIG} @$ns A $domain >>  dns-domain-auth.out 2>&1
    ${DIG} @$ns AAAA $domain >>  dns-domain-auth.out 2>&1
fi
git add dns-domain-auth.out 

if [ $ipinfo = 1 ]; then
    # TODO: we use tail if there is a CNAME chain, may be we should use host instead.
    # TODO: handle the case of multiple IP addresses
    ipaddress=$(${DIG} +short A $host | tail -n 1)
    ip6address=$(${DIG} +short AAAA $host | tail -n 1)
    if [ -z "$ipaddress" ]; then
	ipinfo=0
    fi
fi
parent=$(find-parent.py -a $domain)

${DIG} NS $parent >  dns-parent-domain.out 2>&1
${DIG} SOA $parent >>  dns-parent-domain.out 2>&1
${DIG} A $parent >>  dns-parent-domain.out 2>&1
${DIG} AAAA $parent >>  dns-parent-domain.out 2>&1
git add dns-parent-domain.out 

nsparent=$(${DIG} +short NS $parent | head -n 1)

${DIG} @$nsparent NS $domain >  dns-domain-at-parent.out 2>&1
${DIG} @$nsparent SOA $domain >>  dns-domain-at-parent.out 2>&1
${DIG} @$nsparent A $domain >>  dns-domain-at-parent.out 2>&1
${DIG} @$nsparent AAAA $domain >>  dns-domain-at-parent.out 2>&1
git add dns-domain-at-parent.out 


mkdir zones
try-get-zone $domain zones > zones/output-and-errors.out 2>&1 && git add zones/${domain}.db
# TODO : $parent ends with a dot, which confuses try-get-zone
try-get-zone $parent zones >> zones/output-and-errors.out 2>&1 && git add zones/${parent}.db
git add zones

ntptrace > ntptrace.out 2>&1
git add ntptrace.out

if [ $ipinfo = 1 ]; then
    if [ $host != $domain ]; then
	printf "%s\n" "IP information for $host ($ipaddress $ip6address)" > ipinfo.out
    else
	printf "%s\n" "IP information ($ipaddress $ip6address)" > ipinfo.out
    fi
    date >> ipinfo.out
    varys-ripestat.py $ipaddress >> ipinfo.out 2>&1
    whois $ipaddress >> ipinfo.out 2>&1
    traceroute -m 30 $ipaddress >> ipinfo.out 2>&1
    if [ ! -z "$ip6address" ]; then
	varys-ripestat.py $ip6address >> ipinfo.out 2>&1
	whois $ip6address >> ipinfo.out 2>&1
	traceroute6 -m 30 $ip6address >> ipinfo.out 2>&1
    fi
    git add ipinfo.out
fi

if [ $dnsdb = 1 ]; then
    date > dnsdb.out 
    isc-dnsdb-query rrset $domain/NS >> dnsdb.out 2>&1
    isc-dnsdb-query rrset $domain/SOA >> dnsdb.out 2>&1
    isc-dnsdb-query rrset $domain/A >> dnsdb.out 2>&1
    isc-dnsdb-query rrset $domain/AAAA >> dnsdb.out 2>&1
    git add dnsdb.out
fi

if [ $circl = 1 ]; then
    date > circl.out
    if [ ! -e $HOME/.circl.conf ]; then
	echo "No credentials in ~/.circl.conf" >> circl.out 
    else
	# https://www.circl.lu/services/passive-dns/
	curl -q --user $(head -n 1 ~/.circl.conf) https://www.circl.lu/pdns/query/$domain >> circl.out 2>&1
    fi
    git add circl.out
fi

if [ $dns360 = 1 ]; then
    date > dns360.out 
    flint rrset $domain NS >> dns360.out 2>&1
    flint rrset $domain SOA >> dns360.out 2>&1
    flint rrset $domain A >> dns360.out 2>&1
    flint rrset $domain AAAA >> dns360.out 2>&1
    git add dns360.out
fi

if [ $recursive = 1 ]; then
    date > dnsyo.out
    # http://samarudge.github.io/dnsyo/
    dnsyo --extended $domain NS >> dnsyo.out 2>&1
    dnsyo --extended $domain A >> dnsyo.out 2>&1
    git add dnsyo.out
fi

# As of today (2013-10-28), Atlas probes cannot do requests without the RD bit :-(
# TODO Awful code, see issue #4
if [ $recursive = 1 ] && [ $atlas = 1 ]; then
    cd $ATLASCODE || exit 1
    date > atlas.$$.out
    echo "" >> atlas.$$.out
    python resolve-name.py -r 500 $domain >> atlas.$$.out 2>&1
    # TODO: -r 30 because otherwise "You do not have enough credit to schedule this measurement."
    mv atlas.$$.out $CODEDIR
    cd $CODEDIR || exit 1
    echo "" >> atlas.$$.out 
    resolve-name-periodic.py -r 30 -t A $domain >> atlas.$$.out 2>&1
    echo "" >> atlas.$$.out 
    resolve-name-periodic.py -r 30 -t NS $domain >> atlas.$$.out 2>&1
    mv atlas.$$.out $BASEDIR/$dir/atlas.out
    cd $BASEDIR/$dir || exit 1
    git add atlas.out
fi

if [ $dnsviz = 1 ]; then
    date > dnsviz.out
    dnsviz probe -A $domain > dnsviz.json 2>> dnsviz.out
    dnsviz print -r dnsviz.json $domain >> dnsviz.out 2>&1
    dnsviz graph -T html -r dnsviz.json $domain > dnsviz.html 2>> dnsviz.out
    git add dnsviz.out dnsviz.json dnsviz.html
fi

if [ $zonemaster = 1 ]; then
    date > zonemaster.out
    zonemaster-cli $domain >> zonemaster.out 2>&1
    git add zonemaster.out 
fi

git commit -m "End of automatic gathering of $domain" .

