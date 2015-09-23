#!/bin/bash

export PATH=/bin:/addons/rs-tools/bin

   for i in `/bin/find \
    /bin \
    /lib \
    /usr \
    /addons/amavis \
    /addons/bind \
    /addons/dnsmasq \
    /addons/dcc \
    /addons/perl \
    /addons/rs-tools \
    /addons/clamav \
    /addons/nagios \
    /addons/postfix \
    /addons/postgrey \
    /addons/razor \
    /addons/spamassassin \
    /addons/python \
    /addons/rs-rblcache \
    -type f`; do 
       /addons/rs-tools/bin/file -b $i | /bin/grep '^ELF 32-bit' 2>/dev/null 1>&2
       if [ $? -eq 0 ]; then
           echo $i
           /bin/ldd $i
       fi
     done > /tmp/verify-ldd.txt 2>/dev/null 1>&2 

     /bin/grep 'not found' /tmp/verify-ldd.txt

