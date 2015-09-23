#!/bin/bash

if [ -e /var/rs ]; then
   . /var/rs/etc/scripts/common.sh
else
   . /etc/scripts/common.sh
fi

BASEDIR=${RS_BASE}${ADDON_AMAVIS}/var/amavis/virusmails

[ ! -d $BASEDIR ] && exit 1

# Spams - 10 Jours
if [ -d $BASEDIR/spam ]; then
   $FIND $BASEDIR/spam -type f -mtime +10 -exec rm -f {} \;
fi

# Virus - 5 Jours
if [ -d $BASEDIR/virus ]; then
   $FIND $BASEDIR/virus -type f -mtime +5 -exec rm -f {} \;
fi

# Banneds - 15 Jours
if [ -d $BASEDIR/banned ]; then
   $FIND $BASEDIR/banned -type f -mtime +15 -exec rm -f {} \;
fi

