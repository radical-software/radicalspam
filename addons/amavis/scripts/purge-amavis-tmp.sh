#!/bin/bash

if [ -e /var/rs ]; then
   . /var/rs/etc/scripts/common.sh
else
   . /etc/scripts/common.sh
fi

BASEDIR=${RS_BASE}${ADDON_AMAVIS}/var/amavis/tmp

[ ! -d $BASEDIR ] && exit 1

# Supprime les répertoires temporaires d'amavis datant de plus de 2 jours
$FIND $BASEDIR -mindepth 1 -maxdepth 1 -type d -mtime +2 -exec rm -rf {} \;

exit $?
