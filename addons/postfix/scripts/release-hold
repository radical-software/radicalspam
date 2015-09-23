#!/bin/bash

if [ -e /var/rs ]; then
   . /var/rs/etc/scripts/common.sh
else
   . /etc/scripts/common.sh
fi


RETVAL=0
OPT_DEBUG=""
opt_display DEBUG && OPT_DEBUG="-v"

$LOCAL_CHROOT $RS_BASE $ADDON_POSTFIX/sbin/postsuper $OPT_DEBUG -H ALL
RETVAL=$?

$LOCAL_CHROOT $RS_BASE $ADDON_POSTFIX/sbin/postfix flush

exit $RETVAL

