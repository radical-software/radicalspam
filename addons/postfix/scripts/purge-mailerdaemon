#!/bin/bash

if [ -e /var/rs ]; then
   . /var/rs/etc/scripts/common.sh
else
   . /etc/scripts/common.sh
fi


OPT_DEBUG=""

opt_display DEBUG && OPT_DEBUG="-v"

for i in `$LOCAL_CHROOT $RS_BASE $ADDON_POSTFIX/bin/mailq | $GREP ' MAILER-DAEMON' | $AWK '{ print $1 }' | $CUT -d '*' -f1 | $CUT -d '!' -f1`; do
   $LOCAL_CHROOT $RS_BASE $ADDON_POSTFIX/sbin/postsuper $OPT_DEBUG -d $i
done

exit 0
