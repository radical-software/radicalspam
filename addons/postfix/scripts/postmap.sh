#!/bin/bash

if [ -e /var/rs ]; then
   . /var/rs/etc/scripts/common.sh
else
   . /etc/scripts/common.sh
fi


FILE=$1
$LOCAL_CHROOT $RS_BASE /bin/test -f $FILE
[ $? -eq 0 ] || FILE=${ADDON_POSTFIX}/etc/$1

opt_display DEBUG
if [ $? -eq 0 ]; then
   $LOCAL_CHROOT $RS_BASE ${ADDON_POSTFIX}/sbin/postmap -v $FILE
else
   $LOCAL_CHROOT $RS_BASE ${ADDON_POSTFIX}/sbin/postmap $FILE
fi

exit $?
