#!/bin/bash

if [ -e /var/rs ]; then
   . /var/rs/etc/scripts/common.sh
else
   . /etc/scripts/common.sh
fi


opt_display DEBUG
if [ $? -eq 0 ]; then
   $LOCAL_CHROOT $RS_BASE ${ADDON_POSTFIX}/sbin/postconf -vv "$@"
else
   $LOCAL_CHROOT $RS_BASE ${ADDON_POSTFIX}/sbin/postconf "$@"
fi

exit $?
