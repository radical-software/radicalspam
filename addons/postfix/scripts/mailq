#!/bin/bash

if [ -e /var/rs ]; then
   . /var/rs/etc/scripts/common.sh
else
   . /etc/scripts/common.sh
fi


$LOCAL_CHROOT $RS_BASE ${ADDON_POSTFIX}/bin/mailq

exit $?
