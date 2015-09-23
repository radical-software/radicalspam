#!/bin/bash

# Chemin des commandes utilisees
WC=wc
FIND=find
DATE=date
SSH="ssh -2 -4 -l root -i /root/.ssh/id_dsa -o PreferredAuthentications=publickey"

# Repertoire de base pour les queues Postfix
POSTFIX_SPOOL="/var/rs/addons/postfix/var/spool"

SERVER=$1

if [ ! $# -eq 1 ]; then
   exit 1
fi

echo "UPTIME=`$DATE +%Y%m%d%H%M%S`"

QUEUE_ALL=$($SSH $SERVER $FIND $POSTFIX_SPOOL/deferred $POSTFIX_SPOOL/active -type f | $WC -l)
echo "QUEUE_ALL=$QUEUE_ALL"

QUEUE_ACTIVE=$($SSH $SERVER $FIND $POSTFIX_SPOOL/active -type f | $WC -l)
echo "QUEUE_ACTIVE=$QUEUE_ACTIVE"

QUEUE_DEFERRED=$($SSH $SERVER $FIND $POSTFIX_SPOOL/deferred -type f | $WC -l)
echo "QUEUE_DEFERRED=$QUEUE_DEFERRED"

QUEUE_HOLD=$($SSH $SERVER $FIND $POSTFIX_SPOOL/hold -type f | $WC -l)
echo "QUEUE_HOLD=$QUEUE_HOLD"

