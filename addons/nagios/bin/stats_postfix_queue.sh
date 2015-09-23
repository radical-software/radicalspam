#!/bin/bash

# Chemin des commandes utilisees
WC=wc
FIND=find
DATE=date

# Repertoire de base pour les queues Postfix
POSTFIX_SPOOL="/var/rs/addons/postfix/var/spool"

echo "UPTIME=`$DATE +%Y%m%d%H%M%S`"

QUEUE_ALL=$($FIND $POSTFIX_SPOOL/deferred $POSTFIX_SPOOL/active -type f | $WC -l)
echo "QUEUE_ALL=$QUEUE_ALL"

QUEUE_ACTIVE=$($FIND $POSTFIX_SPOOL/active -type f | $WC -l)
echo "QUEUE_ACTIVE=$QUEUE_ACTIVE"

QUEUE_DEFERRED=$($FIND $POSTFIX_SPOOL/deferred -type f | $WC -l)
echo "QUEUE_DEFERRED=$QUEUE_DEFERRED"

QUEUE_HOLD=$($FIND $POSTFIX_SPOOL/hold -type f | $WC -l)
echo "QUEUE_HOLD=$QUEUE_HOLD"

