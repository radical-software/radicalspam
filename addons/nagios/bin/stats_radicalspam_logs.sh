#!/bin/bash

# ***************************************************************************************
# Version : 1.3
# Date    : 04/06/2009
# Auteur  : Stéphane RAULT - stephane.rault@radicalspam.org
# ***************************************************************************************
# Changement depuis 1.0 :
# - Correction pour la génération des stats cumulés
# ***************************************************************************************
# Changement depuis 1.1 :
# - Ajout d'une ligne de recherche maillog-xxx
# - Ajout de 2 compteurs : PROCESS_TIME_INPUT, PROCESS_TIME_OUTPUT
#
#
# - Ajout des compteurs : SA_TIMED_OUT
# ***************************************************************************************
# TODO: TEMPFAIL|OVERSIZED|BAD-HEADER
# TODO: Ajouter freshclam/update
# ***************************************************************************************

# Chemin des commandes utilisees
CAT=cat
GREP=grep
WC=wc
DATE=date
AWK=awk
CUT=cut

# Stat pour un serveur unique
SERVER=""

if [ $# -eq 1 ]; then
   SERVER=$1" "
fi

# Repertoire de stockage des logs
BASE_LOG="/var/log"

# /var/log/maillog-$DAY$MONTH$YEAR.log
# Fichier de log des mails - 1 par jour, ex : /var/log/maillog-02022007.log
logfile="$BASE_LOG/maillog-`$DATE +%d%m%Y`.log"

if [ ! -f $logfile ]; then
   logfile="$BASE_LOG/mail-`$DATE +%d%m%Y`.log"
fi

if [ ! -f $logfile ]; then
   exit 1
fi
      
echo "UPTIME=`$DATE +%Y%m%d%H%M%S`"

VIRUS=$($CAT $logfile | $GREP " $SERVER" | $GREP -E '(Blocked INFECTED|Passed INFECTED)' | $WC -l)
echo "VIRUS=$VIRUS"

SPAM=$($CAT $logfile | $GREP " $SERVER" | $GREP -E '(Blocked SPAM|Passed SPAM)' | $GREP -v 'SPAMMY' | $WC -l)
echo "SPAM=$SPAM"

SPAMMY=$($CAT $logfile | $GREP " $SERVER" | $GREP -E '(Blocked SPAMMY|Passed SPAMMY)' | $WC -l)
echo "SPAMMY=$SPAMMY"

BANNED=$($CAT $logfile | $GREP " $SERVER" | $GREP -E '(Blocked BANNED|Passed BANNED)' | $WC -l)
echo "BANNED=$BANNED"

UNCHECKED=$($CAT $logfile | $GREP " $SERVER" | $GREP -E '(Blocked UNCHECKED|Passed UNCHECKED)' | $WC -l)
echo "UNCHECKED=$UNCHECKED"

# Temps de traitement moyen du filtre amavis (en secondes) - filtrage entrant
PROCESS_TIME_INPUT=$($CAT $logfile | $GREP " $SERVER" | $GREP 'amavis\[' | $GREP -E '(Passed|Blocked)' | $GREP -v 'output' | $AWK -F 'mail_id' '{ print $2 }' | $AWK -F ',' '{ if ( /queued_as/ ) { v=$5 } else { v=$4 }; print v }' |  $AWK '{ print $1}' | $AWK 'BEGIN{ CONVFMT="%d"; cpt=0; val=0} { cpt++; val=val+$1  } END{ if ( val > 0 ) { printf "%d",((val/cpt)/1000) } else { print "0" } }')
echo "PROCESS_TIME_INPUT=$PROCESS_TIME_INPUT"

# Temps de traitement moyen du filtre amavis (en secondes) - filtrage sortant
PROCESS_TIME_OUTPUT=$($CAT $logfile | $GREP " $SERVER" | $GREP 'amavis\[' | $GREP -E '(Passed|Blocked)' | $GREP 'output' | $AWK -F 'mail_id' '{ print $2 }' | $AWK -F ',' '{ if ( /queued_as/ ) { v=$5 } else { v=$4 }; print v }' |  $AWK '{ print $1}' | $AWK 'BEGIN{ CONVFMT="%d"; cpt=0; val=0} { cpt++; val=val+$1  } END{ if ( val > 0 ) { printf "%d",((val/cpt)/1000) } else { print "0" } }')
echo "PROCESS_TIME_OUTPUT=$PROCESS_TIME_OUTPUT"

SA_TIMED_OUT=$($CAT $logfile | $GREP " $SERVER" | $GREP 'SA TIMED OUT' | $WC -l)
echo "SA_TIMED_OUT=$SA_TIMED_OUT"

