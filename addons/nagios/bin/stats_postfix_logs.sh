#!/bin/bash

# ***************************************************************************************
# Version : 1.2
# Date    : 16/12/2007
# Auteur  : Stéphane RAULT - stephane.rault@radicalspam.org
# ***************************************************************************************
# Changement depuis 1.0 :
# - Correction pour la génération des stats cumulés
# ***************************************************************************************
# Changement depuis 1.1 :
# - Ajout d'une ligne de recherche maillog-xxx
# - Ajout de 4 compteurs : SMTP_DELAY_EXT, SMTP_DELAY_LOCAL, POSTGREY_DELAY, MAIL_SIZE
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

# Rejets dans les logs : lignes reject:

REJECT_5XX=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtpd\[' | $GREP 'reject:' | $GREP -E '\]: (554|550|504|501) ' | $WC -l)
echo "REJECT_5XX=$REJECT_5XX"

REJECT_4XX=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtpd\[' | $GREP 'reject:' | $GREP -E '\]: (450) ' | $WC -l)
echo "REJECT_4XX=$REJECT_4XX"

REJECT_WARNING=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtpd\[' | $GREP 'reject_warning:' | $WC -l)
echo "REJECT_WARNING=$REJECT_WARNING"

REJECT_CLIENT=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtpd\[' | $GREP 'reject:' | $GREP 'Client host rejected:' | $WC -l)
echo "REJECT_CLIENT=$REJECT_CLIENT"

REJECT_SENDER=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtpd\[' | $GREP 'reject:' | $GREP 'Sender address rejected:' | $WC -l)
echo "REJECT_SENDER=$REJECT_SENDER"

REJECT_RECIPIENT=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtpd\[' | $GREP 'reject:' | $GREP 'Recipient address rejected:' | $GREP -v ' Greylisted' | $WC -l)
echo "REJECT_RECIPIENT=$REJECT_RECIPIENT"


# Erreurs et warning Postfix

ERROR=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/' | $GREP -E '\]: (error|fatal|panic): ' | $WC -l)
echo "ERROR=$ERROR"

WARNING=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/' | $GREP '\]: warning: ' | $WC -l)
echo "WARNING=$WARNING"


# Statistiques d'envoi SMTP - Postfix vers destinataires internes/externes

SMTP_MAIL_SENT=$( $CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtp\[' | $GREP 'status=sent' | $GREP -v 'relay=127.0.0.1' | $WC -l)
echo "SMTP_MAIL_SENT=$SMTP_MAIL_SENT"

SMTP_MAIL_DEFERRED=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtp\[' | $GREP 'status=deferred' | $WC -l)
echo "SMTP_MAIL_DEFERRED=$SMTP_MAIL_DEFERRED"

SMTP_MAIL_BOUNCED=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtp\[' | $GREP 'status=bounced' | $WC -l)
echo "SMTP_MAIL_BOUNCED=$SMTP_MAIL_BOUNCED"

# SMTP : Delai moyen de livraison vers serveurs internes/externes (en secondes)
SMTP_DELAY_EXT=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtp\[' | $GREP 'status=sent' | $GREP -v 'orig_to=' | $GREP -v 'relay=127.0.0.1' | $AWK -F 'delay=' '{ print $2}' | $CUT -d ',' -f1 | $AWK 'BEGIN{ CONVFMT="%d"; cpt=0; val=0} { cpt++; val=val+$1  } END{ if ( val > 0 ) { printf "%d",((val/cpt)) } else { print "0" } }')
echo "SMTP_DELAY_EXT=$SMTP_DELAY_EXT"

# SMTP : Delai moyen de livraison locale vers le filtre amavis par smtp
SMTP_DELAY_LOCAL=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/smtp\[' | $GREP 'status=sent' | $GREP -v 'orig_to=' | $GREP 'relay=127.0.0.1' | $AWK -F 'delay=' '{ print $2}' | $CUT -d ',' -f1 | $AWK 'BEGIN{ CONVFMT="%d"; cpt=0; val=0} { cpt++; val=val+$1  } END{ if ( val > 0 ) { printf "%d",((val/cpt)) } else { print "0" } }')
echo "SMTP_DELAY_LOCAL=$SMTP_DELAY_LOCAL"

# Taille moyenne des mails en Ko
MAIL_SIZE=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postfix/qmgr' | $GREP 'size=' | $AWK -F 'size=' '{ print $2}' | $CUT -d',' -f1 | $AWK 'BEGIN{ CONVFMT="%d"; cpt=0; val=0} { cpt++; val=val+$1  } END{ if ( val > 0 ) { printf "%d",((val/cpt)/1024) } else { print "0" } }')
echo "MAIL_SIZE=$MAIL_SIZE"

# Postgrey : Delai moyen de reception finale apres N representation par l'emetteur (en minutes)
POSTGREY_DELAY=$($CAT $logfile | $GREP " $SERVER" | $GREP 'postgrey\[' | $GREP 'delay=' | $AWK -F 'delay=' '{ print $2 }' | $CUT -d ',' -f1 | $AWK 'BEGIN{ CONVFMT="%d"; cpt=0; val=0} { cpt++; val=val+$1} END{ if ( val > 0 ) { printf "%d",((val/cpt)/60) } else { print "0" } }')
echo "POSTGREY_DELAY=$POSTGREY_DELAY"




	
