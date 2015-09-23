#!/bin/bash

PROGNAME=`basename $0`
PROGPATH=`echo $0 | /bin/sed -e 's,[\\/][^\\/][^\\/]*$,,'`
REVISION=`echo '$Revision: 1.0 $' | sed -e 's/[^0-9.]//g'`

STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3

# Chemin des commandes utilisées
CAT="cat"
GREP="grep"
WC="wc"
FIND="find"
DATE="date"
CUT="cut"

if test -x /usr/bin/printf; then
        ECHO=/usr/bin/printf
else
        ECHO=echo
fi


SERVER=""
COUNTER_FILE=/var/rs/addons/nagios/var/stats_postfix_logs_counters.txt
VCASE=$1
VWARN=$2
VCRIT=$3

# Si arguments > 3
if [ $# -gt 3 ]; then
   SERVER=$1

   if [ -f /var/rs/addons/nagios/var/$SERVER-stats_postfix_logs_counters.txt ]; then
      COUNTER_FILE=/var/rs/addons/nagios/var/$SERVER-stats_postfix_logs_counters.txt
   else
      exit $STATE_UNKNOWN
   fi

   VCASE=$2
   VWARN=$3
   VCRIT=$4

fi

if [ ! -e $COUNTER_FILE ]; then
    $ECHO "Log check error: Log file $COUNTER_FILE does not exist!\n"
    exit $STATE_UNKNOWN
elif [ ! -r $COUNTER_FILE ] ; then
    $ECHO "Log check error: Log file $COUNTER_FILE is not readable!\n"
    exit $STATE_UNKNOWN
fi

print_usage() {
        echo "Usage: $PROGNAME --help"
        echo "Usage: $PROGNAME --version"

        echo ""

        echo "Usage: $PROGNAME [server] REJECT_5XX VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] REJECT_4XX VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] REJECT_WARNING VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] REJECT_CLIENT VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] REJECT_SENDER VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] REJECT_RECIPIENT VALUE_WARNING VALUE_CRITICAL"

        echo ""

        echo "Usage: $PROGNAME [server] ERROR VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] WARNING VALUE_WARNING VALUE_CRITICAL"

        echo ""

        echo "Usage: $PROGNAME [server] SMTP_MAIL_SENT VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] SMTP_MAIL_DEFERRED VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] SMTP_MAIL_BOUNCED VALUE_WARNING VALUE_CRITICAL"

        echo ""

        echo "Usage: $PROGNAME [server] SMTP_DELAY_EXT VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] SMTP_DELAY_LOCAL VALUE_WARNING VALUE_CRITICAL"

        echo ""
	
        echo "Usage: $PROGNAME [server] MAIL_SIZE VALUE_WARNING VALUE_CRITICAL"
        echo "Usage: $PROGNAME [server] POSTGREY_DELAY VALUE_WARNING VALUE_CRITICAL"

}

print_help() {
        echo $PROGNAME $REVISION
        echo ""
        print_usage
}

# Si inférieur à 2 arguments
if [ $# -lt 3 ]; then
        print_usage
        exit $STATE_UNKNOWN
fi

# Fonction généric pour déterminer le code retour
generic_count() {

   TXT=$1
   CPT=$2
   WARN=$3
   CRIT=$4

   if [ $CPT -gt $CRIT ]; then

      echo "CRITICAL (Number of $TXT is upper to $CRIT : $CPT)"
      return $STATE_CRITICAL

   elif  [ $CPT -gt $WARN ]; then

      echo "WARNING (Number of $TXT is upper to $WARN : $CPT)"
      return $STATE_WARNING

   else

      echo "OK (Number of $TXT is : $CPT)"
      return $STATE_OK

   fi
}

# Fonction generique pour lire une variable du fichier des compteurs :
# Usage : counter "QUEUE_DEFERRED" 5 15
counter(){
  COUNTER=$1
  count=$( $CAT $COUNTER_FILE | $GREP "^$COUNTER=" | $CUT -d '=' -f2 )
  generic_count "$COUNTER" $count $2 $3
  return $?
}

while test -n "$VCASE"; do
        case "$VCASE" in
                --help)
                        print_help
                        exit $STATE_OK
                        ;;
                --version)
                        print_revision $PROGNAME $REVISION
                        exit $STATE_OK
                        ;;
                REJECT_5XX)
                        counter "REJECT_5XX" $VWARN $VCRIT
                        exit $?
                        ;;
                REJECT_4XX)
                        counter "REJECT_4XX" $VWARN $VCRIT
                        exit $?
                        ;;
                REJECT_WARNING)
                        counter "REJECT_WARNING" $VWARN $VCRIT
                        exit $?
                        ;;
                REJECT_CLIENT)
                        counter "REJECT_CLIENT" $VWARN $VCRIT
                        exit $?
                        ;;
                REJECT_SENDER)
                        counter "REJECT_SENDER" $VWARN $VCRIT
                        exit $?
                        ;;
                REJECT_RECIPIENT)
                        counter "REJECT_RECIPIENT" $VWARN $VCRIT
                        exit $?
                        ;;
                ERROR)
                        counter "ERROR" $VWARN $VCRIT
                        exit $?
                        ;;
                WARNING)
                        counter "WARNING" $VWARN $VCRIT
                        exit $?
                        ;;
                SMTP_MAIL_SENT)
                        counter "SMTP_MAIL_SENT" $VWARN $VCRIT
                        exit $?
                        ;;
                SMTP_MAIL_DEFERRED)
                        counter "SMTP_MAIL_DEFERRED" $VWARN $VCRIT
                        exit $?
                        ;;
                SMTP_MAIL_BOUNCED)
                        counter "SMTP_MAIL_BOUNCED" $VWARN $VCRIT
                        exit $?
                        ;;
                SMTP_DELAY_EXT)
                        counter "SMTP_DELAY_EXT" $VWARN $VCRIT
                        exit $?
                        ;;
                SMTP_DELAY_LOCAL)
                        counter "SMTP_DELAY_LOCAL" $VWARN $VCRIT
                        exit $?
                        ;;
                MAIL_SIZE)
                        counter "MAIL_SIZE" $VWARN $VCRIT
                        exit $?
                        ;;
                POSTGREY_DELAY)
                        counter "POSTGREY_DELAY" $VWARN $VCRIT
                        exit $?
                        ;;
                *)
                        echo "Unknown argument: $VCASE"
                        print_usage
                        exit $STATE_UNKNOWN
                        ;;
        esac
        shift
done

exit $STATE_UNKNOWN


