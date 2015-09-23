#!/bin/bash

DATE=date
GREP=grep
CAT=cat

LANG="en_US"

DAY=`$DATE +%e`
MONTH=`$DATE +%b`

# Ajout de l'espace devant le chiffre pour valeurs inférieurs à 10
for i in `echo "1 2 3 4 5 6 7 8 9"`; do
   if [ $i == $DAY ]; then
      DAY=" "$i
   fi
done

SORT=$MONTH" "$DAY

BASE_LOG="/var/log"

# Fichier de log des mails - 1 par jour, ex : /var/log/maillog-02022007.log
export_logfile="$BASE_LOG/maillog-`$DATE +%d%m%Y`.log"

logfile="$BASE_LOG/mail"

if [ ! -f $logfile ]; then
    logfile="$BASE_LOG/maillog"
fi

if [ ! -f $logfile ]; then
   echo "Fichier de log non trouvé"
   exit 1
fi

echo $logfile
echo $export_logfile

$GREP "^$SORT" $logfile > $export_logfile
