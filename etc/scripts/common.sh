#!/bin/bash

export AWK=awk
export CAT=cat
export PIDOF=pidof
export NETSTAT=netstat
export EGREP=egrep
export PS=ps
export ID=id
export RM=rm
export CHOWN=chown
export CHGRP=chgrp
export CHMOD=chmod
export UNAME=uname
export DATE=date
export TAR=tar
export HOSTNAME=hostname
export MV=mv
export MKDIR=mkdir
export CUT=cut
export GREP=grep
export LS=ls
export FIND=find
export CP=cp
export GZIP_CMD=gzip
export NOHUP=nohup
export SLEEP=sleep
export TEST=test
export KILL=kill
export MOUNT=mount
export CHROOT=chroot
export IFCONFIG=ifconfig
export HEAD=head
export LSOF=lsof
export WHOIS=whois
export SED=sed
export WC=wc
export LDD=ldd
export MD5SUM=md5sum
export DIFF=diff
export TOUCH=touch

export ADDONS_BASE=/addons
export ADDON_PERL=$ADDONS_BASE/perl
export ADDON_CLAMAV=$ADDONS_BASE/clamav
export ADDON_PYTHON=$ADDONS_BASE/python
export ADDON_AMAVIS=$ADDONS_BASE/amavis
export ADDON_RAZOR=$ADDONS_BASE/razor
export ADDON_DCC=$ADDONS_BASE/dcc
export ADDON_POSTGREY=$ADDONS_BASE/postgrey
export ADDON_POSTFIX=$ADDONS_BASE/postfix
export ADDON_BIND=$ADDONS_BASE/bind
export ADDON_SPAMASSASSIN=$ADDONS_BASE/spamassassin
export ADDON_NAGIOS=$ADDONS_BASE/nagios
export ADDON_RS_TOOLS=$ADDONS_BASE/rs-tools
export ADDON_TOOLS=$ADDON_RS_TOOLS
export ADDON_DNSMASQ=$ADDONS_BASE/dnsmasq

if [ -e /var/rs ]; then
   export RS_BASE="/var/rs"
   export LOCAL_CHROOT=chroot
   #$ADDON_TOOLS/bin a cause de spamassassin
   export PATH=$PATH:${RS_BASE}${ADDON_POSTFIX}/scripts:${ADDON_TOOLS}/bin
else
   export RS_BASE=""
   export LOCAL_CHROOT=""
   export PATH=/bin:/usr/bin:/usr/local/bin:$ADDON_TOOLS/bin:${ADDON_POSTFIX}/scripts
fi

export OPT_DIR=${RS_BASE}/etc/options

# Tableau des options
declare -a OPTIONS
OPTIONS[0]="DEBUG"
OPTIONS[1]="POSTFIX"
OPTIONS[2]="AMAVIS"
OPTIONS[3]="BIND"
OPTIONS[4]="CLAMAV"
OPTIONS[5]="DNSMASQ"
OPTIONS[6]="POSTGREY"
OPTIONS[7]="SPAMASSASSIN"
OPTIONS[8]="RAZOR"
OPTIONS[9]="DCC"

declare -a DAEMON_APP
DAEMON_APP[0]="postfix"
DAEMON_APP[1]="bind"
DAEMON_APP[2]="dnsmasq"
DAEMON_APP[3]="amavis"
DAEMON_APP[4]="clamav"
DAEMON_APP[5]="postgrey"

MAIL_SCRIPT=/addons/rs-tools/scripts/SendMail.py

export IP_FIRST=""

export OPEN=1
export CLOSE=0
export ERROR=2

yellow() {
   echo -e "\033[33m\033[1m$1\033[m"
   return 0
}

red() {
   local msg="$1"
   [ -n "$2" ] && msg="$msg : $2"
   echo -e "\033[31m\033[1m${msg}\033[m"
   return 0
}

green() {
   local msg="$1"
   [ -n "$2" ] && msg="$msg : $2"
   echo -e "\033[32m\033[1m${msg}\033[m"
   return 0
}

success(){
        echo -e "\033[32m\033[1m-> $1\033[m"
        return 0
}

failure(){
        rc=$?
        echo -e "\033[31m\033[1m-> $1\033[m"
        return $rc
}

error() {
   echo -e "\033[31m\033[1mError : $1. Program Aborted\033[m"
   exit 1
}

OK(){
        echo -e "\033[32m\033[1m-> $1\033[m"
        return 0
}

NOK(){
        rc=$?
        echo -e "\033[31m\033[1m-> $1\033[m"
        return $rc
}

open(){
        echo -e "\033[32m\033[1m$1 -> OPEN\033[m"
        return 0
}

close(){
        rc=$?
        echo -e "\033[31m\033[1m$1 -> CLOSE\033[m"
        return $rc
}

# Test un port sur ecoute 
# usage : testport 53
testport() {
        if $NETSTAT -an | $EGREP ":$1 .*LISTEN" > /dev/null
        then
                return 0
        else
                return 1
        fi
}

# usage : is_open /var/rs/addons/amavis/var/amavis.pid amavisd
is_open() {
   # $1 = fichier contenant le PID
   if [ -f $1 ]; then
      pid=`$CAT $1 | $HEAD -1 | $AWK '{ print $1 }'`
      $PS ax 2>/dev/null | $EGREP "^ *$pid.*$2" > /dev/null
      # 1 = non trouvé / 0 = trouvé
      if [ $? -eq "0" ]; then
         return $OPEN
      else
         return $CLOSE
      fi
   else
        return $CLOSE
   fi
   # Retourne ERROR par défaut
   return $ERROR
}

# Test si utilisateur root
testroot() {
   if $TEST "`$ID -u`" -ne 0
   then
      echo "Vous devez executer ce script en compte root (ou id=0) !"
      return 1
   else
      return 0
   fi
}

#------------------------------------
# Renvoit la liste des applications de type daemon
#------------------------------------
daemon_list_function() {
   export DAEMON_APP_LIST=""
   for DAEMON in ${DAEMON_APP[@]}; do
      DAEMON_APP_LIST="$DAEMON,$DAEMON_APP_LIST"
   done
   return 0
}

#------------------------------------
# Verifie l'existence d'une option
# return 0 si option existe
# return $ERROR si option n'existe pas
#------------------------------------
opt_exist() {
   opt=$1
   for OPTION in ${OPTIONS[@]}; do
      [ "$opt" = "$OPTION" ] && return 0
   done
   return $ERROR
}

#------------------------------------
# Donne le status d'une option
# 0 pour enable
# 1 pour disable
#------------------------------------
opt_display() {
  # Option demandé
  opt=$1
  opt_exist $1 || return $ERROR
  if [ -f $OPT_DIR/$opt ]; then
     # Option enable
     return 0
  else
     # Option disable
     return 1
  fi
}

#------------------------------------
# Change le status d'une option
# Passe a enable si actuellement disable
# Passe a disable si actuellement enable
#------------------------------------
opt_change() {
  # Option demandé
  opt=$1
  opt_exist $1 || return $ERROR
  if opt_display $opt; then
     # Status enable, passer a disable
     $RM -f $OPT_DIR/$opt
  else
     # Status disable, passer a enable
     $TOUCH $OPT_DIR/$opt
  fi
  return 0
}

# Fonction principale pour savoir si app enable/disable
is_enable() {
   opt_display $1
   return $?
}


# Utilisé par my_status()
my_local_status() {
   case "$2" in
      "0")
         close "$1"
         ;;
      "1")
         open "$1"
         ;;
      "2")
         red "$1 Error !!!"
         ;;
      *)
         yellow "Unknow status : $2"
   esac
}

my_status() {
   is_enable $1
   RETVAL=$?
   if [ "$RETVAL" = "0" ]; then
      my_local_status "$2" "$3"
   fi
}

ip_list() {
   $IFCONFIG 2>/dev/null | $GREP 'inet addr' | $SED -e 's/.*addr://' -e 's/ .*//'
}

ip_first() {
   export IP_FIRST=`ip_list | $GREP -v '127.0.0.1' | $HEAD -1`
}

