#!/usr/bin/awk -f

BEGIN {
   CONVFMT="%d"
   FS="="

   VIRUS=0
   SPAM=0
   SPAMMY=0
   BANNED=0
   UNCHECKED=0
}

NF == 0 { next }

( NF != 0 ){
   if ( $1 ~ /^VIRUS/ ) {
      VIRUS=VIRUS+$2
   }
   if (( $1 ~ /^SPAM/ ) && ( !/SPAMMY/ )) {
      SPAM=SPAM+$2
   }
   if ( $1 ~ /^SPAMMY/ ) {
      SPAMMY=SPAMMY+$2
   }
   if ( $1 ~ /^BANNED/ ) {
      BANNED=BANNED+$2
   }
   if ( $1 ~ /^UNCHECKED/ ) {
      UNCHECKED=UNCHECKED+$2
   }
}

END {
   print "UPTIME="UPTIME
   print "VIRUS="VIRUS
   print "SPAM="SPAM
   print "SPAMMY="SPAMMY
   print "BANNED="BANNED
   print "UNCHECKED="UNCHECKED
}
