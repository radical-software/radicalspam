#!/usr/bin/awk -f

BEGIN {
   CONVFMT="%d"
   FS="="

   QUEUE_ALL=0
   QUEUE_ACTIVE=0
   QUEUE_DEFERRED=0
   QUEUE_HOLD=0
}

NF == 0 { next }

( NF != 0 ){
   if ( $1 ~ /^QUEUE_ALL/ ) {
      QUEUE_ALL=QUEUE_ALL+$2
   }
   if ( $1 ~ /^QUEUE_ACTIVE/ ) {
      QUEUE_ACTIVE=QUEUE_ACTIVE+$2
   }
   if ( $1 ~ /^QUEUE_DEFERRED/ ) {
      QUEUE_DEFERRED=QUEUE_DEFERRED+$2
   }
   if ( $1 ~ /^QUEUE_HOLD/ ) {
      QUEUE_HOLD=QUEUE_HOLD+$2
   }
}

END {
   print "UPTIME="UPTIME
   print "QUEUE_ALL="QUEUE_ALL
   print "QUEUE_ACTIVE="QUEUE_ACTIVE
   print "QUEUE_DEFERRED="QUEUE_DEFERRED
   print "QUEUE_HOLD="QUEUE_HOLD
}
