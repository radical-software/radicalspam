# NOTE: Derived from blib/lib/NetAddr/IP.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP;

#line 791 "blib/lib/NetAddr/IP.pm (autosplit into blib/lib/auto/NetAddr/IP/full.al)"
sub full($) {
  if (! $_[0]->{isv6} && isIPv4($_[0]->{addr})) {
    my @hex = (unpack("n8",$_[0]->{addr}));
    $hex[9] = $hex[7] & 0xff;
    $hex[8] = $hex[7] >> 8;
    $hex[7] = $hex[6] & 0xff;
    $hex[6] >>= 8;
    return sprintf($full_format,@hex);
  } else {
    &full6;
  }
}

# end of NetAddr::IP::full
1;
