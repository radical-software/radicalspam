# NOTE: Derived from ../../blib/lib/NetAddr/IP/Util.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP::Util;

#line 348 "../../blib/lib/NetAddr/IP/Util.pm (autosplit into ../../blib/lib/auto/NetAddr/IP/Util/ipv6_n2d.al)"
sub ipv6_n2d {
  die "Bad arg length for 'ipv6_n2x', length is ". length($_[0]) ." should be 16"
	unless length($_[0]) == 16;
  my @hex = (unpack("n8",$_[0]));
  $hex[9] = $hex[7] & 0xff;
  $hex[8] = $hex[7] >> 8;
  $hex[7] = $hex[6] & 0xff;
  $hex[6] >>= 8;
  return sprintf($n2d_format,@hex);
}

# end of NetAddr::IP::Util::ipv6_n2d
1;
