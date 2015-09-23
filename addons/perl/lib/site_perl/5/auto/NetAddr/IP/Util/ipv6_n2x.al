# NOTE: Derived from ../../blib/lib/NetAddr/IP/Util.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP::Util;

#line 331 "../../blib/lib/NetAddr/IP/Util.pm (autosplit into ../../blib/lib/auto/NetAddr/IP/Util/ipv6_n2x.al)"
sub ipv6_n2x {
  die "Bad arg length for 'ipv6_n2x', length is ". length($_[0]) ." should be 16"
	unless length($_[0]) == 16;
  return sprintf($n2x_format,unpack("n8",$_[0]));
}

# end of NetAddr::IP::Util::ipv6_n2x
1;
