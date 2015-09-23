# NOTE: Derived from ../../blib/lib/NetAddr/IP/Util.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP::Util;

#line 370 "../../blib/lib/NetAddr/IP/Util.pm (autosplit into ../../blib/lib/auto/NetAddr/IP/Util/inet_any2n.al)"
sub inet_any2n($) {
  my($addr) = @_;
  $addr = '' unless $addr;
  $addr = '::' . $addr
	unless $addr =~ /:/;
  return ipv6_aton($addr);
}

# end of NetAddr::IP::Util::inet_any2n
1;
