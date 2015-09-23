# NOTE: Derived from ../../blib/lib/NetAddr/IP/Util.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP::Util;

#line 415 "../../blib/lib/NetAddr/IP/Util.pm (autosplit into ../../blib/lib/auto/NetAddr/IP/Util/inet_n2dx.al)"
sub inet_n2dx($) {
  my($nadr) = @_;
  if (isIPv4($nadr)) {
    ipv6_n2d($nadr) =~ /([^:]+)$/;
    return $1;
  }
  return ipv6_n2x($nadr);
}

# end of NetAddr::IP::Util::inet_n2dx
1;
