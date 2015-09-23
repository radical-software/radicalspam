# NOTE: Derived from ../../blib/lib/NetAddr/IP/Util.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP::Util;

#line 435 "../../blib/lib/NetAddr/IP/Util.pm (autosplit into ../../blib/lib/auto/NetAddr/IP/Util/inet_n2ad.al)"
sub inet_n2ad($) {
  my($nadr) = @_;
  my $addr = ipv6_n2d($nadr);
  return $addr unless isIPv4($nadr);
  $addr =~ /([^:]+)$/;
  return $1;
}

#=item * $onescomp=NetAddr::IP::Util::comp128($ipv6addr);
#
#This function is not exported because it is more efficient to use perl " ~ "
#on the bit string directly. This interface to the B<C> routine is published for
#module testing purposes because it is used internally in the B<sub128> routine. The
#function is very fast, but calling if from perl directly is very slow. It is almost
#33% faster to use B<sub128> than to do a 1's comp with perl and then call
#B<add128>.
#
#=item * $bcdpacked = NetAddr::IP::Util::bin2bcdn($bits128);
#
#Convert a 128 bit binary string into binary coded decimal digits.
#This function is not exported.
#
#  input:	128 bit string variable
#  returns:	string of packed decimal digits
#
#  i.e.	text = unpack("H*", $bcd);
#
#=item * $bcdtext =  NetAddr::IP::Util::bcdn2txt($bcdpacked);
#
#Convert a packed bcd string into text digits, suppress the leading zeros.
#This function is not exported.
#
#  input:	string of packed decimal digits
#  returns:	hexadecimal digits
#
#Similar to unpack("H*", $bcd);
#
#=item * $bcdpacked = NetAddr::IP::Util::simple_pack($bcdtext);
#
#Convert a numeric string into a packed bcd string, left fill with zeros
#
#  input:	string of decimal digits
#  returns:	string of packed decimal digits
#
#Similar to pack("H*", $bcdtext);


1;

1;
# end of NetAddr::IP::Util::inet_n2ad
