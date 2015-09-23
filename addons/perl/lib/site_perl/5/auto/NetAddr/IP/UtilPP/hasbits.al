# NOTE: Derived from ../../blib/lib/NetAddr/IP/UtilPP.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP::UtilPP;

#line 128 "../../blib/lib/NetAddr/IP/UtilPP.pm (autosplit into ../../blib/lib/auto/NetAddr/IP/UtilPP/hasbits.al)"
sub hasbits {
  _deadlen(length($_[0]))
	if length($_[0]) != 16;
  return 1 if vec($_[0],3,32);
  return (isIPv4($_[0])) ? 0 : 1;
}

# end of NetAddr::IP::UtilPP::hasbits
1;
