# NOTE: Derived from ../../blib/lib/NetAddr/IP/UtilPP.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP::UtilPP;

#line 142 "../../blib/lib/NetAddr/IP/UtilPP.pm (autosplit into ../../blib/lib/auto/NetAddr/IP/UtilPP/isIPv4.al)"
sub isIPv4 {
  _deadlen(length($_[0]))
	if length($_[0]) != 16;
  return 0 if vec($_[0],0,32);
  return 0 if vec($_[0],1,32);
  return 0 if vec($_[0],2,32);
  return 1;
}

# end of NetAddr::IP::UtilPP::isIPv4
1;
