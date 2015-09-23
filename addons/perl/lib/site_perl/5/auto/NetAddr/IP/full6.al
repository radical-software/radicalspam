# NOTE: Derived from blib/lib/NetAddr/IP.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP;

#line 804 "blib/lib/NetAddr/IP.pm (autosplit into blib/lib/auto/NetAddr/IP/full6.al)"
sub full6($) {
  my @hex = (unpack("n8",$_[0]->{addr}));
  return sprintf($full6_format,@hex);
}

# end of NetAddr::IP::full6
1;
