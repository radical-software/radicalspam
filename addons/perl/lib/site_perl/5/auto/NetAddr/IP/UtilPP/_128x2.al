# NOTE: Derived from ../../blib/lib/NetAddr/IP/UtilPP.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP::UtilPP;

#line 162 "../../blib/lib/NetAddr/IP/UtilPP.pm (autosplit into ../../blib/lib/auto/NetAddr/IP/UtilPP/_128x2.al)"
# multiply x 2
#
sub _128x2 {
  my $inp = shift;
  $$inp[0] = ($$inp[0] << 1 & 0xffffffff) + (($$inp[1] & 0x80000000) ? 1:0);
  $$inp[1] = ($$inp[1] << 1 & 0xffffffff) + (($$inp[2] & 0x80000000) ? 1:0);
  $$inp[2] = ($$inp[2] << 1 & 0xffffffff) + (($$inp[3] & 0x80000000) ? 1:0);
  $$inp[3] = $$inp[3] << 1 & 0xffffffff;
}

# end of NetAddr::IP::UtilPP::_128x2
1;
