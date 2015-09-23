# NOTE: Derived from blib/lib/NetAddr/IP.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package NetAddr::IP;

#line 1067 "blib/lib/NetAddr/IP.pm (autosplit into blib/lib/auto/NetAddr/IP/compactref.al)"
sub compactref($) {
#  my @r = sort { NetAddr::IP::Lite::comp_addr_mask($a,$b) } @{$_[0]}		# use overload 'cmp' function
#	or return [];
#  return [] unless @r;

  return [] unless (my @unr = @{$_[0]});

  foreach(0..$#unr) {
    $unr[$_]->{addr} = $unr[$_]->network->{addr};
  }
  my @r = sort @unr;

  my $changed;
  do {
	$changed = 0;
	for(my $i=0; $i <= $#r -1;$i++) {
	  if ($r[$i]->contains($r[$i +1])) {
	    splice(@r,$i +1,1);
	    ++$changed;
	    --$i;
	  }
	  elsif ((notcontiguous($r[$i]->{mask}))[1] == (notcontiguous($r[$i +1]->{mask}))[1]) {		# masks the same
	    if (hasbits($r[$i]->network->{addr} ^ $r[$i +1]->network->{addr})) {	# if not the same netblock
	      my $upnet = $r[$i]->copy;
	      $upnet->{mask} = shiftleft($upnet->{mask},1);
	      if ($upnet->contains($r[$i +1])) {					# adjacent nets in next net up
		$r[$i] = $upnet;
		splice(@r,$i +1,1);
		++$changed;
		--$i;
	      }
	    } else {									# identical nets
	      splice(@r,$i +1,1);
	      ++$changed;
	      --$i;
	    }
	  }
	}
  } while $changed;
  return \@r;
}

# end of NetAddr::IP::compactref
1;
