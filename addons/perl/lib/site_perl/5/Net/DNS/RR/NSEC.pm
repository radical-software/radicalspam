package Net::DNS::RR::NSEC;

# $Id: NSEC.pm 728 2008-10-12 09:02:24Z olaf $

use strict;
use vars qw(@ISA $VERSION);
use Carp;
use bytes;
use Net::DNS;
use Net::DNS::Packet;
use Data::Dumper;

use Carp;

@ISA = qw(Net::DNS::RR);
$VERSION = do { my @r=(q$Revision: 728 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };

sub new {
    my ($class, $self, $data, $offset) = @_;
    
    if ($self->{"rdlength"} > 0) {
	my($nxtdname,$nxtoffset) = 
	  Net::DNS::Packet::dn_expand($data, $offset);

	$self->{"nxtdname"} =  $nxtdname;

	my $typebm =substr($$data,$nxtoffset,
				 $self->{"rdlength"}-
				 $nxtoffset+$offset);

	$self->{"typebm"}=$typebm;
	$self->{"typelist"} = join " " 
	    ,  _typebm2typearray($typebm);
    }
    
    return bless $self, $class;
}

sub new_from_string {
    my ($class, $self, $string) = @_;
    if ($string) {
	$string =~ tr/()//d;
	$string =~ s/;.*$//mg;
	$string =~ s/\n//mg;
	my ($nxtdname,$nxtstr) = 
	    $string =~ /^\s*(\S+)\s+(.*)/;
	my @nxttypes = split ' ' , $nxtstr;  # everything after last match...
	
	$self->{"nxtdname"}=  Net::DNS::stripdot($nxtdname);
	$self->{"typelist"}= join " " , sort @nxttypes ;
	$self->{"typebm"}=_typearray2typebm(@nxttypes);
	
    }
    return bless $self, $class;
}




#sub is_optin {
#    my $self =shift;
#    return 1 if $self->{"typelist"}!~/NSEC/;
#    0;
#}

#sub set_optin {
#    my $self =shift;
#    $self->{"typelist"}=~s/NSEC//;
#    1;
#}

sub rdatastr {
	my $self = shift;
	my $rdatastr;

	
	if (exists $self->{"nxtdname"}) {
	    $rdatastr  = $self->{nxtdname}.".";
	    $rdatastr .= "  "  . $self->typelist();
	    }
	else {
	    $rdatastr = "; no data";
	}

	return $rdatastr;
}

sub rr_rdata {
    my ($self, $packet, $offset) = @_;


    my $rdata = "" ;
    if (exists $self->{"nxtdname"}) {
	# Compression used here... 
	$rdata = $packet->dn_comp(($self->{"nxtdname"}),$offset);
	$rdata .= $self->typebm();
    }
    
    return $rdata;
    
}




sub _normalize_dnames {
	my $self=shift;
	$self->_normalize_ownername();
	$self->{'nxtdname'}=lc(Net::DNS::stripdot($self->{'nxtdname'})) if defined $self->{'nxtdname'};
}





sub typebm {
    my ($self, $new_val) = @_;
				
    if (defined $new_val) {
	$self->{"typebm"} = $new_val;
	$self->{"typelist"}= join (" ",  _typebm2typearray($self->{"typebm"}));
    }

    $self->{"typebm"}= _typearray2typebm(split(' ',$self->{"typelist"})) unless $self->{"typebm"};
    return $self->{"typebm"};
}


sub typelist {
    my ($self, $new_val) = @_;
				
    if (defined $new_val) {
	$self->{"typelist"} = $new_val;
	$self->{"typebm"}= _typearray2typebm(split (' ',($self->{"typelist"})));
    }

    $self->{"typelist"}=  join (" ", 
 _typebm2typearray($self->{"typebm"})) unless $self->{"typelist"};

    return $self->{"typelist"};
}
	   


sub _canonicalRdata {
    # rdata contains a compressed domainname... that should not have
    # been done @specification time :-) 
	my ($self) = @_;
	my $rdata;
	$rdata=$self->_name2wire($self->{"nxtdname"});
	$rdata .= $self->{"typebm"};	
	return $rdata;
}


sub _typearray2typebm {


    # typebm= (WindowBlockNumber |BitmapLength|Bitmap)+

    my @typelist= @_;

    my $typebm="";
    my $CurrentWindowNumber=0;

    # $bm is an array of arrays.
    
    # The first index maps onto the CurrentWindowNumber and the array
    # contained has its index mapped to types. The vallues will be set
    # if there is data for a paricular type otherwise undef.
    
    my $bm;
  TYPE:   for(my $i=0;$i < @typelist; $i++){
 	use integer;
	my $typenumber=Net::DNS::typesbyname(uc($typelist[$i]));
	next TYPE if exists ($Net::DSN::qtypesbyname{uc($typelist[$i])});
	next TYPE if  exists ($Net::DSN::metatypesbyname{uc($typelist[$i])});
	# Do net set the bitmap for meta types or qtypes.
	    $CurrentWindowNumber= ($typenumber / 256); # use integer must be in scope..	
	$bm->[$CurrentWindowNumber]->[$typenumber-$CurrentWindowNumber*256] = 1;
	}
    
    # Turn the array of arrays referenced through $bm into the bitmap
    # as used in the RDATA

    for (my $i=0; $i < @{$bm}; $i++){
	if (defined ($bm->[$i])){
	    use integer;
	    my $BitmapLength=0;
	    $BitmapLength =  8 * ((@{$bm->[$i]} / 8) );
	    # Make sure the remaining bits fit...
	    $BitmapLength += 8 if (@{$bm->[$i]} % 8);
	    for (my $j=0;$j< $BitmapLength; $j++){
		$bm->[$i]->[$j]=0 if ! defined $bm->[$i]->[$j];
	    }

	    $typebm.= pack("CCB$BitmapLength",$i,$BitmapLength/8,
			   join ("", @{$bm->[$i]} ));
	}
    }
    return $typebm

}

sub _typebm2typearray {


    # This implements draft-ietfdnsext-nsec-rdata-01.
    # typebm= (WindowBlockNumber |BitmapLength|Bitmap)+

    my $typebm=shift;  # bit representation.
    my@typelist;
    while ($typebm){
	my ($WindowBlockNumber,$BitmapLength)=unpack("CC",$typebm);
	substr($typebm,0,2,"");
	my $Bitmap=substr($typebm,0,$BitmapLength,"");
	# Turn the Bitmap in an array...
	my @bm=split //, unpack("B*", $Bitmap);  # bit representation in arra

	for (my $i=0;$i < @bm; $i++){
	    @typelist=(@typelist,
		       Net::DNS::typesbyval($WindowBlockNumber*256+$i))	   
	      if $bm[$i];
	}
    }

    return sort @typelist;
}





1;


=head1 NAME

Net::DNS::RR::NSEC - DNS NSEC resource record

=head1 SYNOPSIS

C<use Net::DNS::RR;>

=head1 DESCRIPTION

Class for DNS Address (NSEC) resource records.

=head1 METHODS

=head2 nxtdname

    print "nxtdname" = ", $rr->nxtdname, "\n";

Returns the RR's next domain name field.


=head2 typelist

    print "typelist" = ", $rr->typelist, "\n";

Returns a string with the list of qtypes for which data exists for
this particular label.



=head2 typebm

    print "typebm" = " unpack("B*", $rr->typebm), "\n";

Same as the typelist but now in a representation  bitmap as in 
specified in the RFC. This is not the kind of method you will need
on daily basis.

=head1 COPYRIGHT

Copyright (c) 2001-2005  RIPE NCC.  Author Olaf M. Kolkman <olaf@net-dns.org>

All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of the author not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO EVENT SHALL
AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


Based on, and contains, code by Copyright (c) 1997 Michael Fuhr.



=head1 SEE ALSO

L<http://www.net-dns.org/> 

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
RFC4033, RFC4034, RFC4035.

=cut
