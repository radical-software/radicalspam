package Net::DNS::RR::DS;

# $Id: DS.pm 728 2008-10-12 09:02:24Z olaf $


use strict;
use vars qw(@ISA $VERSION $_Babble);

use Net::DNS;
use Carp;

use Digest::SHA  qw(sha1 sha1_hex sha256 sha256_hex );

BEGIN {

    $_Babble=0;    
    $_Babble=1 unless (eval "require Digest::BubbleBabble; import Digest::BubbleBabble qw(bubblebabble)") ;

}





$VERSION = do { my @r=(q$Revision: 728 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };
my $debug=0;

@ISA = qw(Net::DNS::RR);

sub new {
    my ($class, $self, $data, $offset) = @_;
    if ($self->{"rdlength"} > 0) {
	
	my $offsettoalg=$offset+2;
	my $offsettodigtype=$offset+3;
	my $offsettodigest=$offset+4;
	my $digestlength;


	$self->{"keytag"}=unpack("n",substr($$data,$offset,2));
	$self->{"algorithm"}=unpack("C",substr($$data,$offsettoalg,1));
	$self->{"digtype"}=unpack("C",substr($$data,$offsettodigtype,1));
	if ($self->{"digtype"}==1){
	    $digestlength=20; # SHA1 digest 20 bytes long
	}elsif($self->{"digtype"}==2){
	    $digestlength=32; # SHA256 digest 32 bytes long
	}else{
	    $digestlength=0;
	}
	
	$self->{"digestbin"}= substr($$data,$offsettodigest,
				     $digestlength); 


	$self->{"digest"}= unpack("H*",$self->{"digestbin"});
	
	
    }
    return bless $self, $class;
}





sub new_from_string {
	my ($class, $self, $string) = @_;
	if ($string) {
		$string =~ tr/()//d;
		$string =~ s/;.*$//mg;
		$string =~ s/\n//g;
		my ($keytag,  $algorithm, $digtype, $digest) = 
		    $string =~ /^\s*(\S+)\s+(\S+)\s+(\S+)\s+((\S+\s*)+)/;
		# We allow spaces in the digest.
		$digest=~s/\s//g;
		$self->{"keytag"}=$keytag;
		$self->{"algorithm"}=Net::DNS::SEC->algorithm($algorithm)|| 
		    return undef;		
		$self->{"digtype"}=Net::DNS::SEC->digtype($digtype) || 
		    return undef;
		$self->{"digest"}=$digest;
		$self->{"digestbin"}=pack("H*",$digest);
	    }
	return bless $self, $class;
}



sub rdatastr {
	my $self = shift;
	my $rdatastr;
	if (exists $self->{"keytag"}) {
	    $rdatastr  = $self->{keytag};
	    $rdatastr .= "  "  . "$self->{algorithm}";
	    $rdatastr .= "  "  . "$self->{digtype}";
	    $rdatastr .= "  "  . "$self->{digest}";
	    $rdatastr .= " ; ".$self->babble if $_Babble;   
	    }
	else {
	    $rdatastr = "; no data";
	}

	return $rdatastr;
}

sub rr_rdata {
    my $self = shift;
    my $rdata;
    if (exists $self->{"digest"}) {
      $rdata= pack("n",$self->{"keytag"}) ;
      $rdata.= pack("C",  $self->{"algorithm"}) ;
      $rdata.= pack("C",  $self->{"digtype"}) ;
      $rdata.= $self->digestbin;
    }
    return $rdata;
}

sub verify {
    my ($self, $key) = @_;
    my $tstds=create Net::DNS::RR::DS($key,(
					  digtype => $self->digtype,
				      )
	);
    if ($tstds->digestbin eq $self->digestbin){
	return 1;
    }else{
	return 0;
    }
}




sub babble {
    my $self=shift;
    if ($_Babble){
        return bubblebabble(Digest=>$self->digestbin);
    }else{
	return("");
    }
}


sub digestbin {
    my ($self,$new_val)=@_;

    if (defined $new_val) {
	$self->{"digestbin"} = $new_val;
	$self->{"digest"} = unpack("H*",$new_val);
	return  $self->{"digestbin"};
    }
    

    $self->{"digestbin"}=pack("H*",$self->{"digest"}) unless(  $self->{"digestbin"} ); 
    return $self->{"digestbin"};


}

sub create {
    my ($class, $keyrr ,%args) = @_;

    my $self;

    # Default SHA1...
    $self->{"digtype"}=1;
   
    if ($args{"digtype"}){
	$self->{"digtype"}=2 if Net::DNS::SEC->digtype($args{"digtype"})==2;
    }
    
    $self->{"name"}=$keyrr->name;  # Label is per definition the same as 
                                   # keylabll
    $self->{"type"}="DS";
    $self->{"class"}="IN";
    
    if ($args{ttl}){
	print "\nSetting TTL to ".  $args{"ttl"} if $debug;
	$self->{"ttl"}= $args{"ttl"};
    }else{
	$self->{"ttl"}= $keyrr->ttl;
    }


    # The key must not be a NULL key.
    if (($keyrr->{"flags"} & hex("0xc000") ) == hex("0xc000") ){
	croak "\nCreating a DS record for a NULL key is illegal";
    }
    

    # Bit 0 must not be set.
    if (($keyrr->{"flags"}) & hex("0x8000")) {
	croak "\nCreating a DS record for a key with flag bit 0 set ".
	    "to 0 is illegal";
    }
    
    # Bit 6 must be set to 0 bit 7 must be set to 1
    if ( ($keyrr->{"flags"} & hex("0x300")) != hex("0x100")){
	croak "\nCreating a DS record for a key with flags 6 and 7 not set ".
	    "0  and 1 respectively is illegal";
    }
    

    if ($keyrr->{"protocol"}  != 3 ){
	croak "\nCreating a DS record for a non DNSSEC (protocol=3) ".
	    "key is illegal";
    }

    $self->{"keytag"}=$keyrr->keytag;
    $self->{"algorithm"}=$keyrr->algorithm;

    my $data = $keyrr->_name2wire ($keyrr->name) . $keyrr->_canonicalRdata;

    if ($self->{"digtype"}==1){
	$self->{"digestbin"}=  sha1($data);
	$self->{"digest"}= uc(sha1_hex($data));
    }elsif($self->{"digtype"}==2){
	$self->{"digestbin"}=  sha256($data);
	$self->{"digest"}= uc(sha256_hex($data));
    }else{
	return undef;
    }

    return bless $self, $class;


}

1;


=head1 NAME

Net::DNS::RR::DS - DNS DS resource record

=head1 SYNOPSIS

C<use Net::DNS::RR;>

=head1 DESCRIPTION

Class for Delegation signer (DS) resource records.

=head1 METHODS

In addition to the regular methods 


=head2 create

This constructor takes a key object as argument and will return a DS
RR object.

$dsrr=create Net::DNS::RR::DS($keyrr, (
                  digtype => "SHA256"
);
$keyrr->print;
$dsrr->print;

The digest type defaults to SHA1.

=head2 verify

The verify method will return 1 if the hash over the key provided in
the argument matches the data in the $dsrr itself i.e. if the DS
pointing to the DNSKEY from the argument. It will return 0
otherwise.

$dsrr->($keyrr);


=head2 algorithm

    print "algoritm" = ", $rr->algorithm, "\n";

Returns the RR's algorithm field in decimal representation

    1 = MD5 RSA
    2 = DH
    3 = DSA
    4 = Elliptic curve

=head2 digest

    print "digest" = ", $dsrr->digest, "\n";

Returns the SHA1 digest over the label and key in hexadecimal representation


=head2 digestbin

    $digestbin =  $dsrr->digestbin;

Returns the digest as  binary material

=head2 keytag

    print "keytag" ." = ". $dsrr->keytag . "\n";

Returns the key tag of the key. (RFC2535 4.1.6)


=head2 digtype

   print "digest type" . " = " . $dsrr->digtype ."\n";

Returns the digest type of the DS RR.

=head2 babble

   print $dsrr->babble;

Returns the 'BabbleBubble' representation of the digest. The
'BabbleBubble' string may be handy for telephone confirmation.

The 'BabbleBubble' string returned as a comment behind the RDATA when
the string method is called.



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
RFC 4033, RFC4034, RFC4035

=cut





