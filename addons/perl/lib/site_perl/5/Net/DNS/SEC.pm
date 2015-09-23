#
# $Id: SEC.pm 767 2008-12-24 10:02:25Z olaf $
#

use strict;



package Net::DNS::SEC;
use Net::DNS;
use bytes;
use Carp;
use strict;
use Exporter;
use vars qw($SVNVERSION $VERSION $HAS_NSEC3 $HAS_DLV @EXPORT_OK @ISA);
@ISA=qw(Exporter);
$VERSION = '0.15';

$HAS_DLV=1;     # Signals availability of DLV to Net::DNS::RR
$HAS_NSEC3=1;   # Signals availability of NSEC3 to Net::DNS::RR


$SVNVERSION = (qw$LastChangedRevision: 767 $)[1];


@EXPORT_OK= qw (
              key_difference
              verify_selfsig
               );


=head1 NAME

Net::DNS::SEC - DNSSEC extensions to Net::DNS

=head1 SYNOPSIS

C<use Net::DNS;>

The Net::DNS::SEC module implements a few class methods used by the
other modules in this suite and a few functions that can be exported.


=head1 DESCRIPTION

The Net::DSN::SEC suite provides the resource records that are needed
for DNSSEC (RFC 4033, 4034 and 4035). In addition the DLV RR, a clone
of the DS RR is supported (RFC 4431)

It also provides support for SIG0. That later is useful for dynamic
updates using key-pairs.

RSA and DSA crypto routines are supported.

For details see L<Net::DNS::RR::RRSIG>, L<Net::DNS::RR::DNSKEY>,
L<Net::DNS::RR::NSEC>, L<Net::DNS::RR:DS>, L<Net::DNS::RR::DLV>, and
see L<Net::DNS::RR::SIG> and L<Net::DNS::RR::KEY> for the use with
SIG0.

Net::DNS contains all needed hooks to load the Net::DNS::SEC
extensions when they are available.

See L<Net::DNS> for general help.

=head1 Utility function

Use the following construct if you want to use thos function in your code.

   use Net::DNS::SEC qw( key_difference );


=head2 key_difference

    $result=key_differnece(\@a,\@b,\@result);


Fills @result with all keys in the array "@a" that are not in the
array "@b".

Returns 0 on success or an error message on failure.


=cut



sub key_difference {
    my $a=shift;
    my $b=shift;
    my $r=shift;

    my %b_index;
    foreach my $b_key (@$b){
	return "Second array contains something different than a ".
	    "Net::DNS::RR::DNSKEY objects (".ref($b_key).")" if
	    ref($b_key) ne "Net::DNS::RR::DNSKEY";
	    
	$b_index{$b_key->name."+".$b_key->algorithm."+".$b_key->keytag}++;
    }
    foreach my $a_key (@$a){
	return "First array contains something different than a ".
	    "Net::DNS::RR::DNSKEY objects (".ref($a_key).")" if
	    ref($a_key) ne "Net::DNS::RR::DNSKEY";

	push @$r,$a_key  unless 
	    defined ($b_index{$a_key->name."+".$a_key->algorithm."+".$a_key->keytag});
    }
    return (0);
}


=head1 Class methods

These functions are inherited by relevant Net::DNS::RR classes. They
are not exported.

=head2 algorithm

    $value=Net::DNS::SEC->algorithm("RSASHA1");
    $value=$self->algorithm("RSASHA1");
    $value=$self->algorithm(5);

    $algorithm=$self->algorithm();
    $memonic=$self->algorithm("mnemonic");


The algorithm method is used to set or read the value of the algorithm
field in Net::DNS::RR::DNSKEY and Net::DNS::RR::RRSIG.

If supplied with an argument it will set the algorithm accordingly, except
when the argument equals the string "mnemonic" the method will return the
mnemonic of the algorithm.

Can also be called as a class method to do Mnemonic to Value conversion.

=head2 digtype

    $value=$self->digtype("SHA1");
    $value=$self->digtype(1);

    $algorithm=$self->digtype();
    $memonic=$self->digtype("mnemonic");


The algorithm method is used to set or read the value of the digest or
hash algorithm field in Net::DNS::RR::DS and Net::DNS::RR::NSEC3
objects.

If supplied with an argument it will set the digetstype/hash algorithm
accordingly, except when the argument equals the string "mnemonic" the
method will return the mnemonic of the digetstype/hash algorithm.

Can also be called as a class method to do Mnemonic to Value
conversion, note however that it will then use the "Delegation Signer
(DS) Resource Record (RR) Type Digest Algorithms" and not the "DNSSEC
NSEC3 Hash Algorithms" IANA registry. If you want to specifically get
access to the NSEC3  digest types then use a construct like:

 bless $self, Net::DNS::RR::NSEC3;
 $self->digtype("SHA1");




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


 
=head1 SEE ALSO

L<http://www.net-dns.org/> 


L<perl(1)>, L<Net::DNS>, L<Net::DNS::RR::KEY>, L<Net::DNS::RR::SIG>,
L<Net::DNS::RR::DNSKEY>, L<Net::DNS::RR::RRSIG>,
L<Net::DNS::RR::NSEC>, L<Net::DNS::RR::DS>, L<Net::DNS::SEC::Private>.

RFC4033, 4034 and 4035.

=cut






 sub algorithm {
    my $self=shift;
    my $argument=shift;

   # classmethod is true if called as class method.
    my $classmethod=0;
    $classmethod=1 unless  ref ($self);
 
    my %algbyname = (
	"RSAMD5"		   => 1,		
	"DH"                  => 2,           # Not implemented
	"DSA"                 => 3,
	"ECC"                 => 4,           # Not implemented
	"RSASHA1"             => 5,
	"DSA-NSEC3-SHA1"      => 6,
	"RSA-NSEC3-SHA1"      => 7,
	"INDIRECT"            => 252,         # Not implemented
	"PRIVATEDNS"          => 253,          # Not implemented
	"PRIVATEOID"          => 254,          # Not implemented
	);      
    my %algbyval = reverse %algbyname;

    # If the argument is undefined...
    
    if (!defined $argument){
	return if $classmethod;
	return $self->{"algorithm"};
    }

    # Argument has some value...
    $argument =~ s/\s//g; # Remove strings to be kind
    $argument =~ s!RSA/!RSA!;  # Be kind for those who use RSA/SHA1
    if ($argument =~ /^\d+$/ ){    #Numeric argument.

	if ($classmethod){
	    return $argument ;
	}else{
	    return $self->{"algorithm"}=$argument ;
	}
    }else{  # argument is not numeric
	if ($classmethod){
	    # This will return undefined if the argument does not exist
	    return $algbyname{uc($argument)};
	    
	}else{ # Not a class method..
	    if (lc($argument) eq "mnemonic"){
		return $algbyval{$self->{"algorithm"}};
	    }else{
		# This will return undefined if the argument does not exist
		return $self->{"algorithm"}=$algbyname{uc($argument)};
	    }	    
	}

	
    }	
    die "algorithm method should never end here";

	
}







sub digtype {
    _digtype(@_);
}

sub _digtype {
    my $self=shift;
    my $argument=shift;
    # classmethod is true if called as class method.
    my $classmethod=0;
    $classmethod=1 unless  ref ($self);

    my %digestbyname= (
			"SHA1"		   => 1,		
			"SHA256"	   => 2,		
			);      

    
    if (! $classmethod && defined ($self->{'digestbyname'}) ){
	%digestbyname= %{$self->{"digestbyname"}};
    }


    my %digestbyval = reverse %digestbyname;
    
    # If the argument is undefined...
    
    if (!defined $argument){
	return if $classmethod;
	return $self->{"digest"};
    }

    # Argument has some value...
    $argument =~ s/\s//g; # Remove strings to be kind

    if ($argument =~ /^\d+$/ ){    #Numeric argument.
	carp "$argument does not map to a valid digest" unless 
	    exists $digestbyval{$argument};
	if ($classmethod){
	    return $argument ;
	}else{
	    return $self->{"digest"}=$argument ;
	}
    }else{  # argument is not numeric
	if ($classmethod){
	    carp "$argument does not map to a valid digest" unless
		exists $digestbyname{uc($argument)};
	    return $digestbyname{uc($argument)};
	    
	}else{ # Not a class method..
	    if (lc($argument) eq "mnemonic"){
		return $digestbyval{$self->{"digest"}};
	    }else{
		carp "$argument does not map to a valid digest" unless
		    exists $digestbyname{uc($argument)};
		return $self->{"digest"}=$digestbyname{uc($argument)};
	    }	    
	}

	
    }	
    die "digest method should never end here";

	
}






