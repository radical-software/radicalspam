package Net::DNS::RR::NSEC3PARAM;

# $Id: NSEC3.pm 602 2006-07-24 14:23:15Z olaf $

use strict;
use vars qw(@ISA $VERSION);
use Carp;
use bytes;

use Net::DNS;
use Net::DNS::SEC;
use Net::DNS::Packet;
use Net::DNS::RR::NSEC;
use Data::Dumper;

use Carp qw(cluck);


# To be removed when finalized


@ISA     = qw(Net::DNS::RR Net::DNS::RR::NSEC3);



$VERSION = do { my @r=(q$Revision: 510 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };

sub new {
    my ($class, $self, $data, $offset) = @_;


    if ($self->{"rdlength"} > 0) {


	#                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
	#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#   | Hash Alg.     |  Flags Field  |         Iterations            |
	#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#   |  Salt Length  |                     Salt                      /
	#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#
	#   Hash Algorithm is a single octet.
	#
	#   Flags Field is a single octet.
	#
	#   Iterations is represented as a 16-bit integer, with the most
	#   significant bit first.
	#
	#   Salt Length represents the length of the following Salt field in
	#   octets.  If the value is zero, the Salt field is omitted.


      my $offsettoflag=$offset+1;
      my $offsettoits=$offset+2;
      my $offesttosaltlength=$offset+4;
      my $offsettosalt=$offset+5;

      $self->{"hashalgo"}=unpack("C",substr($$data,$offset,1));
      $self->{"flags"}=unpack("C",substr($$data,$offsettoflag,1));
      $self->{"iterations"}= unpack("n",substr($$data,$offsettoits,2));
      $self->{"saltlength"}=unpack("C",substr($$data,$offesttosaltlength,1));


      $self->{"saltbin"}=substr($$data,$offsettosalt,$self->{"saltlength"});
      $self->{"salt"}= unpack("H*",$self->{"saltbin"});

    }


    
    bless $self, $class;
    return $self;
}




sub new_from_string {
    my ($class, $self, $string) = @_;
    bless $self, $class;

    if ($string) {
      $string =~ tr/()//d;
      $string =~ s/;.*$//mg;
      $string =~ s/\n//mg;

      my ($hashalgo,$flags,$iterations,$salt)= 
	$string =~ /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S*)\s*$/;


      # This assumes that the digest type allocations follow the assignments as used for DS...
      defined($self->{'hashalgo'}=Net::DNS::SEC->digtype($hashalgo)) || 
		    return undef;
      defined($self->{'iterations'}=$iterations) || return undef;

      defined($self->{'flags'}=$flags) || return undef;
      
      defined($self->{"salt"}=$self->salt($salt)) || return undef;
      $self->{"saltbin"}=pack("H*",$salt) || return undef;
      $self->{saltlength}=length $self->{saltbin}; 

      
    }
    return $self;
}


sub rdatastr 
{
   my $self = shift;
   my $rdatastr;
   if (exists $self->{hashalgo}) 
   {
      $rdatastr .= $self->{hashalgo} ." ";
      $rdatastr .= $self->{flags}." ";
      $rdatastr .= $self->{iterations}. " ";
      $rdatastr .=   $self->salt()." \n";

   }
   else 
   {
      $rdatastr = "; no data"
   }
   $rdatastr
}

sub rr_rdata {
    my ($self, $packet, $offset) = @_;



    my $rdata = "" ;

    if (exists $self->{'hashalgo'}) {

      $rdata = pack("C",$self->{'hashalgo'});
      $rdata .= pack("C",$self->{'flags'});
      $rdata .= pack("n",$self->{'iterations'});
      unless( exists  $self->{"saltbin"}) {      
	if ($self->{"salt"} eq "-"){
	  $self->{"saltbin"}="";
	}else{
	  $self->{"saltbin"}=pack("H*",$self->{"salt"}) 

	}
      }
      $rdata .= pack("C",length($self->{'saltbin'}));
      $rdata .= $self->{'saltbin'};

    }
    
    return $rdata;
}





1;


=head1 NAME

Net::DNS::RR::NSEC3PARAM - DNS NSEC3PARAM resource record

=head1 SYNOPSIS

C<use Net::DNS::RR;>

=head1 DESCRIPTION

Class for DNS Address (NSEC3PARAM) resource records. 


The NSEC3PARAM RR contains the NSEC3 parameters (hash algorithm,
flags, iterations and salt) needed to calculate hashed ownernames.
The presence of an NSEC3PARAM RR at a zone apex indicates that the
specified parameters may be used by authoritative servers to choose an
appropriate set of NSEC3 records for negative responses.



=head1 METHODS

=head2 hashalgo

Reads and sets the hashalgo (hash algorithm) attribute. 

=head2 flags

Reads and sets the flag field. Check the IANA registry for valid values.
At the time of code release the only defined value was 0x00

=head2 iterations

Reads and sets the iterations field

=head2 salt

Reads and sets the salt value. Accepts and returns a string with a
number in hexadecimal notation.


=head1 COPYRIGHT

Copyright (c) 2007,2008  NLnet Labs.  Author Olaf M. Kolkman <olaf@net-dns.org>

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

Acknowledgements to Roy Arends who made a test version for this class
and whose code I've looked at before writing this module.

=head1 SEE ALSO

L<http://www.net-dns.org/> 
L<http://tools.ietf.org/wg/dnsext/draft-ietf-dnsext-nsec3>
L<Net::DNS::RR::NSEC3>,

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
RFC4033, RFC4034, RFC4035, RFC 5155

=cut
