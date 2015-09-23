package Net::DNS::RR::NSEC3;
# 
# $Id: NSEC3.pm 767 2008-12-24 10:02:25Z olaf $

use strict;
require Exporter;

use vars qw(
	@ISA 
	$VERSION 
	@EXPORT_OK
	%digestbyname
	%digestbyval
);


use Carp;
use bytes;
use MIME::Base64;
use MIME::Base32;

use Digest::SHA  qw(sha1 sha1_hex sha256 sha256_hex );

use Net::DNS qw( name2labels );
use Net::DNS::SEC;
use Net::DNS::Packet;
use Net::DNS::RR::NSEC;


#http://www.iana.org/assignments/dnssec-nsec3-parameters
%digestbyname = (
			"SHA1"		   => 1,		
			);      

@EXPORT_OK= qw (
		name2hash
               );


# Inherit a couple of methods from NSEC.
@ISA     = qw(Exporter Net::DNS::SEC Net::DNS::RR Net::DNS::RR::NSEC);



$VERSION = do { my @r=(q$Revision: 510 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };

sub new {
    my ($class, $self, $data, $offset) = @_;

    if ($self->{'rdlength'} > 0) {

      # section 3.1 of NSEC3 specs
      #                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
      #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   | Hash Alg.     |  Flags Field  |          Iterations           |
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |  Salt Length  |                     Salt                      /
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   |  Hash Length  |             Next Hashed Ownername             /
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      #   /                         Type Bit Maps                         /
      #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

      my $offsettoits=$offset+2;
      my $offsettoflags=$offset+1;
      my $offsettosaltlength=$offset+4;
      my $offsettosalt=$offset+5;
      $self->{'hashalgo'}=unpack("C",substr($$data,$offset,1));
      $self->{'flags'}=unpack("C",substr($$data,$offsettoflags,1));
      $self->{'iterations'}=unpack("n",substr($$data,$offsettoits,3));

      $self->{'saltlength'}=unpack("C",substr($$data,$offsettosaltlength,1));
      $self->{'saltbin'}=substr($$data,$offsettosalt,$self->{'saltlength'});
      $self->{'salt'}= unpack("H*",$self->{'saltbin'});

      my $offsettohashlength= $offsettosalt+$self->{'saltlength'};
      $self->{'hashlength'}=unpack("C",substr($$data,$offsettohashlength,1));

      $self->{'hnxtnamebin'}=substr($$data,$offsettohashlength+1,$self->{'hashlength'});
      $self->{'hnxtname'}=MIME::Base32::encode  $self->{'hnxtnamebin'};
      my $offsettotypebm=$offsettohashlength+1+$self->{'hashlength'};

      my $typebm =substr($$data,$offsettotypebm, $self->{'rdlength'}-$offsettotypebm +$offset );


      $self->{'typebm'}=$typebm;
      $self->{'typelist'} = join " " 
	,  Net::DNS::RR::NSEC::_typebm2typearray($typebm);
      
    }
    bless $self, $class;
    return $self;
}




sub new_from_string {
    my ($class, $self, $string) = @_;
    if ($string) {
      $string =~ tr/()//d;
      $string =~ s/;.*$//mg;
      $string =~ s/\n//mg;
      
      my ($hashalgo,$flags,$iterations,$salt,$hnxtname,$nxtstr)= 
	$string =~ /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s?(.*)/;
      my @nxttypes = split ' ' , $nxtstr;  # everything after last match...

      bless $self, $class;

      # This assumes that the digest type allocations follow the assignments as used for DS...

      #overwrite the digestby name table used by Net::DNS::SEC digtype
      $self->{'hashalgo'}=$self->digtype($hashalgo) || 
		    return undef;
      $self->{'flags'}=$flags;
      $self->{'iterations'}=$iterations;
      if ($salt eq '-') {$salt=''}; 
      $self->{'salt'}=$salt;
      $self->{'saltbin'}=pack("H*",$salt);
      $self->{'saltlength'}=length $self->{saltbin}; 

      $self->{'hnxtname'}= Net::DNS::stripdot($hnxtname);
      $self->{'hnxtnamebin'}=MIME::Base32::decode uc $hnxtname;

      $self->{'typelist'}= join " " , sort @nxttypes ;
      $self->{'typebm'}=Net::DNS::RR::NSEC::_typearray2typebm(@nxttypes);
      
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
      $rdatastr .=   $self->salt()." ";

      $rdatastr .= "(\n\t\t\t";
      $rdatastr .= $self->{hnxtname} . "\n";
      $rdatastr .= "\t\t\t$self->{typelist} )";
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

    if (exists $self->{'hnxtname'}) {
      $rdata = pack("C",$self->{'hashalgo'});
      $rdata .= pack("C", $self->{'flags'} );
      $rdata .= pack("n", $self->{'iterations'} );

      unless( exists  $self->{'saltbin'}) {      
	if ($self->{'salt'} eq "-"){
	     $self->{'saltbin'}="";
	}else{
	    $self->{'saltbin'}=pack("H*",$self->{'salt'}) 
	}
      }
      $rdata.= pack("C",length($self->{'saltbin'}));
      $rdata .= $self->{'saltbin'};

      $self->{'hnxtnamebin'}=MIME::Base32::decode(uc $self->{'hnxtname'}) unless 
	 exists  $self->{'hnxtnamebin'} ;
      $rdata.= pack("C",length($self->{'hnxtnamebin'}));
      $rdata .= $self->{'hnxtnamebin'};
      $rdata .= $self->typebm();

    }
    return $rdata;
}


sub _normalize_dnames {
	my $self=shift;
	$self->_normalize_ownername();
	$self->{'hnxtname'}= Net::DNS::stripdot($self->{'hnxtname'}) if defined $self->{'hnxtname'};
	$self->{'hnxtnamebin'}=MIME::Base32::decode(uc $self->{'hnxtname'});

}




sub salt {
  my ($self,$salt)=@_;
  if (defined $salt){
    if ($salt eq "-"){
      $self->{'salt'} = "" ;
    }else{
      $self->{'salt'} = $salt ;
      unless ($salt =~ /^[0-9a-f]*$/i ) {
	# print "input ($salt) not hex" ; 
	return undef;
      }
      $self->{'saltbin'} = pack("H*",$salt);
    }
  }
  return "-" if ($self->{'salt'} eq "");
  return $self->{'salt'};
}


sub name2hash {
  my $hashalg=shift;
  my $inname= lc shift;
  my $iterations=shift;
  my $saltbin=shift;

  my  $hashfunc;
  if ($hashalg==1){
    $hashfunc = sub {my $x=shift ; return sha1($x)};
  }elsif($hashalg==2){
    $hashfunc = sub {my $x=shift ; return sha256($x)};
  }else{
    return;
  }
  my $wirename=Net::DNS::RR->_name2wire($inname);
  my $i=0;
  for (0..$iterations)
    {
      $wirename=&$hashfunc($wirename.$saltbin);
    }
  return lc MIME::Base32::encode $wirename;


}



sub ownername {
	my $self=shift;
	if (defined $self->{'ownername'}){
		return $self->{'ownername'};
	}else{
		return $self->{'ownername'} = (name2labels($self->name))[0] ;
	}
	
}


sub _zonelabels {
    # Extracts the labels that make up the zone from the owner name of the 
    # record, simply by stripping the first label.
    # returns an array of labels in wire format.
    my $self=shift;
    unless (defined $self->{'zonelabels'}){
	my @labels= (name2labels($self->name)) ;
	shift @labels;
	$self->{'zonelabels'} =  \@labels ;

    }
    return @{$self->{'zonelabels'}};
}

sub _zone {
    # Returns the result from the zonelabels method in presentation
    # format (without trailing dot
    my $self=shift;
    my $name;
    foreach my $label ($self->zonelabels){
	$name .= wire2presentation($label) . ".";
    }
    chop($name);
    return $name;
}


sub optout {
    my ($self,$newval )= @_;
    if (defined ($newval)) {
	if ($newval){
	    $self->{'flags'} |= hex("0x01");
	}else{
	    $self->{'flags'} &= ~hex("0x01");
	}
    }

    return $self->{'flags'} & hex("0x01");
}



	
sub covered {
    my $self=shift;
    my $domainname=shift;

    # first test if the domain name is in the NSEC zone.
    my @domainlabels=name2labels($domainname);
    my @zonelabels= $self->_zonelabels();

    while (my $zlabel = pop @zonelabels ){
	my $dlabel= pop @domainlabels;
	return 0 unless ($dlabel eq $zlabel)
    }

    my $hashedname= Net::DNS::RR::NSEC3::name2hash(
	$self->hashalgo,
	$domainname,
	$self->iterations,
	$self->saltbin,
	);

    if ( ($self->ownername() cmp $self->hnxtname() )== 1 ) {
	# last name in the zone.
	return 1 if ( ( $hashedname cmp $self->hnxtname() ) == 1 );
	return 1 if ( ( $hashedname cmp $self->ownername() ) == -1  );
    }
    elsif ( ($self->ownername() cmp $self->hnxtname() )== 0 ) {
	# One entry in the zone.
	return 1;
    }else{
	return 1 if ( ($self->ownername() cmp $hashedname) == -1  )
	    &&
	    ( ( $hashedname cmp $self->hnxtname() ) == -1 );
    }
    return 0;
    
}



sub match {
    my $self=shift;
    my $domainname=shift;
    my $ownername=$self->ownername();
    my $hashedname= Net::DNS::RR::NSEC3::name2hash(
	$self->hashalgo,
	$domainname,
	$self->iterations,
	$self->saltbin
	);

    return $ownername eq $hashedname;

}





sub digtype {
    my $self=shift;
    $self->{'digestbyname'}= \%digestbyname;
    $self->_digtype(@_);
}



1;


=head1 NAME

Net::DNS::RR::NSEC3 - DNS NSEC3 resource record

=head1 SYNOPSIS

C<use Net::DNS::RR;>

=head1 DESCRIPTION

Class for DNS Address (NSEC3) resource records.

The NSEC3 Resource Record (RR) provides authenticated denial of
existence for DNS Resource Record Sets.  The NSEC3 RR lists RR types
present at the NSEC3 RR's original ownername.  It includes the next
hashed ownername in the hash order of the zone.  The complete set of
NSEC3 RRs in a zone indicates which RRsets exist for the original
ownername of the RRset and form a chain of hashed ownernames in the
zone.



=head1 METHODS

=head2 ownername

Returns the hashed value of the original owner name as contained in the first
label of the ownername of the record. 

   The owner name for the NSEC3 RR is the base32 encoding of the hashed
   owner name prepended as a single label to the name of the zone.

In other words the name(name) method returns the result of the
ownername() method prepended to the name of the containing zone.


=head2 optout

Reads and sets the opt-out attribute.


=head2 flags

Reads and sets the flag field. 

=head2 hashalgo

Reads and sets the hashalgo (hash algorithm) attribute. 

=head2 hnxtname

Reads and sets the hnxtname (hashed next ownername) attribute. 

=head2 typelist  (inhereted from NSEC)

    print "typelist" = ", $rr->typelist, "\n";

Returns a string with the list of qtypes for which data exists for
this particular label.


=head2 typebm  (inhereted from NSEC)

    print "typebm" = " unpack("B*", $rr->typebm), "\n";

Same as the typelist but now in a representation  bitmap as in 
specified in the RFC. This is not the kind of method you will need
on daily basis.


=head2 covered, matched

    print "covered" if $rr->covered{'example.foo'}

covered returns a nonzero value when the the domain name provided as argument
is covered as defined in the NSEC3 specification:


   To cover:  An NSEC3 RR is said to "cover" a name if the hash of the
      name or "next closer" name falls between the owner name and the
      next hashed owner name of the NSEC3.  In other words, if it proves
      the nonexistence of the name, either directly or by proving the
      nonexistence of an ancestor of the name.




Similarly ismatched returns a nonzero value when the domainname in the argument
matches as defined in the NSEC3 specification:

   To match: An NSEC3 RR is said to "match" a name if the owner name
      of the NSEC3 RR is the same as the hashed owner name of that
      name.



=head1 Functions

=head2 name2hash

Takes the hash identifyer (numeric), a fullyqualfied domain name, the
number of iterations and a binary salt to compute the hash value used
in the NSEC3 calculations.

    $hashalg=Net::DNS::SEC->digtype("SHA1");
    $salt=pack("H*","aabbccdd");
    $iterations=12;
    $name="*.x.w.example";

    $hashedname= Net::DNS::RR::NSEC3::name2hash($hashalg,$name,$iterations,$salt);
    print $hashedname;
results in:
    92pqneegtaue7pjatc3l3qnk738c6v5m

Normally the salt and itterations would be fetched from an NSEC3PARAM record.



=head1 COPYRIGHT

Copyright (c) 2007, 2008  NLnet Labs.  Author Olaf M. Kolkman <olaf@net-dns.org>

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
L<http://www.iana.org/assignments/dnssec-nsec3-parameters>
L<Net::DNS::RR::NSEC3PARAM>,
L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
RFC4033, RFC4034, RFC4035, RFC5155

=cut
