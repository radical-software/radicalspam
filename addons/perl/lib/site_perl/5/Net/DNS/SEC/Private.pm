package Net::DNS::SEC::Private;

use vars qw(@ISA $VERSION @EXPORT );

use Net::DNS;
use Carp;

use bytes;

use Crypt::OpenSSL::DSA;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;

use File::Basename;
use MIME::Base64;
use Math::BigInt;
use Time::Local;


require Exporter;

$VERSION = do { my @r=(q$Revision: 543 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };

sub new {
    my ($class,  $key_file) = @_;
    my $self={};
    my    ($Modulus,$PublicExponent,$PrivateExponent,$Prime1,
	   $Prime2,$Exponent1,$Exponent2,$Coefficient,
	   $prime_p,$subprime_q,$base_g,$private_val_x,$public_val_y);
    

    bless ($self,$class);
    my $keyname=basename($key_file);
    print "\nKeyname:\t ". $keyname ."\n" if $ debug;

    #Format something like: /Kbla.foo.+001+60114.private'
    # assuming proper file name.
    # We determine the algorithm from the filename.
    if ($keyname =~ /K(.*)\.\+(\d{3})\+(\d*)\.private/){
	$self->{"signame"}=$1.".";
	$self->{"algorithm"}= 0 + $2; #  Force non-string 
	$self->{"keytag"}=$3;
    }else{
	croak "$keyname does not seem to be a valid private key\n";
    }



    open (KEYFH, "<$key_file" ) || croak "Cannot open keyfile: $key_file";
    
    
    while (<KEYFH>) {
	if (/Private-key-format: (v\d*\.\d*)/) {
	    if ($1 ne "v1.2") {
		croak "Private Key Format not regognized";
	    }
	}elsif	    (/^Algorithm:\s*(\d*)/) {
	    if ($1 != 1 && $1 != 3 && $1 != 5) {
		croak "Key $key_file algorithm is not RSA or DSA (those are the only implemented algorithms) ";
	    }
	    
	} elsif (/^Modulus:\s*(\S+)/) {				#RSA 
	  $Modulus=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^PublicExponent:\s*(\S+)/) {

	  $PublicExponent=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^PrivateExponent:\s*(\S+)/) {
	    $PrivateExponent=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Prime1:\s*(\S+)/) {
	    $Prime1=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Prime2:\s*(\S+)/) {
	    $Prime2=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Exponent1:\s*(\S+)/) {
	    $Exponent1=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Exponent2:\s*(\S+)/) {
	    $Exponent2=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Coefficient:\s*(\S+)/) {
	    $Coefficient=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));

	} elsif (/^Prime\(p\):\s*(\S+)/) {				#DSA
	    $prime_p=decode_base64($1);
	} elsif (/^Subprime\(q\):\s*(\S+)/) {
	    $subprime_q=decode_base64($1);
	} elsif (/^Base\(g\):\s*(\S+)/) {
	    $base_g=decode_base64($1);
	} elsif (/^Private_value\(x\):\s*(\S+)/) {
	    $private_val_x=decode_base64($1);
	} elsif (/^Public_value\(y\):\s*(\S+)/) { 
	    $public_val_y=decode_base64($1);
	}
    }
    close(KEYFH);

    if ($self->{"algorithm"} == 1 || $self->{"algorithm"} == 5) {  #RSA
      $self->{'privatekey'}=Crypt::OpenSSL::RSA-> 
	  new_key_from_parameters(
	      $Modulus,
	      $PublicExponent,
	      $PrivateExponent,
	      $Prime1,
	      $Prime2,
	      $Exponent1,
	      $Exponent2,
	      $Coefficient,
	);

      # Trying to determine the keytag

      my $keytag_from_data1=$self->dump_rsa_keytag(256,1);
      my $keytag_from_data2=$self->dump_rsa_keytag(257,1);
      if (($self->{"keytag"} != $keytag_from_data1) &&
	  ($self->{"keytag"} != $keytag_from_data2)){
	  warn "NB: filename seems to have the wrong keytag.\n".
	      "Depending on DNSKEY RR flags set for this key the keytag should be\n".
	      $keytag_from_data1. " or ".  $keytag_from_data2. " instead of ".$self->{"keytag"}."\n";
	  return(0);
      }
      
    }elsif ($self->{"algorithm"} == 3){  #DSA
	my $private_dsa = Crypt::OpenSSL::DSA->new();
	$private_dsa->set_p($prime_p);
	$private_dsa->set_q($subprime_q);
	$private_dsa->set_g($base_g);
	$private_dsa->set_priv_key($private_val_x);
	$private_dsa->set_pub_key($public_val_y);
	$self->{"privatekey"}=$private_dsa;
    }
    return $self;

}




sub algorithm {
    my $self=shift;
    return $self->{'algorithm'};
}


sub privatekey {
    my $self=shift;
    return $self->{'privatekey'};
}


sub keytag {
    my $self=shift;
    return $self->{'keytag'};
}



sub signame {
    my $self=shift;
    return $self->{'signame'};
}


# Little helper function to put a BigInt into a binary (unsigned,
#network order )

#sub bi2bin {
#    my($p, $l) = @_;
#    $l ||= 0;
#    my $base = Math::BigInt->new("+256");
#    my $res = '';
#    {
#        my $r = $p % $base;
#        my $d = ($p-$r) / $base;
#        $res = chr($r) . $res;
#        if ($d >= $base) {
#            $p = $d;
#            redo;
#        }
#        elsif ($d != 0) {
#            $res = chr($d) . $res;
#        }
#    }
#    $res = "\0" x ($l-length($res)) . $res
#        if length($res) < $l;
#    $res;
#}



sub new_rsa_priv {
    my ($class,  $keyblob,$signame,$flags) = @_;
    my $self={};
    bless ($self,$class);
    $self->{"signame"}=$signame;
    $self->{"algorithm"}=5;
    $self->{"flags"}=$flags;
    $self->{'privatekey'}=Crypt::OpenSSL::RSA->  
	new_private_key($keyblob);

    $self->{"keytag"}=$self->dump_rsa_keytag();
    return $self;
}

sub  dump_rsa_priv {
    my $self=shift;

    my ( $Modulus,$PublicExponent, $PrivateExponent, $Prime1, $Prime2, $Exponent1,
	 $Exponent2,$Coefficient )=$self->{"privatekey"}->get_key_parameters;
    my $string="Private-key-format: v1.2\n";
    $string .= "Algorithm: 5 (RSASHA1)\n";
    
    if (defined $Modulus 
	&& defined $PublicExponent 
	&& defined $PrivateExponent 
	&& defined $Prime1 
	&& defined $Prime2 
	&& defined $Exponent1 
	&& defined $Exponent2 
	&& $Coefficient ){
	$string .= "Modulus: ". encode_base64($Modulus->to_bin,"")."\n" ;
	$string .= "PublicExponent: ". encode_base64($PublicExponent->to_bin,"")."\n" ;
	$string .= "PrivateExponent: ". encode_base64($PrivateExponent->to_bin,"")."\n"; 
	$string .= "Prime1: ". encode_base64($Prime1->to_bin,"")."\n" ;
	$string .= "Prime2: ". encode_base64($Prime2->to_bin,"")."\n" ;
	$string .= "Exponent1: ". encode_base64($Exponent1->to_bin,"")."\n" ;
	$string .= "Exponent2: ". encode_base64($Exponent2->to_bin,"")."\n" ;
	$string .= "Coefficient: ". encode_base64($Coefficient->to_bin,"")."\n" ;
    }
    else  {
	$string= "";
    };
    return $string;
}


sub  dump_rsa_pub {
    my $self=shift;
    my ( $Modulus,$PublicExponent, $PrivateExponent, $Prime1, $Prime2, $Exponent1,
	 $Exponent2,$Coefficient )=$self->{"privatekey"}->get_key_parameters;
    
    return "" unless (defined  $Modulus && defined $PublicExponent);
    my $explength;
    my $pubexp=$PublicExponent->to_bin;
    if (length($pubexp)>255){
	$explength=pack("C",0).pack("n",length($pubexp));
    }else{
	$explength=pack("C",length($pubexp));
    }

    return encode_base64($explength.$pubexp.$Modulus->to_bin, "");
}


sub dump_rsa_keytag{
    my $self=shift;
    my $flags;
    if (defined $self->{"flags"}){
	$flags=$self->{"flags"}
    }else{
	$flags=shift;
    }
    return()  unless defined $flags;

    # This will set flag if empty before, note the undocumented
    # feature that a non-zero second argument to this function will
    # _not_ set the flag.
    $self->{"flags"}=$flags unless shift; 
    my $alg=$self->{"algorithm"};
    return () unless ($alg ==1 || $alg ==5);
    my $key=$self->dump_rsa_pub;
    return ()  unless $key;
    my $tmprr=Net::DNS::RR->new("tmp  IN DNSKEY $flags 3 $alg  $key");
    return $tmprr->keytag;
}

sub dump_rsa_private_der {
    my $self=shift;
    return $self->{"privatekey"}->get_private_key_string;

    }




sub generate_rsa {
    my ($class) =shift;
    my $name=shift;
    my $flags=shift;
    my $size=shift;
    $size=1024 if !defined ($size);
    my $good_entropy=shift;
    my $self={};
    bless ($self,$class);

    $self->{"signame"}=$name;  
    $self->{"algorithm"}= 5; #  Force non-string 
    if (defined($good_entropy)){
	Crypt::OpenSSL::Random::random_seed($good_entropy);
	  Crypt::OpenSSL::RSA->import_random_seed();
      }
    $rsa = Crypt::OpenSSL::RSA->generate_key($size);
    $self->{"privatekey"}=$rsa;
    $self->{"keytag"}=$self->dump_rsa_keytag($flags);
    return $self;
}




1;








=head1 NAME

Net::DNS::SEC::Private - DNS SIG Private key object

=head1 SYNOPSIS

use Net::DNS::SEC::Private;
my $private=Net::DNS::SEC::Private->new($keypath);

=head1 DESCRIPTION

Class containing a the private key as read from a dnssec-keygen
generate zonefile. The class is written to be used only in the context
of the Net::DNS::RR::SIG create method. This class is not designed to
interact with any other system.



=head1 METHODS

=head2 new

$private->new("/home/foo/ Kexample.com.+001+11567.private")

Creator method. The argument is the full path to a private key
generated by the BIND dnssec-keygen tool. Note that the filename contains
information about the algorithm and keyid.


=head2 private

$private->private

Returns the private key material. This is either a Crypt::OpenSSL::RSA
or Crypt::OpenSSL::DSA object. This is really only relevant to the
Net::DNS::RR::SIG class.


=head2  algorithm, keytag, signame
 
 $private->algorithm
 $private->keytag
 $private->signame

Returns components as determined from the filename and needed by
Net::DNS::RR::RRSIG.


=head1 RSASHA1 specific helper functions

These functions may be usefull to read and transfer BIND private keys to and
from X509 format.

=head2 new_rsa_private

Constructor method.

 my $private=Net::DNS::SEC::Private->new_rsa_private($keyblob,$domain,$flag);

Creates a Net::DNS::SEC::Private object from the supplied string.  For
the object to be useful you will have to provide the "domain" name for
which this key is to be used as the second argument and the flag
(either 256 or 257 for a non SEP and a SEP key respectivly).


The string should include the -----BEGIN...----- and -----END...-----
lines.  The padding is set to PKCS1_OAEP, but can be changed with the
use_xxx_padding methods

It is the same 

=head2 dump_rsa_priv

  my $bind_keyfilecontent=$private->dump_rsa_priv
  
Returns the content of a BIND private keyfile (Private-key-format: v1.2).

An empty string will be returned if not all parameters are available (please
supply the author with example code if this ever happens).

=head2 dump_rsa_pub

    my $bind_keyfilecontent=$private->dump_rsa_pub

Returns the publick key part of the DNSKEY RR.

Returns an empty string on failure.


=head2 dump_rsa_keytag
    
    my $flags=257;   # SEP key.
    my $keytag=$private->dump_rsa_keytag($flags);

This function will calculate the keyt with the value of the DNSKEY
flags as input.

The flags field may be needed in case it was not specified when the
key was created. If the object allready knows it's flags vallue the
input is ignored. 

returns undefined on failure

=head2 dump_rsa_private_der

    my $keyblob=$private->dump_rsa_privat_der

Return the DER-encoded PKCS1 representation of the private key. (Same format that
can be read with the read_rsa_private method.)

=head2 generate_rsa

    my $keypair=Net::DNS::SEC::Private->generate_rsa("example.com",$flag,1024,$random);
prin $newkey->dump_rsa_priv;
print $newkey->dump_rsa_pub();


Uses Crypt::OpenSSL::RSA generate_key to create a keypair.

First argument is the name of the key, the second argument is the flag
field (take a value of 257 for Keysigning keys and a value of 256 for
zone signing keys). The 3rd argument is the keysize.

If the 4th argument is defined it is passed to the
Crypt::OpenSSL::Random::random_seed method (see Crypt::OpenSSL::RSA
for details), not needed with a proper /dev/random.

=head1 Example

This is a code sniplet from the test script. First a new keypair is
generated.  An Net::DNS::RR object is created by constructing
the resource record string - using the dump_rsa_pub() method.

Then a self signature over the public key is created and verified.

    my $newkey=Net::DNS::SEC::Private->generate_rsa("example.com",257,1024);
    my $tstpubkeyrr= Net::DNS::RR->new ($newkey->signame .
                                    "  IN DNSKEY 257 3 5 ".
				    $newkey->dump_rsa_pub());
    # flags not needed as argument for dump_rsa_keytag
    $ since they where set by generate_rsa

    is($tstpubkeyrr->keytag,$newkey->dump_rsa_keytag(),
                "Consistent keytag calculation");

    my $sigrr= create Net::DNS::RR::RRSIG([$tstpubkeyrr],$newkey);
    is ($sigrr->keytag,$tstpubkeyrr->keytag,
            "Consisted keytag in the created signature");;

    ok($sigrr->verify([$tstpubkeyrr],$tstpubkeyrr), 
             "Self verification consistent.");









=head1 COPYRIGHT

Copyright (c) 2002-2005 RIPE NCC.  Author Olaf M. Kolkman <olaf@net-dns.org>

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


This code uses Crypt::OpenSSL which uses the openssl library


=head1 SEE ALSO

L<http://www.net-dns.org/>

L<perl(1)>, L<Net::DNS>, L<Net::DNS::RR::SIG>, L<Crypt::OpenSSL::RSA>,L<Crypt::OpenSSL::DSA>, RFC 2435 Section 4, RFC 2931.

=cut

