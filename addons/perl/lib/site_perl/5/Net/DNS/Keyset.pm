
# $Id: Keyset.pm 728 2008-10-12 09:02:24Z olaf $


package Net::DNS::Keyset;
use Cwd;

=head1 NAME

    Net::DNS::Keyset - DNSSEC Keyset object class

=head1 SYNOPSIS


use Net::DNS::Keyset;

=head1 DESCRIPTION




A keyset is a "administrative" unit used for DNSSEC maintenance.

The bind dnssec-signzone tool uses it to genertate DS records. This class
provides interfaces for reading keysets, creating and parsing them.

Note that this class is still being developed. Attributes and methods
are subject to change.

=cut


use Data::Dumper;
use strict;
use Net::DNS;
use Carp;

use vars qw ( $VERSION @EXPORT $keyset_err );

( $VERSION ) = '$Revision: 728 $ ' =~ /\$Revision:\s+([^\s]+)/;

my $debug=0;



sub new {
	my $retval;
	$keyset_err="No Error";
	if (@_ == 2 && ! ref $_[1] ) {
		$retval = new_from_file(@_);
	}
	elsif (@_ == 3 
	       && (ref($_[2]) eq "ARRAY")  &&
	       ref($_[2]->[0]) eq "Net::DNS::RR::RRSIG" &&
	      (ref($_[1]) eq "ARRAY")  &&
	       ref($_[1]->[0]) eq "Net::DNS::RR::DNSKEY" ) {
	    $retval = new_from_keys_sigs(@_);
	}elsif (@_ >= 2 && (ref($_[1]) eq "ARRAY")  &&
	       ref($_[1]->[0]) eq "Net::DNS::RR::DNSKEY" ) {
	    $retval = new_from_keys(@_);
	}elsif ( @_ == 2 &&  ref($_[1]) eq "Net::DNS::Packet"  ){
	    $retval = new_from_packet(@_);
	}else{
	     $keyset_err="Could not parse argument";
	     return(0);
	 }	
	return $retval;
}




=head2 new (from file)

    $keyset=Net::DNS::Keyset->new("keyset-example.tld");


Creator method, will read the specified keyset file and return a 
keyset object. Fails if not all keys in the set are self-signed.

Sets $Net::DNS::Keyset::keyset_err and returns 0 on failure.

=cut


sub new_from_file {
    my $class=shift;
    my $keysetfile=shift;

    $keyset_err="No Error";
    my $TTL;

    croak "need keysetfile as argumnt" if ! $keysetfile;

    open(KEYSET, $keysetfile)          # get sort's results
	|| croak "Can't open $keysetfile for input: $!";

    my $currentorigin;
    my $buffer="";
    my $previouslabel;
    my @keys;
    my $k=0;
    my @sigs;
    my $s=0;
    my %names;
    
    # We now read the keyset as if it is a (bind) zone file.  # To be
    #able to read the individual RRs into RR-objects we # have to fill
    #in the information that was conveniently left out # of the zone
    #file to make it more readable for us humans.  #


    # This is code I reused. There is a whole chunk of code for dncame
    # completion for RR types other than DNSKEY and RRSIG.  That may be
    # usefull # if you want to reuse the code for writing a zone
    # parser


    while (<KEYSET>){
	s/;.*//;  # Remove comments
	next if /^\s*$/ ;
	if (!$TTL && /^\s*\$TTL\s+(\d+)/){
	    $TTL=$1;
	    print ";; TTL found : ". $TTL ."\n" if $debug;
	    next;
	}
	
	
	
	# replace the @ by the ORIGIN.. as given by the argument.
	s/@/$currentorigin/;
	
	# Set the current originin. This is the one from the $ORINIGIN value from 
	# the zone file. It will be used to complete labels  below.
	if ( /^\s*\$ORIGIN\s+(\S+)\s*$/){
	    $currentorigin=$1;
	    print ";; currentorigin set to : ". $currentorigin ."\n" if $debug;
	    next;
	}
	# Join multilines to one line
	if ( $buffer ne ""){
	    if (s/\)//) {
		$buffer.=$_;
		$_=$buffer;
		$buffer="";
		s/\s+(\s)/$1/g;
	    }else{
		chop;
		$buffer.=$_;
		next;
	    }
	}elsif (s/\(//) {        
	    chop;
	    $buffer.=$_;
	    next;
	}
	s/\s+/ /g; #Single spaces .. eases future matching
	s/ $//;    #strips trailing space, that got introduced by the previous...
	
	# Use the previoous label if no label was qualified (line starts with blanks)
	if (/^(\S+) /){
	    $previouslabel=$1;
	}else{
	    $_ = $previouslabel . $_;
	}
	
	
	# Now we have
	# label  optional TTL  optional ClASS and QTYPE and RDATA
	# If the TTL and CLASS are not there we'll add them. Besides we'll
	# look at the QTYPE and may take some action to RDATA depending on that.
	
	{ #LOCALIZE SOME VARIABLES
	    my $label;
	    my $ttl=$TTL;
	    my $class='IN';  # We only considder IN
	    my $rtype='';
	    my $rdata='';
	    my $prefix='';
	    
	    # It should be easier to do this....
	    
	    s/^(\S+) / /;  # remove the label to put it back fully quallified
	    if ($1){
		
		$label=$1;
		_complete_dname($label,$currentorigin);
		$_ = $label . $_;
		print ";;    read LABEL: " . $label ."\n" if  $debug>2 ;
	    }else{
		croak "Couldnt match label in read method while reading\n". $_ . " \nthis Should not happen\n";
	    }
	    
	    
	    # See if there is a TTL value, if not insert one
	    if (/^\S+. (\d+)/) {
		print ";;    TTL   : " . $1. "\n" if  $debug>2 ;
		$ttl=$1;
	    }else {
		# instert default TTL
		s/^(\S+) (.*)$/$1 $ttl $2/;
	    }		
	    
	    
	    # See if there is the CLASS is defined, if not insert one.
	    if(! /^\S+ \d+ (IN)/){   
		#insert IN
		s/^(\S+ \d+ )(.*)$/$1IN $2/;
	    }
	    
	    
	    
	    # We have everything specified.. We now get the RTYPE AND RDATA...
	    /^\S+ \d+ IN (\S+) (.*)$/;
	    
	    
	    if ($1) {
		print ";;    rtype: " . $1 ."\n" if  $debug>2 ;
		$rtype=$1;
	    }else{
		croak " We expected to match an RTYPE\n". $_ . " \nthis Should not happen\n";
	    }
	    
	    if ($2) {
		$rdata=$2;	       
		print ";;    rdata:-->" . $rdata ."<---\n" if  $debug>3 ;
		
	    }else{
		croak " We expected a match RDATA\n". $_ . " \nthis Should not happen\n";
	    }
	    
	    $prefix=$label." ".$ttl." IN ".$rtype." ";
	    
	    
	} #END LOCALIZATION
	print ";;    " . $_ . "\n" if $debug>2;
	
	# The sting in $_ now contains a one-line RRset. We now turn it into
	# RR object.
	my $rr=Net::DNS::RR->new($_);
	if ($rr->type eq "DNSKEY") {
	    $keys[$k++]=$rr;
	    $names{$rr->name}=1;
	}elsif ($rr->type eq "RRSIG") {
	    $sigs[$s++]=$rr;
	    $names{$rr->name}=1;
	}else{
	    $keyset_err= "WARNING the following RR was found in a keyset and is not expected there\n".   $rr->string;
	    return(0);
	}
    }

    if ((keys %names )!=1){
	$keyset_err = "Different names in the keyset: ". 
	    join ( " ",(keys %names))."\n";
	return 0;
    }

    # @keys_and_sigs contains all keys and sigs from the RRset.
    

    my $ks;
    my $keyset;
    $keyset= {
	keys => [ @keys ],
	sigs => [ @sigs ],
    };
    bless $ks= $keyset, $class;
    return 0 if (! $ks->verify);
    return $ks;
}



=head2 new (by signing keys)

    $keyset=Net::DNS::Keyset->new(\@keyrr,$privatekeypath);

Creates a keyset object from the keys provided through the reference
to an array of Net::DNS::RR::Key objects.

The method will create selfsign the whole keyset. The private keys as
generated by the BIND dnssec-keygen tool are assumed to be in the
current directory or, if specified, in the directory indicat by the
$privatekeypath.

Sets $Net::DNS::Keyset::keyset_err and returns 0 on failure.

=cut



sub new_from_keys {
    my $class=shift;
    my $keyrr_ref=shift;
    my $privatekeypath=shift;
    $keyset_err="No Error";

    if (  defined $privatekeypath ){
	$privatekeypath =~ s!\/*\s*$!! ; #strip trailing spaces and slashes
	if (! -d $privatekeypath){
	    $keyset_err= "The file " . $privatekeypath . 
		" could not be found\n";
	    return 0;
	}
    }else{
	$privatekeypath=cwd;
    }
    my $key;
    my $privatekey;
    my @sigrr;
    my @keyrr;
    foreach $key (@{$keyrr_ref}){
	my $privkey= $privatekeypath."/".$key->privatekeyname;
	if (! -r $privkey){
	    $keyset_err= "private key  ".$privkey.
		"could not be found";
	    return 0;
	}
	my $sig=Net::DNS::RR::RRSIG->create($keyrr_ref,$privkey);
	push @sigrr, $sig;
	push @keyrr, $key;

    }

    my $ks;
    my $keyset= {
	keys => [ @keyrr ],
	sigs => [ @sigrr ],
    };
    bless $ks= $keyset, $class;
    return 0 if (! $ks->verify);
    return $ks;
}




=head2 new (from keys and sig RRsets)

    $keyset=Net::DNS::Keyset->new(\@keyrr,\@sigrr);

Creates a keyset object from the keys provided through the reference
to an array of Net::DNS::RR::DNSKEY and Net::DNS::RR::RRSIG objects.


Sets $Net::DNS::Keyset::keyset_err and returns 0 on failure.

=cut


sub new_from_keys_sigs{
    my $class=shift;
    my $keyrr_ref=shift;
    my $sigrr_ref=shift;

    my @sigrr;
    my @keyrr;

    
    foreach my  $key (@{$keyrr_ref}){
	push @keyrr, $key;

    }


    foreach my $sig (@{$sigrr_ref}){
	push @sigrr, $sig;

    }


    my $ks;
    my $keyset= {
	keys => [ @keyrr ],
	sigs => [ @sigrr ],
    };
    bless $ks= $keyset, $class;
    return 0 if (! $ks->verify);
    return $ks;

}


=head2 new (from Packet)

    $res = Net::DNS::Resolver->new;
    $res->dnssec(1);
   
    $packet = $res->query ("example.com", "DNSKEY", "IN");

    $keyset=Net::DNS::Keyset->new($packet)
    
    die "Corrupted selfsignature " if ! $keyset->verify;

Creates a keyset object from a Net::DNS::Packet that contains the
answer to a query for the apex key records.

This is the method you want to use for automatically fetching keys.

Sets $Net::DNS::Keyset::keyset_err and returns 0 on failure.

=cut


sub new_from_packet {
    my $class=shift;    
    my $packet=shift;

    my @sigrr;
    my @keyrr;

    $keyset_err="No Error";

    if (ref ($packet) ne "Net::DNS::Packet"){
	$keyset_err="Input is not a Net::DNS::Packet" ;
	return (0);
    }
	     
    # All the information is in the answer section. 
    # We expect keys and signatures there.
    foreach my $rr  ($packet->answer){
	if ($rr->type eq "RRSIG"){
	    push @sigrr, $rr;
	}
	elsif ($rr->type eq "DNSKEY")
	{
	    push @keyrr, $rr ;
	}else{
	    $keyset_err = "Unexpected RR in the answer section of the packet:\n".
		$rr->string."\n";
	    return (0);

	}
    }


    my $ks;
    my $keyset= {
	keys => [ @keyrr ],
	sigs => [ @sigrr ],
    };
    bless $ks= $keyset, $class;

    return 0 if (! $ks->verify);
    return $ks;


}




    


=head2 keys

    @keyrr=$keyset->keys;

Returns an array of Net::DNS::RR::Key objects

=cut

sub keys {
    my $self=shift;
    return @{$self->{'keys'}};
}


=head2 sigs

    @keyrr=$keyset->sigs;

Returns an array of Net::DNS::RR::Sig objects

=cut



sub sigs {
    my $self=shift;
    return @{$self->{'sigs'}};
}


=head2 verify
    
    die $Net::DNS::Keyset::keyset_err if $keyset->verify;

If no arguments are given:
    
    - Verifies if all signatures present verify the keyset.
    - Verifies if there are DNSKEYs with the SEP flag set there is
      at least one RRSIG made using that key
    - Verifies that if there are no DNSKEYS with the SEP flag set there is
      at lease one RRSIG made with one of the keys from the keyset.
    


If an argument is given it is should be the KEYID of one of the keys
in the keyset and the method verifies if the the RRSIG with that made
with that key verifies.

The argument returns 0 if verification fails and sets
$Net::DNS::Keyset::keyset_err.

If verification succeeds an array is returne with the key-tags of the
keys for which signatures verified.


=cut


    
sub verify {
    my $self=shift;
    my $keyid=shift;
    my $key;
    my $sig;
    



    my $one_sep_key_found=0;
    my $one_sep_key_validated=0;
    my $one_key_validated=0;
    my $key_id_found=0;
    my @tags_verified=();

    
  KEY:    foreach $key ($self->keys) {
      $one_sep_key_found=1 if $key->is_sep;
      foreach $sig ($self->sigs) {
	  print "Checking: " . $key->name .":". $key->keytag . 
	      ($key->is_sep?"(SEP)":"") .
	      "---" .
	      $sig->signame .":". $sig->keytag .  "\n" if $debug;
	  
	  if ($key->keytag == $sig->keytag &&
	      $key->name."." eq $sig->signame."." ){
	      print "...\n" if $debug;
		my @keys=$self->keys ;
		if (! $sig->verify( \@keys , $key)){
		    $keyset_err="" if ($keyset_err eq "No Error");
		    $keyset_err .= $sig->vrfyerrstr. " on key ". $key->name.			" ".$key->keytag ." ";

		    # If we did supply an argument we want to fail if
		    # the signature made with that keytag failed.

		    if (defined $keyid && $sig->keytag == $keyid ){
			$keyset_err= "Signature made with $keyid did not validate";
			return 0;
		    }
		    # If we did not supply an argument we want to fail if any 
		    # of the signatures failed
		    return 0 if (! defined $keyid);
		    
		    next KEY;
		}
	      push @tags_verified, $key->keytag;
	      # past verification
		$one_key_validated=1;
		$one_sep_key_validated=1 if $key->is_sep;    
		$key_id_found=1 if (defined $keyid && $key->keytag == $keyid );
		print "verified " .$key->keytag."\n" if $debug;

	    }
      }

  }
    if ($one_sep_key_found && ! $one_sep_key_validated){
	$keyset_err= "One key had the SEP flag set but non of the keys had a signature";
	return 0;
    }elsif(  ! $one_key_validated ){
	$keyset_err= "None of the keys in the keyset had a signature";
	return 0;
    }elsif ( defined($keyid) && ! $key_id_found ){
	$keyset_err= "No signature made with $keyid found";
	return 0;
    }
    @tags_verified = ($keyid) if defined ($keyid);
    return @tags_verified;
}


=head2 print

    $keyset->print;

Prints the keyset


=head2 string
    
    $keysetstring=$keyset->string;

Returns a string representation of the keyset

    print $keyset->string;
    is similar to
    $keyset->print;

=cut





sub string {
    my $self=shift;
    my $string;
    foreach my $rr ($self->keys,$self->sigs){
	$string .= $rr->string ."\n";
    }
    return $string;
}

sub print {
    my $self=shift;
    print $self->string;
}

=head2 extract_ds

    @ds=$keyset->extract_ds;
    foreach $ds (@ds) {
        $ds->print;
    }

Extracts DS records from the keyset. Note that the keyset will be verified
during extraction: All keys will need to have a valid selfsignature.

=cut
  
sub extract_ds {
    my $self=shift;
    $keyset_err="No error";
    my @ds;
   
    return (0) if (! $self->verify);

    foreach my $rr ($self->keys){
	my $ds=Net::DNS::RR::DS->create($rr);
	push @ds, $ds;
    }


    return (@ds);
}

=head2 writekeyset

    die $Net::DNS::Keyset::keyset_err if ! $keyset->writekeyset($prefix, $path);


Writes the keyset to a file named "keyset-<domain>." in the current
working directory or the directory defined by $path. $prefix specifies an
optional prefix that will be prepended to the string "keyset-<domain>."
Returns 0 on failure and sets keyset_err.

=cut

sub writekeyset {
    my $self=shift;
    my $prefix=shift;
    my $keysetpath=shift;
    $keyset_err="No Error";
    my $domainname=$self->{'keys'}->[0]->name;
    if (  defined $keysetpath ){
	$keysetpath =~ s!\/*\s*$!! ; #strip trailing spaces and slashes
	if (! -d $keysetpath){
	    $keyset_err= "Directory " . $keysetpath . 
		" could not be found\n";
	    return 0;
	} 
    }else {
	$keysetpath=cwd;
    }
    
    my $keysetname="$keysetpath/$prefix" . "keyset-$domainname.";
    if (! open(KEYSET,"> $keysetname")   ){
	$keyset_err= " Could not open $keysetname for writing";
	return 0;
    }
    print KEYSET $self->string;
    return (1);
}



sub _complete_dname
{
    my $dname=shift;
    my $origin=shift;
    if ( $dname !~ /\.$/ ){       
	# breaks if a label ends in an escapped \. 
	# Is that allowed?
	$dname .= ".".$origin;
    }
    return $dname;
}





1;
__END__


=head1 COPYRIGHT

Copyright (c) 2002 RIPE NCC.  Author Olaf M. Kolkman
<net-dns-sec@ripe.net>

All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of the author not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO
EVENT SHALL AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

=cut

