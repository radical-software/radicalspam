# perldoc RRSIG.pm for documentation.
# Specs: RFC 2535 section 4
# $Id: RRSIG.pm 777 2008-12-30 17:18:54Z olaf $

package Net::DNS::RR::RRSIG;

use vars qw(@ISA $VERSION @EXPORT );

use Net::DNS;
use Carp;
use bytes;
use Data::Dumper;

use Crypt::OpenSSL::DSA;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;
use Net::DNS::SEC::Private;

use File::Basename;
use MIME::Base64;
use Math::BigInt;
use Time::Local;
use Digest::SHA qw (sha1);





#
# Most of the cryptovariables should be interpred as unsigned
#
#


require Exporter;

$VERSION = do { my @r=(q$Revision: 777 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };
@ISA = qw (
	   Exporter
  	 Net::DNS::RR
  	 Net::DNS::SEC
	   );


@EXPORT = qw (          
	      );




use strict;
my $crypt_open_ssl=1;
my $debug=0;




sub new {
    my ($class, $self, $data, $offset) = @_;

    if ($self->{"rdlength"} > 0) {
	#RFC2535 section 4.1
	my $offsettoalg=$offset+2;
	my $offsettolabels=$offset+3;
	my $offsettoorgttl=$offset+4;
	my $offsettosigexp=$offset+8;
	my $offsettosiginc=$offset+12;
	my $offsettokeytag=$offset+16;
	my $offsettosignm=$offset+18;

	$self->{"typecovered"}= _type2string(unpack("n",substr($$data,$offset,2)));
	$self->{"algorithm"}=unpack("C",substr($$data,$offsettoalg,1));
	$self->{"labels"}=lc(unpack("C",substr($$data,$offsettolabels,1)));
	$self->{"orgttl"}=unpack("N",substr($$data,$offsettoorgttl,4));
	my @expt=gmtime(unpack("N",substr($$data,$offsettosigexp,4)));
	$self->{"sigexpiration"}= sprintf ("%d%02d%02d%02d%02d%02d",
					   $expt[5]+1900 ,$expt[4]+1 , 
					   $expt[3] ,$expt[2] , $expt[1]  , 
					   $expt[0]);
	my @inct=gmtime(unpack("N",substr($$data,$offsettosiginc,4)));
	$self->{"siginception"}=  sprintf ("%d%02d%02d%02d%02d%02d",
					     $inct[5]+1900 ,$inct[4]+1 , 
					     $inct[3] ,$inct[2] , $inct[1]  ,
					     $inct[0]);
	$self->{"keytag"}=unpack("n",substr($$data,$offsettokeytag,2));
	my($signame,$sigoffset) = Net::DNS::Packet::dn_expand
	    ($data, $offsettosignm);
	$self->{"signame"}=lc($signame); 
	my($sigmaterial)=substr($$data,$sigoffset,
				($self->{"rdlength"}-$sigoffset+$offset));
	$self->{"sigbin"}=$sigmaterial;
	$self->{"sig"}= encode_base64($sigmaterial);
	$self->{"vrfyerrstr"}="";
	
    }
    return bless $self, $class;
}




sub new_from_string {
    my ($class, $self, $string) = @_;
    if ($string) {
	$string =~ tr/()//d;
	$string =~ s/;.*$//mg;
	$string =~ s/\n//mg;
	my ($typecovered, $algoritm,
	    $labels, $orgttl, $sigexpiration,
	    $siginception, $keytag,$signame,$sig) = 
		$string =~ 
		    /^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)/;
	croak (" Invallid RRSIG RR, check your fomat ") if !$keytag;
	$sig =~ s/\s*//g;
	$self->{"typecovered"}= $typecovered;
	$self->{"algorithm"}= Net::DNS::SEC->algorithm($algoritm);
	$self->{"labels"}= lc($labels);
	$self->{"orgttl"}= $orgttl;
	_checktimeformat($sigexpiration);
	_checktimeformat($siginception);
	$self->{"sigexpiration"}=  $sigexpiration;
	$self->{"siginception"}= $siginception;
	$self->{"keytag"}= $keytag;
	$self->{"signame"}= lc(Net::DNS::stripdot($signame));
	$self->{"sig"}= $sig;
	$self->{"sigbin"}= decode_base64($sig);
	$self->{"vrfyerrstr"}="";
    }
    return bless $self, $class;
}


sub rdatastr {
	my $self = shift;
	my $rdatastr;
	if (exists $self->{"typecovered"}) {
	    $rdatastr  = $self->{typecovered};
	    $rdatastr .= "  "  . $self->algorithm;
	    $rdatastr .= "  "  . "$self->{labels}";
	    $rdatastr .= "  "  . "$self->{orgttl}";
	    $rdatastr .= "  "  . "$self->{sigexpiration}";
	    $rdatastr .= " (\n\t\t\t"  . "$self->{siginception}";
	    $rdatastr .= " "  . "$self->{keytag}";
	    $rdatastr .= "  "  . "$self->{signame}.";
	    # do some nice formatting
	    my $sigstring=$self->{sig};
	    $sigstring =~ s/\n//g;
	    $sigstring =~ s/(\S{45})/$1\n\t\t\t/g;
	    $rdatastr .=  "\n\t\t\t".$sigstring;
	    $rdatastr .= " )";
	    }
	else {
	    $rdatastr = "; no data";
	}

	return $rdatastr;
}


sub rr_rdata_without_sigbin {
    my ($self) = shift;
    my $rdata = "";

    if (exists $self->{"typecovered"}) {
	$rdata  = pack("n",_string2type($self->{typecovered}));
	$rdata .= pack("C",$self->algorithm);
	$rdata .= pack("C",$self->{"labels"});
	$rdata .= pack("N",$self->{"orgttl"});

	$self->{"sigexpiration"} =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;
	$rdata .= pack("N",timegm ($6, $5, $4, $3, $2-1, $1-1900));

	$self->{"siginception"} =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;
	$rdata .= pack("N",timegm ($6, $5, $4, $3, $2-1, $1-1900));
	$rdata .= pack("n",$self->{"keytag"});
	# Since we will need canonical and expanded names while checking 
	# we do not use the packet->dn_comp here but use RFC1035 p10.
	{   my @dname= split /\./,lc($self->{"signame"}.".");  #/ emacs fontlock
	    for (my $i=0;$i<@dname;$i++){
		$rdata .= pack ("C",length $dname[$i] );
		$rdata .= $dname[$i] ;

	    }
	    $rdata .= pack ("C","0");
	}
    }
    return $rdata;

}


sub rr_rdata {
    my ($self, $packet, $offset) = @_;
    my $rdata = "";
    if (exists $self->{"typecovered"}) {
	$rdata=$self->rr_rdata_without_sigbin;
	
	if ($self->{"sig"} ne "NOTYETCALCULATED") {
            $self->{"sigbin"}= decode_base64($self->{"sig"}) unless defined $self->{"sigbin"} ;
	    $rdata .= $self->{"sigbin"};
	}else{
	    die "RRSIGs should not be used for SIG0 type signatures, use Net::DNS::RR::SIG";
	}
    }
    return $rdata;
}

sub create {
    my ($class,  $datarrset, $priv_key, %args) = @_;


    # This method returns a sigrr with the signature over the
    # datatrrset (an array of RRs) made with the private key stored in
    # the $key_file.

    my $self;
    $self->{"sigerrstr"}="---- Unknown Error Condition ------";
    my $Private;


    if (UNIVERSAL::isa($priv_key,"Net::DNS::SEC::Private")){
	$Private=$priv_key;
    }else{
	$Private=Net::DNS::SEC::Private->new($priv_key);
    }

    unless (UNIVERSAL::isa($Private,"Net::DNS::SEC::Private")){
	$self->{"sigerrstr"}= "Create did not manage to parse a private key into a Net::DNS::SEC::Private object ";
	return (0);
	    
    }
    $self->{"algorithm"}=Net::DNS::SEC->algorithm($Private->algorithm);
    $self->{"keytag"}=$Private->keytag;
    $self->{"signame"}=Net::DNS::stripdot($Private->signame);
   

    die "Argument is not a reference to an array, are you trying to create a SIG0 using RRSIG?" if ! ref ($datarrset);


    $self->{"rr_rdata_recursion"}=0;

    # Start with seting up the data in the packet we can get our hands on...


    $self->{"name"}=$datarrset->[0]->name;

    $self->{"type"}="RRSIG";
    $self->{"class"}="IN";


    if (defined ($args{ttl})){
	print "Setting TTL to ".  $args{"ttl"} . "\n" if $debug;
	$self->{"ttl"}= $args{"ttl"};
    }else{
	$self->{"ttl"}= $datarrset->[0]->ttl;
    }

    $self->{"typecovered"}=$datarrset->[0]->type;  #Sanity checks elsewhere



    if (defined ($args{response})){
	$self->{"response"}=$args{"response"};
    }

    if (defined($args{"sigin"})){
	_checktimeformat($args{"sigin"});
	print "\nSetting siginception to " . $args{"sigin"} if $debug;
	$self->{"siginception"} =$args{"sigin"};
    }else{
	my @inct=gmtime(time);
	my $currentdatestring=  sprintf ("%d%02d%02d%02d%02d%02d",
					 $inct[5]+1900 ,$inct[4]+1 , 
					 $inct[3] ,$inct[2] , $inct[1]  ,
					 $inct[0]);	
	$self->{"siginception"} = $currentdatestring ;
    }

    # This will fail if the dateformat is not correct...
    $self->{"siginception"} =~ 
	/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/ ;
    my $siginc_time=timegm ($6, $5, $4, $3, $2-1, $1-1900);

    if (defined($args{"sigval"})){ #sigexpiration set by siginception + sigval
	my @inct;


	# treat sigval as days
	@inct=gmtime($siginc_time+$args{"sigval"}*24*3600 );  

	$self->{"sigexpiration"}= sprintf ("%d%02d%02d%02d%02d%02d",
					   $inct[5]+1900 ,$inct[4]+1 , 
					   $inct[3] ,$inct[2] , $inct[1]  ,
					   $inct[0]);	
    }elsif ($args{"sigex"}) { #sigexpiration set by the argument
	_checktimeformat($args{"sigex"});

	if ( $self->{"siginception"} > $args{"sigex"} ){
	    croak "Signature can only expire after it has been incepted (".
		$args{"sigex"} . "<" . $self->{"siginception"} .
		    ")";
	}
	print "\nSetting sigexpiration to " . $args{"sigex"} if $debug;
	$self->{"sigexpiration"}=$args{"sigex"} ;

    }else{ 
	my @inct;

	# Take the 30 days default for sigexpiration 	
	@inct=gmtime($siginc_time+30*24*3600 );  

	$self->{"sigexpiration"}= sprintf ("%d%02d%02d%02d%02d%02d",
					   $inct[5]+1900 ,$inct[4]+1 , 
					   $inct[3] ,$inct[2] , $inct[1]  ,
					   $inct[0]);	
    }


    my  $labels=$datarrset->[0]->name;
    $labels =~ s/\.$//;  # remove trailing dot.
    $labels =~ s/^\*\.//;  # remove initial asterisk label
    my @labels= split /\./ , $labels;    # / emacs font-lock-mode	
    $self->{"labels"}= scalar(@labels);


    # All the TTLs need to be the same in the data RRset.
    if ( @{$datarrset}>1 ){
	for (my $i=0; $i<@{$datarrset}; $i++){
	    if ($datarrset->[0]->{"ttl"} != $datarrset->[$i]->{"ttl"}){
		croak "\nNot all TTLs  in the data RRset are equal ";
	    }
	}
    }
    $self->{"orgttl"}=$datarrset->[0]->{"ttl"};

    $self->{"sig"}=  "NOTYETCALCULATED";  # This is what we'll do in a bit...
    $self->{"sigbin"}= decode_base64($self->{"sig"});

    # Bless the whole thing so we can get access to the methods...
    # (Don not ask me why I havent called the new method, There are
    # more ways to do things)

    bless $self, $class;
    
    my $sigdata=$self->_CreateSigData($datarrset);

    my $signature;
    
    #
    # Enjoy the crypto
    if ($self->algorithm == 1 
	|| $self->algorithm == 5
	|| $self->algorithm == 7) {  #RSA
	if (! ($Private->algorithm == 1 
	       || $Private->algorithm == 5 
	       || $Private->algorithm == 7  )) {
	    die "Private key mismatch, not RSAMD5 or RSASHA.";
	    
	}
#	my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($Private->privatekey);
	my $rsa_priv = $Private->privatekey;
	$self->{"private_key"}=$Private->privatekey;
	eval {
	    $rsa_priv->use_pkcs1_oaep_padding;
	    if ($self->algorithm == 1) {
		$rsa_priv->use_md5_hash;
	    } else {
		$rsa_priv->use_sha1_hash;
	    }

	};
	die "RSA private key loading failed:".$@ if $@;
	eval {
	    $signature = $rsa_priv->sign($sigdata);
	};
	die "RSA Signature generation failed ".$@ if $@;

	print "\n SIGNED" if $debug ;
	
    }elsif ($self->algorithm == 3 || $self->algorithm == 6  ){  #DSA
	$self->{"private_key"}=$Private->privatekey;
	my $private_dsa=$Private->privatekey;

	
      	if ($datarrset ne "" ){
	    if (my $sig_obj= $private_dsa->do_sign(sha1($sigdata)))
	    {
		
		print "\n SIGNED" if $debug ;
		# See RFC 2535 for the content of the SIG
		my $T_parameter= (length($private_dsa->get_g)-64)/8;
		$signature=pack("C",$T_parameter);

		my $sig_r_param=$sig_obj->get_r;
		my $sig_s_param=$sig_obj->get_s;
		# both the R and S paramater in the RDATA need to be
		# 20 octets:
		while (length($sig_r_param)<20){
		    $sig_r_param=pack('x').$sig_r_param ; 
		}
		while (length($sig_s_param)<20) {	
		    $sig_s_param=pack('x').$sig_s_param ;
		}
		$signature.=$sig_r_param.$sig_s_param;


	    }else
	    {  
		confess "creation of DSA Signature failed " ;
	    }
	}
	
    }

    if ($datarrset ne "" ){
	# Replace the "sig" by the real signature and return the object.
	$self->{"sigbin"}=$signature;
	$self->{"sig"}= encode_base64($signature);
    }

    return $self;
}


sub verify {
    my ($self, $dataref, $keyrrref ) = @_;

    # Reminder...

    # $dataref may be a reference to an array of RR objects:
    # $dataref->[$i]->method is the call to the method of the $i th
    # object in the array...  @{$dataref} is length of the array when
    # called in numerical context

    # $keyref is eiter a reference to an array of keys or a a key object.

    # if $dataref is not a reference it contains a string with data to be 
    # verified using SIG0
    
    my $sigzero_verify=0;
    my $packet_verify=0;
    my $rrarray_verify=0;

    my $keyrr; # This will be used to store the key to which we want to 
               # verify.
   

    print "Second argument is of class".ref($keyrrref)."\n" if $debug;;
    if (ref($keyrrref) eq "ARRAY"){
	#  We will recurse for each key that matches algorithm and key-id 
	#  we return when there is a succesful verification.
        #  If not we'll continue so that we even survive key-id collission.
	#  The downside of this is that the error string only matches the
	#  last error.
	my @keyarray=@{$keyrrref};
	my $errorstring="";
	my $i=0;
	print "Itterating over " . @keyarray ." keys \n" if $debug;
      KEYRR: foreach my $keyrr (@keyarray) {
	  $i++;
	  unless ($keyrr->algorithm == $self->algorithm){
	      print "key $i: algorithm does not match\n" if $debug;
	      $errorstring.="key $i: algorithm does not match ";
	      next KEYRR;
	  }
	  unless ($keyrr->keytag == $self->keytag){
	      print "key $i: keytag does not match (".$keyrr->keytag." ".$self->keytag.")\n" if $debug;
	      $errorstring.="key $i: keytag does not match ";
	      next KEYRR ;
	      
	  }
	  my $result=$self->verify($dataref,$keyrr);
	  print "key $i:".$self->vrfyerrstr if $debug;
	  $errorstring.="key $i:".$self->vrfyerrstr." ";
	  next KEYRR unless $result;
	  $self->{"vrfyerrstr"}="No Error";
	  return $result;
      }
	$self->{"vrfyerrstr"}=$errorstring;	  
	return (0);
    }elsif(ref($keyrrref) eq 'Net::DNS::RR::DNSKEY' ||
	   ref($keyrrref) eq 'Net::DNS::RR::KEY' # we are liberal...
	){
	# substitute and continue processing after this conditional
	$keyrr=$keyrrref;
	print "Validating using key with keytag:".$keyrr->keytag." \n" if $debug;

    }else{
	# Error condition
	$self->{"vrfyerrstr"} = "You are trying to pass ".ref($keyrrref) ." data for a key";
	return (0);
    }




    print "Verifying data of class:".  ref( $dataref) . "\n" if $debug;
    $sigzero_verify=1 unless (ref($dataref));
    if (! $sigzero_verify ){
	if (ref($dataref) eq "ARRAY"){

	    if (ref($dataref->[0]) and $dataref->[0]->isa('Net::DNS::RR')){
		$rrarray_verify=1;
	    }else{
		die "Trying to verify an array of ".  ref( $dataref->[0]) ."\n";
	    }
	}elsif( (ref($dataref)) and $dataref->isa("Net::DNS::Packet")){
	    $packet_verify=1 if ((ref($dataref)) and $dataref->isa("Net::DNS::Packet"));
	    die "Trying to verify a packet while signature is not of SIG0 type"
		if ($self->{"typecovered"} ne "SIGZERO");
	    
	}else{
	    die "Do not know what kind of data this is" . ref( $dataref) . ")\n";
	}
    }



    $self->{"vrfyerrstr"}="---- Unknown Error Condition ------";
    print "\n ------------------------------- RRSIG DEBUG  -----------------\n"  if $debug;
    print "Reference: ".ref($dataref) if $debug;;
    print "\n  RRSIG:\t", $self->string if $debug;
    if ( $rrarray_verify ){
	for (my $i=0; $i<@{$dataref}; $i++){
	    print "\n DATA:\t", $dataref->[$i]->string if $debug ;
	}
    }
    print "\n  KEY:\t" , $keyrr->string if $debug;
    print "\n ------------------------------------------------------------\n" if $debug;



     
    if (!$sigzero_verify && !$packet_verify && $dataref->[0]->type ne $self->typecovered ) {
	$self->{"vrfyerrstr"} = "\nCannot verify datatype  " . $self->typecovered . 
	    " with a key intended for " . 
		$dataref->[0]->type .
		    " verification\n";
	return 0;
    }


    if ( $rrarray_verify &&  !$dataref->[0]->type eq "RRSIG" ) {
	# if [0] has type RRSIG the whole RRset is type RRSIG. 
	# There are no SIGs over SIG RRsets
	$self->{"vrfyerrstr"} = 
	    "RRSIGs over RRSIGs???\n" .
 	   " What are you trying to do. This is not possible.\n";
	return 0;
    }
    if ( $self->algorithm != $keyrr->algorithm ){
	$self->{"vrfyerrstr"} = 
	    "It is impossible to verify a signature made with algorithm " .
		$self->algorithm . "\nagainst a key made with algorithm " .
		    $keyrr->algorithm . "\n";
	return 0;

    }

    if ( $packet_verify){
	# We keep the intelligence for verification in here....
	# The packet is compressed ... we have to undo the compression.
	# Do this by creating a newpaclet
	my $newpacket;
	bless($newpacket = {},"Net::DNS::Packet");
	%{$newpacket} = %{$dataref};
	bless($newpacket->{"header"} = {},"Net::DNS::Header");
	%{$newpacket->{"header"}} = %{$dataref->{"header"}};
	@{$newpacket->{"additional"}} = @{$dataref->{"additional"}};
	shift(@{$newpacket->{"additional"}});
	$newpacket->{"header"}{"arcount"}--;
	$newpacket->{"compnames"} = {};
	$dataref=$dataref->data;
    }


    # The data that is to be signed
    my $sigdata=$self->_CreateSigData($dataref);
    my $signature=$self->sigbin; 
    my $verified=0;
    if ( $self->algorithm == 1 ){    #Verifying for RSA
	$verified=$self->_verifyRSA($sigdata,$signature,$keyrr,0) || return 0;
    }     
    elsif ( $self->algorithm == 3 ||  $self->algorithm == 6 )  # Verifying for DSA
    {
	 $verified=$self->_verifyDSA($sigdata,$signature,$keyrr) || return 0;
    }
    elsif ( $self->algorithm == 5 ||  $self->algorithm == 7 )  # Verifying for RSASHA1
    {
	$verified=$self->_verifyRSA($sigdata,$signature,$keyrr,1) || return 0;
    }
    else                                  # Verifying other algorithms
    { 
	$self->{"vrfyerrstr"}= "Algoritm ". $self->algorithm . " has not yet been implemented";
	return 0;
    }	
    
    # This really is a redundant test
    if ($verified) {  
        # time to do some time checking.
	my @inct=gmtime(time);
	my $currentdatestring=  sprintf ("%d%02d%02d%02d%02d%02d",
					     $inct[5]+1900 ,$inct[4]+1 , 
					     $inct[3] ,$inct[2] , $inct[1]  ,
					     $inct[0]);	
	if ($self->{"siginception"} > $currentdatestring ){
	    $self->{"vrfyerrstr"}= "Signature may only be used in the future; after " .
		$self->{"siginception"} ;
	    return 0;
	}elsif($self->{"sigexpiration"} < $currentdatestring ){
	    $self->{"vrfyerrstr"}= "Signature has expired since: " .
		$self->{"sigexpiration"} ;
	    return 0;
	}
	$self->{"vrfyerrstr"}= "No Error";
	return 1;
    }
    
    $self->{"vrfyerrstr"}="Verification method error.";
    return 0;

} #END verify block




# Below are all sorts of helper functions. 
# They should not really be used outside the scope of this class ...
#
# To do:  make these functions invisable outside the class.
#
sub _type2string {
    my $index=shift;
    if( Net::DNS::typesbyval($index)){
	return Net::DNS::typesbyval($index) ;
    }else{
	return "UNKNOWN TYPE";
    }
}

sub _string2type {
    my $index=shift;
        if( Net::DNS::typesbyname(uc($index))){
	return Net::DNS::typesbyname(uc($index)) ;
    }else{
	carp "UNKNOWN TYPE, cannot continue ";
    }
}






sub _verifyDSA {
    my ($self, $sigdata, $signature, $keyrr) = @_; 

    print "\nDSA verification called with key:\n". $keyrr->string . 
	
	" and sig:\n" . $self->string ."\n" if $debug;

    # RSA RFC2536
    #
    # Setup a DSA::Key. 
    #


    
    
    
    my $t_param=ord substr($keyrr->keybin,
			0,
			1);   # This works since T is only one octed .
    
    my $q_param=substr($keyrr->keybin, 
		       1,
		       20);
    my $p_param=substr($keyrr->keybin, 
		       21, 
		       64+$t_param*8 );
    my $g_param=substr($keyrr->keybin, 
		       21+64+$t_param*8,
				    64+$t_param*8);
    


    #rfc3279  section 2.3.2
    # (...)
    # The DSA public key MUST be ASN.1 DER encoded as an INTEGER; this
    # encoding shall be used as the contents (i.e., the value) of the
    # subjectPublicKey component (a BIT STRING) of the
    # SubjectPublicKeyInfo data element.
    # (...)

    
my $pubkey_param=substr($keyrr->keybin, 
			21+2*(64+$t_param*8),
			64+$t_param*8);

my $dsa_pub=Crypt::OpenSSL::DSA->new();
    $dsa_pub->set_q($q_param);
    $dsa_pub->set_g($g_param);
    $dsa_pub->set_p($p_param);
    $dsa_pub->set_pub_key($pubkey_param);



    my $r_field=(substr($self->sigbin,
			1,
			20));
    my $s_field=(substr($self->sigbin,
			21,
			20));
    
    my $DSAsig=Crypt::OpenSSL::DSA::Signature->new();
    $DSAsig->set_r($r_field);
    $DSAsig->set_s($s_field);


    if (my $valid=$dsa_pub->do_verify (sha1( $sigdata) ,
				       $DSAsig
				       )){
	if ($valid==-1){
	    print "Crypt::OpenSSL::DSA Verification failed with error\n" if $debug;
	    $self->{"vrfyerrstr"}="DSA Verification failed with error";
	    return(0);
	}else{
	    print "Crypt::OpenSSL::DSA Verification successful:$valid\n" if $debug;;
	    
	    $self->{"vrfyerrstr"}="DSA Verification successful ";
	    return(1);
	}
    }else{
	print "Crypt::OpenSSL::DSA Verification failed\n " if $debug;;
	$self->{"vrfyerrstr"}="DSA Verification failed ";
	return(0);
    }
    
    $self->{"vrfyerrstr"}="DSA Verification failed: undefined error ";
    
    return 0;	
}


sub _verifyRSA {
    # Implementation using crypt::openssl

    my ($self, $sigdata, $signature, $keyrr, $isSHA) = @_; 

    print "\nRSA verification called with key:\n". $keyrr->string . 
	
	" sig:\n" . $self->string ."\non sigdata:\t".
	    unpack ("H*",$sigdata) . "\n" 
	    if $debug;
    # RSA RFC2535
    # 
    
    my $explength;
    my $exponent;
    my $modulus;
    my $RSAPublicKey;
	
    {   #localise dummy
	my $dummy=1;
	# determine exponent length
	
	#RFC 2537 sect 2
	($dummy, $explength)=unpack("Cn",$keyrr->keybin) 
	    if ! ($explength=unpack("C",$keyrr->keybin));
	print "\n\nEXPLENGTH:",$explength if $debug;
	
	# We are constructing the exponent and modulus as a hex number so 
	# the AUTOLOAD function in Crypt::RSA::Key::Public can deal with it
	# later, there must be better ways to do this,
	if ($dummy) { # skip one octet
	    $exponent=(substr ($keyrr->keybin, 
			       1, 
			       $explength));
	    
	    $modulus=( substr ($keyrr->keybin,
			       1+$explength, 
			       (length $keyrr->keybin) - 1
			       - $explength));
	    
	    
	}else{ # skip two octets
	    $exponent=(substr ($keyrr->keybin, 
			       3,
			       $explength));
	    
	    $modulus=( substr ($keyrr->keybin, 
			       3+$explength, 
			       (length $keyrr->keybin) - 3
			       - $explength));
	}
    }
    

    my $bn_modulus=Crypt::OpenSSL::Bignum->new_from_bin($modulus);
    my $bn_exponent=Crypt::OpenSSL::Bignum->new_from_bin($exponent);

  

    my $rsa_pub = Crypt::OpenSSL::RSA->new_key_from_parameters($bn_modulus,$bn_exponent);


    die "Could not load public key" unless $rsa_pub;
    $rsa_pub->use_pkcs1_oaep_padding;
    if ($isSHA) {
	$rsa_pub->use_sha1_hash;
    } else {
	$rsa_pub->use_md5_hash;
    }
    

    
    my $verified;
    eval {
	$verified=$rsa_pub->verify($sigdata, $signature);
    };

    if ($@){
	 $self->{"vrfyerrstr"}=
	     "Verification of RSA string generated error: ". $@;
	 print "\nRSA library error.\n" if $debug;
	 return 0;
     }
    if ($verified )
    {
	print "\nVERIFIED\n\n" if $debug ;
	$self->{"vrfyerrstr"}="RSA Verification successful";
	return 1;
    }else
    {   $self->{"vrfyerrstr"}="RSA Verification failed";
	# Data is not verified
	print "\nNOT VERIFIED\n" if $debug;
	return 0;
    }
    
    $self->{"vrfyerrstr"}="RSA Verification failed: This code should not be run ";
    0;

}

sub _CreateSigData {
    # this is the data that will be  signed, it will be fed to the
    # verifier. See RFC4034 section 6 on how this string is constructed

    # This method is called by the method that creates as signature
    # and by the method that verifies the signature. It is assumed
    # that the creation method has checked that all the TTL are the same
    # for the dataref and that sig->orgttl has been set to the TTL of
    # the data. This method will set the datarr->ttl to the sig->orgttl for
    # all the RR in the dataref.



    my ($self,$rawdata)=@_;

    my $sigzero= ! ref ($rawdata);
    my $sigdata;
    # construction of message 

    print "_CreatSigData\n" if $debug;
    my $rdatawithoutsig=$self->rr_rdata_without_sigbin;
    print "raw RRsig:\t",  unpack("H*", $rdatawithoutsig) if $debug;
    $sigdata= $rdatawithoutsig;


    if ( ! $sigzero ){
	# Not a SIG0
	if (@{$rawdata}>1) {
	    my @canonicaldataarray;
	    for (my $i=0; $i<@{$rawdata}; $i++){
		if ($debug){
		    print "Setting TTL to from ". $rawdata->[$i]->{"ttl"} . " to " .
			$self->orgttl . "\n" 
			    if ( $rawdata->[$i]->{"ttl"}!=$self->orgttl);
		}
		$rawdata->[$i]->{"ttl"}=$self->orgttl;
		# Some error checking is done to. A RRset is defined by 
		# Same label,class,qtype
		if (lc($rawdata->[$i]->name) ne lc($rawdata->[0]->name)){
		    print "\nError:\n";
		    for  (my $j=0; $j<@{$rawdata}; $j++){
			print "\n";
			$rawdata->[$j]->print;
		    }
		    croak "\nNot all labels in the data RRset above are equal ";
		}
		
		if ($rawdata->[$i]->type ne $rawdata->[0]->type){
		    print "\nError:\n";
		    for  (my $j=0; $j<@{$rawdata}; $j++){
			print "\n";
			$rawdata->[$j]->print;
		    }
		    croak "\nThe  the data RRset consists of different types ";
		}
		
		if ($rawdata->[$i]->class ne $rawdata->[0]->class){
		    print "\nError:\n";
		    for  (my $j=0; $j<@{$rawdata}; $j++){
			print "\n";
			$rawdata->[$j]->print;
		    }
		    croak "\nThe  the data RRset has different classes (What are you trying to do?)  ";
		}
		
		print "\n\nCan Data RR: $i\t", 
		unpack("H*", ($rawdata->[$i]->_canonicaldata)) if $debug;
		
		# To allow for sorting on RDATA we create an array of hashes.
		# We sort on canonicalRdata and use the full RR representation 
		# in rr to build the digest.
		$canonicaldataarray[$i]= 
		{ rrdigest => $rawdata->[$i]->_canonicaldata,
		  canonicalRdata => $rawdata->[$i]->_canonicalRdata,
	      };
	    }
	    
	    # Sort acording to RFC2535 section 8.3
	    # Comparing left justified octet strings: perl sort does just that.
	    # We have to sort on RDATA.. the array contains the whole RRset.
	    #  the sort routine
	    
	    my @sortedcanonicaldataarray= sort        {
		$a->{"canonicalRdata"} cmp $b->{"canonicalRdata"};   
	    }
	    @canonicaldataarray;
	    
	    
	    
	    for (my $i=0; $i<@sortedcanonicaldataarray ; $i++){
		print "\n>>>" . $i 	.
		    ">>> \t" .
			unpack("H*",$sortedcanonicaldataarray[$i]{canonicalRdata}) .
			    "\n>>>\t " .
				unpack("H*",$sortedcanonicaldataarray[$i]{rrdigest}) .
				    "\n" if $debug;
		$sigdata .=  $sortedcanonicaldataarray[$i]{rrdigest};
	    }
	}else{
	    if ($debug) {
		print "\nSetting TTL to from ". $rawdata->[0]->{"ttl"} . " to " .
		    $self->orgttl . "\n" if 
			( $rawdata->[0]->{"ttl"}!=$self->orgttl );
	    }
	    print "\nRDATA:\t\t" .$rawdata->[0]->_canonicalRdata ."\n-----:\t\t" .
	      unpack("H*",$rawdata->[0]->_canonicalRdata) ."\n" if $debug;
	    
	    $rawdata->[0]->{"ttl"}=$self->orgttl;	    
	    $sigdata .= $rawdata->[0]->_canonicaldata;
	    
	}
	
    }else{ #SIG0 case  

	print "\nsig0 proccessing\nrawdata:\t". unpack("H*",$rawdata)."\n"if $debug;
	$sigdata=$sigdata.$rawdata;
    }
    

    print "\n sigdata:\t".   unpack("H*",$sigdata) . "\n" if $debug;

    return $sigdata;
}


sub _checktimeformat {
    # Function to check if the strings entered as time are properly formated.
    # Croaks if the format does not make sense...
    
    
    my $timestring=shift;

    my @timeval=($timestring =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
    if (@timeval != 6) {
	croak "The time " . $timestring . " is not in the expected format (yyyymmddhhmmss)";
    }
    if ($timeval[0]< 1970) {
	croak "The year ". $timeval[0] . " is before the epoch (1970)";
    }
    if ($timeval[1]> 12) {
	croak "What??? There is no month number ". $timeval[1] ;
    }
    # This is a rough check... 
    # Feb 31 will work... 
    if ($timeval[2]> 31) {
	croak "Intresting, a month with ". $timeval[2] . " days" ;
    }

    if ($timeval[3]> 24) {
	croak "Intresting, a day with ". $timeval[3] . " hours" ;
    }

    if ($timeval[4]> 60) {
	croak "Intresting, an hour with ". $timeval[3] . " minutes" ;
    }
    if ($timeval[5]> 60) {
	croak "Intresting, a minute with ". $timeval[3] . " seconds" ;
    }

    
    0;
}


# The previous versions had a typo... *Sigh*
sub siginceptation {
    my $self=shift;
    return $self->siginception(@_);
}



sub _normalize_dnames {
	my $self=shift;
	$self->_normalize_ownername();
	$self->{'signame'}=lc(Net::DNS::stripdot($self->{'signame'})) if defined $self->{'signame'};
}


1;


=head1 NAME

Net::DNS::RR::RRSIG - DNS RRSIG resource record

=head1 SYNOPSIS

C<use Net::DNS::RR;>

=head1 DESCRIPTION


Class for DNS Address (RRSIG) resource records. In addition to the
regular methods in the Net::DNS::RR the Class contains a method to
sign RRsets using private keys (create). And a class for verifying
signatures over RRsets (verify).

The RRSIG RR is an implementation of RFC 4034. 
See L<Net::DNS::RR::SIG> for an impelementation of SIG0 (RFC 2931).




=head1 METHODS

=head2 create
    
Create a signature over a RR set.

    my $keypath= 
            "/home/olaf/keys/Kbla.foo.+001+60114.private";
    my $sigrr= create Net::DNS::RR::RRSIG(\@datarrset,
					$keypath);
    my $sigrr= create Net::DNS::RR::RRSIG(\@datarrset,
					$keypath,
					%arguments);
    $sigrr->print;



    #Alternatively use Net::DNS::SEC::Private 

    my $private=Net::DNS::SEC::Private-new(
	"/home/olaf/keys/Kbla.foo.+001+60114.private");
    my $sigrr= create Net::DNS::RR::RRSIG(\@datarrset,
					  $private);




create is an alternative constructor for a RRSIG RR object.  

The first argument is either reference to an array that contains the
RRset that needs to be signed.

The second argument is a string containing the path to a file
containing the the private key as generated with dnssec-keygen, a
program that commes with the bind distribution.

The third argument is an anonymous hash containing the following
possible arguments:  

    ( ttl => 3600,                        # TTL 
      sigin =>   20010501010101,          # signature inception 
      sigex =>   20010501010101,          # signature expiration
      sigval => 1.5                       # signature validity
      )

The default for the ttl is 3600 seconds. sigin and sigex need to be
specified in the following format 'yyyymmddhhmmss'. The default for
sigin is the time of signing. 

sigval is the validity of the signature in minutes for SIG0s and days
for other signatures (sigex=sigin+sigval).  If sigval is specified
then sigex is ignored. The default for sigval is 5 minutes for SIG0s
and 30 days other types of signatures.



Notes: 

- Do not change the name of the file generated by dnssec-keygen, the
  create method uses the filename as generated by dnssec-keygen to
  determine the keyowner, algorithm and the keyid (keytag).

- Only RSA signatures (algorithm 1,5 and 7) and DSA signatures 
  (algorithm 3, and 6) have been implemented.



=head2 typecovered

    print "typecovered =", $rr->typecovered, "\n"

Returns the qtype covered by the sig.

=head2 algorithm

    print "algorithm =", $rr->algorithm, "\n"

Returns the algorithm number used for the signature

=head2 labels

    print "labels =", $rr->labels, "\n"

Returns the the number of labels of the RRs over wich the 
sig was made.

=head2 orgttl

    print "orgttl =", $rr->orgttl, "\n"

Returns the RRs the original TTL of the signature

=head2 sigexpiration

    print "sigexpiration =", $rr->sigexpiration, "\n"

Returns the expiration date of the signature

=head2 siginception

    print "siginception =", $rr->siginception, "\n"

Returns the date the signature was incepted.

=head2 keytag

    print "keytag =", $rr->keytag, "\n"

Returns the the keytag (key id) of the key the sig was made with.
Read "KeyID Bug in bind." below.

=head2 signame

    print "signame =", $rr->signame, "\n"

Returns the name of the public KEY RRs  this sig was made with.

=head2 sig

    print "sig =", $rr->sig, "\n"

Returns the base64 representation of the signature.


=head2 verify and vrfyerrstr

    $sigrr->verify($data, $keyrr) || croak $sigrr->vrfyerrstr;
    $sigrr->verify($data, [$keyrr, $keyrr2, $keyrr3]) || 
                  croak $sigrr->vrfyerrstr;


If $data contains a reference to an array of RR objects then them
method verifies the RRset against the signature contained in the
$sigrr object itself using the public key in $keyrr.  Because of the
KeyID bug in bind (see below) a check on keyid is not performed.

If $data contains a reference to a Net::DNS::Packet and if $sig->type
equals zero a a sig0 verification is performed. Note that the
signature needs to be 'popped' from the packet before verifying.

The second argument can either be a Net::DNS::RR::KEYRR object or a
reference to an array of such objects. Verification will return
successful as soon as one of the keys in the array leads to positive
validation.

Returns 0 on error and sets $sig->vrfyerrstr

=head2 Example


   my $sigrr=$packet->pop("additional");
   print $sigrr->vrfyerrstr unless $sigrr1->verify($update1, $keyrr1);


=head1 Remarks

- The code is not optimized for speed whatsoever. It is probably not
suitable to be used for signing large zones. 

=head1 TODO

- Clean up the code.

- If this code is still around by 2030 you have a few years to check
the proper handling of times...

- Add wildcard handling


=head1 ACKNOWLEDGMENTS

Andy Vaskys (Network Associates Laboratories) supplied the code for
handling RSA with SHA1 (Algorithm 5).

Chris Reinardt for maintianing Net::DNS.  

T.J. Mather, <tjmather@tjmather.com>, the Crypt::OpenSSL::DSA
maintainer, for his quick responses to bug report and feature
requests.


=head1 COPYRIGHT

Copyright (c) 2001 - 2005  RIPE NCC.  Author Olaf M. Kolkman 
Copyright (c) 2007 - 2008  NLnet Labs.  Author Olaf M. Kolkman 
<olaf@net-dns.org>

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

This code uses Crypt::OpenSSL which uses the openssl library


=head1 SEE ALSO

L<http://www.net-dns.org/> 

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Header>, L<Net::DNS::Question>,
L<Net::DNS::RR>,L<Crypt::OpenSSL::RSA>,
L<Crypt::OpenSSL::DSA>, L<Net::DNS::SEC::Private>, RFC 4034

=cut

