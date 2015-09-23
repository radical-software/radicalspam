# perldoc SIG.pm for documentation.
# Specs: RFC 2535 section 4
# $Id: SIG.pm 777 2008-12-30 17:18:54Z olaf $

package Net::DNS::RR::SIG;

use vars qw(@ISA $VERSION @EXPORT );

use Net::DNS;
use Carp;
use bytes;
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
# Most of the cryptovariables should be interpred as unsigne
#
#


require Exporter;

$VERSION = do { my @r=(q$Revision: 777 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };
@ISA = qw (
	   Exporter
	 Net::DNS::RR
	   );

@EXPORT = qw (
	      );


use strict;
my $debug=0;
my $crypt_open_ssl=1;
my $__DeprecationWarningVerifyShown=0;
my $__DeprecationWarningCreateShown=0;




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
	$self->{"signame"}=lc($signame) ;
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
		    /^\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)/;
	croak (" Invallid SIG RR, check your fomat ") if !$keytag;
	$sig =~ s/\s*//g;
	$self->{"typecovered"}=uc($typecovered);
	$self->{"algorithm"}= $algoritm;
	$self->{"labels"}= lc($labels);
	$self->{"orgttl"}= $orgttl;
	_checktimeformat($sigexpiration);
	_checktimeformat($siginception);
	$self->{"sigexpiration"}=  $sigexpiration;
	$self->{"siginception"}= $siginception;
	$self->{"keytag"}= $keytag;
	$self->{"signame"}= Net::DNS::stripdot(lc($signame));
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
	    $rdatastr .= "  "  . "$self->{algorithm}";
	    $rdatastr .= "  "  . "$self->{labels}";
	    $rdatastr .= "  "  . "$self->{orgttl}";
	    $rdatastr .= "  "  . "$self->{sigexpiration}";
	    $rdatastr .= " (\n\t\t\t"  . "$self->{siginception}";
	    $rdatastr .= " "  . "$self->{keytag}";
	    $rdatastr .= "  "  . "$self->{signame}";
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
	$rdata .= pack("C",$self->{algorithm});
	$rdata .= pack("C",$self->{"labels"});
	$rdata .= pack("N",$self->{"orgttl"});
	$self->{"sigexpiration"} =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;
	$rdata .= pack("N",timegm ($6, $5, $4, $3, $2-1, $1-1900));

	$self->{"siginception"} =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;
	$rdata .= pack("N",timegm ($6, $5, $4, $3, $2-1, $1-1900));
	$rdata .= pack("n",$self->{"keytag"});
	# Since we will need canonical and expanded names while checking 
	# we do not use the packet->dn_comp here but use RFC1035 p10.
	{   my @dname= split /\./,lc($self->{"signame"});
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
            #do sigzero calculation based on current packet content...
	    
	    die "Signature not known for a not SIG0 type of signature" if ($self->{"typecovered"} ne "TYPE000");
	    die "Private key not known for SIG0" if (! exists $self->{"private_key"});
	    

	    my $rr=$packet->pop("additional");
	    die "SIG0 should be the last RR in the packet" if ($rr->type ne "SIG");
	    die "Unexpected error during creation of SIG0. " if ($rr ne $self);
	    print "Processing SIG0 signature\n" if $debug;

	    my $data;
	    # Compress the data and make sure we will not go into deep
	    # recursion 
	    if ($self->{"rr_rdata_recursion"}==0){	    
		$self->{"rr_rdata_recursion"}=1;	    

		$data=$packet->data;

		my $sigdata=$self->_CreateSigData($data);
		my $signature;

		if ($self->{"algorithm"} == 1 ||
		    $self->{"algorithm"} == 5)
		{  #RSA


		  my $rsa_priv=$self->{"private_key"};
		    eval {
			$rsa_priv->use_pkcs1_oaep_padding;
			if ($self->{"algorithm"} == 1) {
			    $rsa_priv->use_md5_hash;
			} else {
			    $rsa_priv->use_sha1_hash;
			}

		    };
		    die "Error loading RSA private key " . $@ if $@;

		    eval {
			$signature = $rsa_priv->sign($sigdata);
		    };
		    die "RSA Signature generation failed ".$@ if $@;

		    print "\n SIGNED" if $debug ;
		    
		}elsif ($self->{"algorithm"} == 3){  #DSA


		    my $private_dsa = $self->{"private_key"};


		    # If $sigzero then we want to sign data if given
		    # in the argument. If the argument is empty we
		    # sign when the packet put on the wire.

		    if (my $sig_obj= $private_dsa->do_sign(sha1($sigdata)))
		    {
			
			print "\n SIGNED" if $debug ;
			# See RFC 2536 for the content of the DSA SIG rdata 
			my $T_parameter= (length($private_dsa->get_g)-64)/8;
			$signature=pack("C",$T_parameter);
			my $sig_r_param=$sig_obj->get_r;
			my $sig_s_param=$sig_obj->get_s;
			# both the R and S paramater in the RDATA need to be
			# 20 octets
			while (length($sig_r_param)<20){	
			    $sig_r_param=pack("x").$sig_r_param ;
			}
			while (length($sig_s_param)<20) {	
			    $sig_s_param=pack("x").$sig_s_param ;
			}


			$signature.=$sig_r_param.$sig_s_param;


			

		    }else
		    {  
			confess "creation of DSA Signature failed " ;
		    }
		}
		
		
		
		
		
		
		
		$self->{"sigbin"}=$signature;
		$self->{"sig"}= encode_base64($signature);
		$rdata .= $self->{"sigbin"};
	    }
	    $packet->push("additional", $self);
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

    die "Create did not manage obtain a Net::DNS::SEC::Private object "unless (UNIVERSAL::isa($Private,"Net::DNS::SEC::Private"));

    $self->{"algorithm"}=$Private->algorithm;
    $self->{"keytag"}=$Private->keytag;
    $self->{"signame"}=$Private->signame;


    # if $datarrset is a plain datastrream then construct a sigzero sig.
    # So any number will actually do.

    my $sigzero= ! ref ($datarrset);
    $self->{"rr_rdata_recursion"}=0;

    # Start with seting up the data in the packet we can get our hands on...

    if ($sigzero){
	$self->{"name"}="";
    }else{
	$self->{"name"}=$datarrset->[0]->name;
    }

    $self->{"type"}="SIG";
    $self->{"class"}="IN";


    if ($sigzero){
	# RFC 2931 sect 3
	$self->{"ttl"}=0;
	$self->{"class"}="any";
    }elsif ($args{ttl}){
	print "\nSetting TTL to ".  $args{"ttl"} if $debug;
	$self->{"ttl"}= $args{"ttl"};
    }else{
	$self->{"ttl"}= 3600;
    }

    if ($sigzero){
	$self->{"typecovered"}="TYPE000";
    }else{
	print "Note: the SIG RR has been deprecated for use other than SIG0; use the RRSIG instead\n"		  if !$__DeprecationWarningCreateShown ;
		$__DeprecationWarningCreateShown=1;

	$self->{"typecovered"}=$datarrset->[0]->type;  #Sanity checks elsewhere
    }


    if ($args{response}){
	$self->{"response"}=$args{"response"};
    }

    if ($args{"sigin"}){
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

    if ($args{"sigval"}){ #sigexpiration set by siginception + sigval
	my @inct;


	if ($sigzero){
	    # treat sigval as minutes
	    @inct=gmtime($siginc_time+$args{"sigval"}*60 );  
	}else{
	    # treat sigval as days
	    @inct=gmtime($siginc_time+$args{"sigval"}*24*3600 );  
	}
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
	print "\nSetting sigexpiration to " . $args{"sigexp"} if $debug;
	$self->{"sigexpiration"}=$args{"sigex"} ;
    }else{ 
	my @inct;
	if ($sigzero){
	    #default 5 minutes
	    @inct=gmtime($siginc_time+5*60  );  
	}else{
	   # Take the 30 days default for sigexpiration 	
	    @inct=gmtime($siginc_time+30*24*3600 );  
	}
	$self->{"sigexpiration"}= sprintf ("%d%02d%02d%02d%02d%02d",
					   $inct[5]+1900 ,$inct[4]+1 , 
					   $inct[3] ,$inct[2] , $inct[1]  ,
					   $inct[0]);	
    }


    if (!$sigzero)    {   
	my  $labels=$datarrset->[0]->name;
	$labels =~ s/\.$//;  # remove trailing dot.
        $labels =~ s/^\*\.//;  # remove initial asterisk label
	my @labels= split /\./ , $labels;
	$self->{"labels"}= scalar(@labels);
	
    }else{
	$self->{"labels"}= 0;
    }

    # All the TTLs need to be the same in the data RRset.
    if ( (!$sigzero) && @{$datarrset}>1){
	for (my $i=0; $i<@{$datarrset}; $i++){
	    if ($datarrset->[0]->{"ttl"} != $datarrset->[$i]->{"ttl"}){
		croak "\nNot all TTLs  in the data RRset are equal ";
	    }
	}
    }
  
    if ($sigzero){
	$self->{"orgttl"}=0;
    }else{	
	$self->{"orgttl"}=$datarrset->[0]->{"ttl"};  
    }


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
    if ($self->{"algorithm"} == 1 || $self->{"algorithm"} == 5) {  #RSA
	if (! ($Private->algorithm == 1 || $self->algorithm == 5 )) {
	    die "Private key mismatch, not RSAMD5 or RSASHA.";
	    
	}
#	my $rsa_priv = Crypt::OpenSSL::RSA->new_private_key($Private->privatekey);
	my $rsa_priv = $Private->privatekey;
	$self->{"private_key"}=$Private->privatekey;
	eval {
	    $rsa_priv->use_pkcs1_oaep_padding;
	    if ($self->{"algorithm"} == 1) {
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
	
    }elsif ($self->{"algorithm"} == 3){  #DSA
	$self->{"private_key"}=$Private->privatekey;
	my $private_dsa=$Private->privatekey;

	# If $sigzero then we want to sign data if given in the
	# argument. If the argument is empty we sign when the packet
	# put on the wire.
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
    my ($self, $dataref, $keyrr) = @_;

    # Reminder...

    # $dataref may be a reference to an array of RR objects:
    # $dataref->[$i]->method is the call to the method of the $i th
    # object in the array...  @{$dataref} is length of the array when
    # called in numerical context

    # Alternatively %dataref may refer to a a Net::DNS::Packet.

    # if $dataref is not a reference it contains a string with data to be 
    # verified using SIG0
    
    my $sigzero_verify=0;
    my $packet_verify=0;
    my $rrarray_verify=0;
   
    print "Verifying data of class:".  ref( $dataref) . "\n" if $debug;
    $sigzero_verify=1 unless (ref($dataref));
    if (! $sigzero_verify ){
	if (ref($dataref) eq "ARRAY"){
	    if (ref($dataref->[0]) and $dataref->[0]->isa('Net::DNS::RR')){
		$rrarray_verify=1;

	print "Note: the SIG RR has been deprecated for use other than SIG0; use the RRSIG instead\n"		  
		  if !$__DeprecationWarningVerifyShown ;
		$__DeprecationWarningVerifyShown=1;
	    }else{
		die "Trying to verify an array of ".  ref( $dataref->[0]) ."\n";
	    }
	}elsif( (ref($dataref)) and $dataref->isa("Net::DNS::Packet")){
	    $packet_verify=1 if ((ref($dataref)) and $dataref->isa("Net::DNS::Packet"));
	    die "Trying to verify a packet while signature is not of SIG0 type"
		if ($self->{"typecovered"} ne "TYPE000");
	}else{
	    die "Do not know what kind of data this is" . ref( $dataref) . ")\n";
	}
    }

    $self->{"vrfyerrstr"}="---- Unknown Error Condition ------";
    print "\n ------------------------------- SIG DEBUG  -----------------\n"  if $debug;
    print "Reference: ".ref($dataref) if $debug;;
    print "\n  SIG:\t", $self->string if $debug;
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


    if ( $rrarray_verify &&  !$dataref->[0]->type eq "SIG" ) {
	# if [0] has type SIG the whole RRset is type SIG. 
	# There are no SIGs over SIG RRsets
	$self->{"vrfyerrstr"} = 
	    "SIGs over SIGs???\n" .
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
    elsif ( $self->algorithm == 3 )  # Verifying for DSA
    {
	 $verified=$self->_verifyDSA($sigdata,$signature,$keyrr) || return 0;
    }
    elsif ( $self->algorithm == 5 )  # Verifying for RSASHA1
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
	carp "UNKNOWN QTYPE, cannot continue ";
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


    my $rdatawithoutsig=$self->rr_rdata_without_sigbin;
    print "\n\nstrip:\t\t",  unpack("H*", $rdatawithoutsig) if $debug;
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
		if ($rawdata->[$i]->name ne $rawdata->[0]->name){
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
	    print "\nRDATA: \t" .$rawdata->[0]->_canonicalRdata ."\t" .
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



1;


=head1 NAME

Net::DNS::RR::SIG - DNS SIG resource record

=head1 SYNOPSIS

C<use Net::DNS::RR;>

=head1 DESCRIPTION


IMPORTANT: For any other use than SIG0 signatures the SIG RR has been
deprecated (RFC3755). Use the DNSSIG instead.

All functionality currently remains present although a warning will be
printed at first usage of the verify and create methods.


Class for DNS Address (SIG) resource records. In addition to the
regular methods in the Net::DNS::RR the Class contains a method to
sign RRsets using private keys (create). And a class for verifying
signatures over RRsets (verify).

The SIG RR is an implementation of RFC 2931.



=head1 SIG0 Support

When Net::DNS::RR::SIG.pm is available the Net::DNS::Packet module will have
the abilityh for sig0 support. See L<Net::DNS::Packet> for details.


    my $keypathrsa="Ktest.example.+001+11567.private";
    my $update1 = Net::DNS::Update->new("test.example");

    $update1->push("update", Net::DNS::rr_add("foo.test.example 3600 IN A 10.0.0.1"));
    $update1->sign_sig0($keypathrsa);


=head1 METHODS

=head2 create 


create is an alternative constructor for a SIG RR object.  

You are advised to create a packet object and then use the sign_sig0
method to create a sig0 signature. 


To create a signature over a packet (SIG0) you can use the following
alternative recipe.

    my $keypath= 
            "/home/olaf/keys/Kbla.foo.+001+60114.private";

    $sig0 = Net::DNS::RR::SIG->create('', $keypath);
    $packet->push('additional', $sig0) if $sig0;
    $packet->data;  # When the data method on a packet is called
                    # the actual sig0 calculation is done.


The first argument to the create method should be an empty string in
order for the SIG0 magic to work.

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

sigval is the validity of the signature in minutes. If sigval is
specified then sigex is ignored. The default for sigval is 5 minutes.

Note that for SIG0 signatures the default sigin is calculated at the
moment the object is created, not at the moment that the packet is put
on the wire. 


Notes: 

- Do not change the name of the file generated by dnssec-keygen, the
  create method uses the filename as generated by dnssec-keygen to determine 
  the keyowner, algorithm and the keyid (keytag).

- Only RSA signatures (algorithm 1 and 5) and DSA signatures
  (algorithm 3) have been implemented.



=head2 typecovered

    print "typecovered =", $rr->typecovered, "\n"

Returns the type covered by the sig (should be TYPE000 with common
SIG0 usage)

=head2 algorithm

    print "algorithm =", $rr->algorithm, "\n"

Returns the algorithm number used for the signature

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
(Note: the name does not contain a trailing dot.)

=head2 sig

    print "sig =", $rr->sig, "\n"

Returns the base64 representation of the signature.


=head2 verify and vrfyerrstr


    my $sigrr=$update1->pop("additional");
    $sigrr->verify($packet, $keyrr) || croak $sigrr->vrfyerrstr;


If the first argument is a Net::DNS::Packet object and if $sig->type
equals zero a a sig0 verification is performed. Note that the
signature needs to be 'popped' from the packet before verifying.

Returns 0 on error and sets $sig->vrfyerrstr

=head2 Example


   my $sigrr=$packet->pop("additional");
   print $sigrr->vrfyerrstr unless $sigrr1->verify($update1, $keyrr1);


=head1 Remarks

- The code is not optimized for speed whatsoever. It is probably not
  suitable to be used for signing large zones. 

=head1 TODO

- Clean up the code, it still contains some cruft left from the times that
  the SIG RR was used for signing packets and RR sets.

- If this code is still around by 2030 you have a few years to check
  the proper handling of times...


=head1 ACKNOWLEDGMENTS

Andy Vaskys (Network Associates Laboratories) supplied the code for
handling RSA with SHA1 (Algorithm 5).

Chris Reinardt for maintianing Net::DNS.

T.J. Mather, <tjmather@tjmather.com>, the Crypt::OpenSSL::DSA
maintainer, for his quick responses to bug report and feature
requests.


=head1 COPYRIGHT

Copyright (c) 2001-2005  RIPE NCC.  Author Olaf M. Kolkman 
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
L<Net::DNS::RR>,L<Crypt::OpenSSL::RSA>,L<Crypt::OpenSSL::DSA>, RFC 2931.

=cut


