package MIME::Base32;

require 5.005_62;
use strict;
use warnings;

use vars qw( $VERSION );

	$VERSION = '1.01'; # $Id: Base32.pm_rev 1.5 2003/12/11 13:21:18 root Exp root $


sub import
{
	my(		$pkg, $arg		)=@_;
	if( defined($arg) && $arg =~ /rfc|3548/i )
	{
		*encode = \&encode_rfc3548;
		*decode = \&decode_rfc3548;
	}
	else
	{
		*encode = \&encode_09AV;
		*decode = \&decode_09AV;
	}
}

sub encode_rfc3548{			

	# base32:
	#
	#  modified base64 algorithm with
	#  32 characters set:  A - Z 2 - 7 compliant with: RFC-3548
	#
	
	
	$_ = shift @_;
	my( $buffer, $l, $e );

	$_=unpack('B*', $_);
	s/(.....)/000$1/g;
	$l=length;
	if ($l & 7)
	{
		$e = substr($_, $l & ~7);
		$_ = substr($_, 0, $l & ~7);
		$_ .= "000$e" . '0' x (5 - length $e);
	}
	$_=pack('B*', $_);
	tr|\0-\37|A-Z2-7|;
	$_;
}

sub decode_rfc3548{
        $_ = shift;
        my( $l );
		
        tr|A-Z2-7|\0-\37|;
        $_=unpack('B*', $_);
        s/000(.....)/$1/g;
        $l=length;
					
        # pouzije pouze platnou delku retezce
        $_=substr($_, 0, $l & ~7) if $l & 7;
					
        $_=pack('B*', $_);
}

sub encode_09AV{			

	# base32:
	#
	#  modified base64 algorithm with
	#  32 characters set:  [0-9A-V] pre 1.00 backward compatibility
	#
	
	
	$_ = shift @_;
	my( $buffer, $l, $e );

	$_=unpack('B*', $_);
	s/(.....)/000$1/g;
	$l=length;
	if ($l & 7)
	{
		$e = substr($_, $l & ~7);
		$_ = substr($_, 0, $l & ~7);
		$_ .= "000$e" . '0' x (5 - length $e);
	}
	$_=pack('B*', $_);
	tr|\0-\37|0-9A-V|;
	$_;
}

sub decode_09AV{
        $_ = shift;
        my( $l );
		
        tr|0-9A-V|\0-\37|;
        $_=unpack('B*', $_);
        s/000(.....)/$1/g;
        $l=length;
					
        # pouzije pouze platnou delku retezce
        $_=substr($_, 0, $l & ~7) if $l & 7;
					
        $_=pack('B*', $_);
}


1;
__END__

=head1 NAME

MIME::Base32 - Base32 encoder / decoder

=head1 SYNOPSIS

  # RFC forces the [A-Z2-7] RFC-3548 compliant encoding 
  # default encoding [0-9A-V] is for backward compatibility with pre v1.0
  use MIME::Base32 qw( RFC ); 
  
  $encoded = MIME::Base32::encode($text_or_binary_data);
  $decoded = MIME::Base32::decode($encoded);
					 
=head1 DESCRIPTION

Encode data similar way like MIME::Base64 does. 
  
Main purpose is to create encrypted text used as id or key entry typed-or-submitted by user. It is upper/lowercase safe (not sensitive).

=head1 EXPORT

ALLWAYS NOTHING

=head1 AUTHOR

Daniel Peder, sponsored by Infoset s.r.o., Czech Republic 
<Daniel.Peder@InfoSet.COM> http://www.infoset.com

=head1 SEE ALSO

perl(1), MIME::Base64(3pm).

=cut
