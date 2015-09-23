#!/usr/bin/perl
package NetAddr::IP::Util;

use strict;
#use diagnostics;
#use lib qw(blib lib);

use vars qw($VERSION @EXPORT_OK @ISA %EXPORT_TAGS $Mode);
use AutoLoader qw(AUTOLOAD);
use NetAddr::IP::Util_IS;
require DynaLoader;
require Exporter;

@ISA = qw(Exporter DynaLoader);

$VERSION = do { my @r = (q$Revision: 1.31 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

@EXPORT_OK = qw(
	inet_aton
	inet_ntoa
	ipv6_aton
	ipv6_n2x
	ipv6_n2d
	inet_any2n
	hasbits
	isIPv4
	inet_n2dx
	inet_n2ad
	shiftleft
	addconst
	add128
	sub128
	notcontiguous
	bin2bcd
	bcd2bin
	mode
	ipv4to6
	mask4to6
	ipanyto6
	maskanyto6
	ipv6to4
	bin2bcdn
	bcdn2txt
	bcdn2bin
	simple_pack
	comp128
);

%EXPORT_TAGS = (
	all     => [@EXPORT_OK],
	inet	=> [qw(
		inet_aton
		inet_ntoa
		ipv6_aton
		ipv6_n2x
		ipv6_n2d
		inet_any2n
		inet_n2dx
		inet_n2ad
		ipv4to6
		mask4to6
		ipanyto6
		maskanyto6
		ipv6to4
	)],
	math	=> [qw(
		shiftleft
		hasbits
		isIPv4
		addconst
		add128
		sub128
		notcontiguous
		bin2bcd
		bcd2bin
	)],
	ipv4	=> [qw(
		inet_aton
		inet_ntoa
	)],
	ipv6	=> [qw(
		ipv6_aton
		ipv6_n2x
		ipv6_n2d
		inet_any2n
		inet_n2dx
		inet_n2ad
		ipv4to6
		mask4to6
		ipanyto6
		maskanyto6
		ipv6to4
	)],
);

if (NetAddr::IP::Util_IS->not_pure) {
  eval {		## attempt to load 'C' version of utilities
	bootstrap NetAddr::IP::Util $VERSION;
  };
}
if (NetAddr::IP::Util_IS->pure || $@) {	## load the pure perl version if 'C' lib missing
  require NetAddr::IP::UtilPP;
  import NetAddr::IP::UtilPP qw( :all );
  require Socket;
  import Socket qw(inet_ntoa);
  *yinet_aton = \&Socket::inet_aton;
  $Mode = 'Pure Perl';
}
else {
  $Mode = 'CC XS';
}

# allow user to choose upper or lower case

our $n2x_format = "%X:%X:%X:%X:%X:%X:%X:%X";
our $n2d_format = "%X:%X:%X:%X:%X:%X:%D.%D.%D.%D";

sub upper { $n2x_format = uc($n2x_format); $n2d_format = uc($n2d_format); }
sub lower { $n2x_format = lc($n2x_format); $n2d_format = lc($n2d_format); }

# if Socket lib is broken in some way, check for overange values
#
my $overange = yinet_aton('256.1') ? 1:0;

sub mode() { $Mode };

sub inet_aton {
  if (! $overange || $_[0] =~ /[^0-9\.]/) {	# hostname
    return &yinet_aton;
  }
  my @dq = split(/\./,$_[0]);
  foreach (@dq) {
    return undef if $_ > 255;
  }
  return &yinet_aton;
}

sub DESTROY {};

1;
__END__

=head1 NAME

NetAddr::IP::Util -- IPv4/6 and 128 bit number utilities

=head1 SYNOPSIS

  use NetAddr::IP::Util qw(
	inet_aton
	inet_ntoa
	ipv6_aton
	ipv6_n2x
	ipv6_n2d
	inet_any2n
	hasbits
	isIPv4
	inet_n2dx
	inet_n2ad
	ipv4to6
	mask4to6
	ipanyto6
	maskanyto6
	ipv6to4
	shiftleft
	addconst
	add128
	sub128
	notcontiguous
	bin2bcd
	bcd2bin
	mode
  );

  use NetAddr::IP::Util qw(:all :inet :ipv4 :ipv6 :math)

  :inet	  =>	inet_aton, inet_ntoa, ipv6_aton,
		ipv6_n2x, ipv6_n2d, inet_any2n,
		inet_n2dx, inet_n2ad, ipv4to6,
		mask4to6, ipanyto6, maskanyto6,
		ipv6to4

  :ipv4	  =>	inet_aton, inet_ntoa

  :ipv6	  =>	ipv6_aton, ipv6_n2x, ipv6_n2d,
		inet_any2n, inet_n2dx, inet_n2ad
		ipv4to6, mask4to6, ipanyto6,
		maskanyto6, ipv6to4

  :math	  =>	hasbits, isIPv4, addconst,
		add128, sub128, notcontiguous,
		bin2bcd, bcd2bin, shiftleft

  $dotquad = inet_ntoa($netaddr);
  $netaddr = inet_aton($dotquad);
  $ipv6naddr = ipv6_aton($ipv6_text);
  $hex_text = ipv6_n2x($ipv6naddr);
  $dec_text = ipv6_n2d($ipv6naddr);
  $ipv6naddr = inet_any2n($dotquad or $ipv6_text);
  $rv = hasbits($bits128);
  $rv = isIPv4($bits128);
  $dotquad or $hex_text = inet_n2dx($ipv6naddr);
  $dotquad or $dec_text = inet_n2ad($ipv6naddr);
  $ipv6naddr = ipv4to6($netaddr);
  $ipv6naddr = mask4to6($netaddr);
  $ipv6naddr = ipanyto6($netaddr);
  $ipv6naddr = maskanyto6($netaddr);
  $netaddr = ipv6to4($pv6naddr);
  $bitsX2 = shiftleft($bits128,$n);
  $carry = addconst($ipv6naddr,$signed_32con);
  ($carry,$ipv6naddr)=addconst($ipv6naddr,$signed_32con);
  $carry = add128($ipv6naddr1,$ipv6naddr2);
  ($carry,$ipv6naddr)=add128($ipv6naddr1,$ipv6naddr2);
  $carry = sub128($ipv6naddr1,$ipv6naddr2);
  ($carry,$ipv6naddr)=sub128($ipv6naddr1,$ipv6naddr2);
  ($spurious,$cidr) = notcontiguous($mask128);
  $bcdtext = bin2bcd($bits128);
  $bits128 = bcd2bin($bcdtxt);
  $modetext = mode;

  NetAddr::IP::Util::lower();
  NetAddr::IP::Util::upper();

=head1 INSTALLATION

Un-tar the distribution in an appropriate directory and type:

	perl Makefile.PL
	make
	make test
	make install

B<NetAddr::IP::Util> installs by default with its primary functions compiled
using Perl's XS extensions to build a 'C' library. If you do not have a 'C'
complier available or would like the slower Pure Perl version for some other
reason, then type:

	perl Makefile.PL -noxs
	make
	make test
	make install

=head1 DESCRIPTION

B<NetAddr::IP::Util> provides a suite of tools for manipulating and
converting IPv4 and IPv6 addresses into 128 bit string context and back to
text. The strings can be manipulated with Perl's logical operators:

	and	&
	or	|
	xor	^
		~	compliment

in the same manner as 'vec' strings.

The IPv6 functions support all rfc1884 formats.

  i.e.	x:x:x:x:x:x:x:x:x
	x:x:x:x:x:x:x:d.d.d.d
	::x:x:x
	::x:d.d.d.d
  and so on...

=over 4

=item * $dotquad = inet_ntoa($netaddr);

Convert a packed IPv4 network address to a dot-quad IP address.

  input:	packed network address
  returns:	IP address i.e. 10.4.12.123

=item * $netaddr = inet_aton($dotquad);

Convert a dot-quad IP address into an IPv4 packed network address.

  input:	IP address i.e. 192.5.16.32
  returns:	packed network address

=item * $ipv6addr = ipv6_aton($ipv6_text);

Takes an IPv6 address of the form described in rfc1884
and returns a 128 bit binary RDATA string.

  input:	ipv6 text
  returns:	128 bit RDATA string

=cut

sub ipv6_aton {
  my($ipv6) = @_;
  return undef unless $ipv6;
  local($1,$2,$3,$4,$5);
  if ($ipv6 =~ /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {	# mixed hex, dot-quad
    return undef if $2 > 255 || $3 > 255 || $4 > 255 || $5 > 255;
    $ipv6 = sprintf("%s%X%02X:%X%02X",$1,$2,$3,$4,$5);			# convert to pure hex
  }
  my $c;
  return undef if
	$ipv6 =~ /[^:0-9a-fA-F]/ ||			# non-hex character
	(($c = $ipv6) =~ s/::/x/ && $c =~ /(?:x|:):/) ||	# double :: ::?
	$ipv6 =~ /[0-9a-fA-F]{5,}/;			# more than 4 digits
  $c = $ipv6 =~ tr/:/:/;				# count the colons
  return undef if $c < 7 && $ipv6 !~ /::/;
  if ($c > 7) {						# strip leading or trailing ::
    return undef unless
	$ipv6 =~ s/^::/:/ ||
	$ipv6 =~ s/::$/:/;
    return undef if --$c > 7;
  }
  while ($c++ < 7) {					# expand compressed fields
    $ipv6 =~ s/::/:::/;
  }
  $ipv6 .= 0 if $ipv6 =~ /:$/;
  my @hex = split(/:/,$ipv6);
  foreach(0..$#hex) {
    $hex[$_] = hex($hex[$_] || 0);
  }
  pack("n8",@hex);
}

=item * $hex_text = ipv6_n2x($ipv6addr);

Takes an IPv6 RDATA string and returns an 8 segment IPv6 hex address

  input:	128 bit RDATA string
  returns:	x:x:x:x:x:x:x:x

=cut

sub ipv6_n2x {
  die "Bad arg length for 'ipv6_n2x', length is ". length($_[0]) ." should be 16"
	unless length($_[0]) == 16;
  return sprintf($n2x_format,unpack("n8",$_[0]));
}

=item * $dec_text = ipv6_n2d($ipv6addr);

Takes an IPv6 RDATA string and returns a mixed hex - decimal IPv6 address
with the 6 uppermost chunks in hex and the lower 32 bits in dot-quad
representation.

  input:	128 bit RDATA string
  returns:	x:x:x:x:x:x:d.d.d.d

=cut

sub ipv6_n2d {
  die "Bad arg length for 'ipv6_n2x', length is ". length($_[0]) ." should be 16"
	unless length($_[0]) == 16;
  my @hex = (unpack("n8",$_[0]));
  $hex[9] = $hex[7] & 0xff;
  $hex[8] = $hex[7] >> 8;
  $hex[7] = $hex[6] & 0xff;
  $hex[6] >>= 8;
  return sprintf($n2d_format,@hex);
}

=item * $ipv6naddr = inet_any2n($dotquad or $ipv6_text);

This function converts a text IPv4 or IPv6 address in text format in any
standard notation into a 128 bit IPv6 string address. It prefixes any
dot-quad address (if found) with '::' and passes it to B<ipv6_aton>.

  input:	dot-quad or rfc1844 address
  returns:	128 bit IPv6 string

=cut

sub inet_any2n($) {
  my($addr) = @_;
  $addr = '' unless $addr;
  $addr = '::' . $addr
	unless $addr =~ /:/;
  return ipv6_aton($addr);
}

=item * $rv = hasbits($bits128);

This function returns true if there are one's present in the 128 bit string
and false if all the bits are zero.

  i.e.	if (hasbits($bits128)) {
	  &do_something;
	}

  or	if (hasbits($bits128 & $mask128) {
	  &do_something;
	}

This allows the implementation of logical functions of the form of:

	if ($bits128 & $mask128) {
	    ...

  input:	128 bit IPv6 string
  returns:	true if any bits are present

=item * $rv = isIPv4($bits128);

This function returns true if there are no on bits present in the IPv6
portion of the 128 bit string and false otherwise.

=item * $dotquad or $hex_text = inet_n2dx($ipv6naddr);

This function B<does the right thing> and returns the text for either a
dot-quad IPv4 or a hex notation IPv6 address.

  input:	128 bit IPv6 string
  returns:	ddd.ddd.ddd.ddd
	    or	x:x:x:x:x:x:x:x

=cut

sub inet_n2dx($) {
  my($nadr) = @_;
  if (isIPv4($nadr)) {
    ipv6_n2d($nadr) =~ /([^:]+)$/;
    return $1;
  }
  return ipv6_n2x($nadr);
}

=item * $dotquad or $dec_text = inet_n2ad($ipv6naddr);

This function B<does the right thing> and returns the text for either a
dot-quad IPv4 or a hex::decimal notation IPv6 address.

  input:	128 bit IPv6 string
  returns:	ddd.ddd.ddd.ddd
	    or  x:x:x:x:x:x:ddd.ddd.ddd.dd

=cut

sub inet_n2ad($) {
  my($nadr) = @_;
  my $addr = ipv6_n2d($nadr);
  return $addr unless isIPv4($nadr);
  $addr =~ /([^:]+)$/;
  return $1;
}

=item * $ipv6naddr = ipv4to6($netaddr);

Convert an ipv4 network address into an ipv6 network address.

  input:	32 bit network address
  returns:	128 bit network address

=item * $ipv6naddr = mask4to6($netaddr);

Convert an ipv4 network address/mask into an ipv6 network mask.

  input:	32 bit network/mask address
  returns:	128 bit network/mask address

NOTE: returns the high 96 bits as one's

=item * $ipv6naddr = ipanyto6($netaddr);

Similar to ipv4to6 except that this function takes either an IPv4 or IPv6
input and always returns a 128 bit IPv6 network address.

  input:	32 or 128 bit network address
  returns:	128 bit network address

=item * $ipv6naddr = maskanyto6($netaddr);

Similar to mask4to6 except that this function takes either an IPv4 or IPv6
netmask and always returns a 128 bit IPv6 netmask.

  input:	32 or 128 bit network mask
  returns:	128 bit network mask

=item * $netaddr = ipv6to4($pv6naddr);

Truncate the upper 96 bits of a 128 bit address and return the lower
32 bits. Returns an IPv4 address as returned by inet_aton.

  input:	128 bit network address
  returns:	32 bit inet_aton network address

=item * $bitsXn = shiftleft($bits128,$n);

  input:	128 bit string variable,
		number of shifts [optional]
  returns:	bits X n shifts

  NOTE: a single shift is performed
	if $n is not specified

=item * addconst($ipv6naddr,$signed_32con);

Add a signed constant to a 128 bit string variable.

  input:	128 bit IPv6 string,
		signed 32 bit integer
  returns:  scalar	carry
	    array	(carry, result)

=item * add128($ipv6naddr1,$ipv6naddr2);

Add two 128 bit string variables.

  input:	128 bit string var1,
		128 bit string var2
  returns:  scalar	carry
	    array	(carry, result)

=item * sub128($ipv6naddr1,$ipv6naddr2);

Subtract two 128 bit string variables.

  input:	128 bit string var1,
		128 bit string var2
  returns:  scalar	carry
	    array	(carry, result)

Note: The carry from this operation is the result of adding the one's
complement of ARG2 +1 to the ARG1. It is logically
B<NOT borrow>.

	i.e. 	if ARG1 >= ARG2 then carry = 1
	or	if ARG1  < ARG2 then carry = 0


=item * ($spurious,$cidr) = notcontiguous($mask128);

This function counts the bit positions remaining in the mask when the
rightmost '0's are removed.

	input:	128 bit netmask
	returns true if there are spurious
		    zero bits remaining in the
		    mask, false if the mask is
		    contiguous one's,
		128 bit cidr number

=item * $bcdtext = bin2bcd($bits128);

Convert a 128 bit binary string into binary coded decimal text digits.

  input:	128 bit string variable
  returns:	string of bcd text digits

=item * $bits128 = bcd2bin($bcdtxt);

Convert a bcd text string to 128 bit string variable

  input:	string of bcd text digits
  returns:	128 bit string variable

=cut

#=item * $onescomp=NetAddr::IP::Util::comp128($ipv6addr);
#
#This function is not exported because it is more efficient to use perl " ~ "
#on the bit string directly. This interface to the B<C> routine is published for
#module testing purposes because it is used internally in the B<sub128> routine. The
#function is very fast, but calling if from perl directly is very slow. It is almost
#33% faster to use B<sub128> than to do a 1's comp with perl and then call
#B<add128>.
#
#=item * $bcdpacked = NetAddr::IP::Util::bin2bcdn($bits128);
#
#Convert a 128 bit binary string into binary coded decimal digits.
#This function is not exported.
#
#  input:	128 bit string variable
#  returns:	string of packed decimal digits
#
#  i.e.	text = unpack("H*", $bcd);
#
#=item * $bcdtext =  NetAddr::IP::Util::bcdn2txt($bcdpacked);
#
#Convert a packed bcd string into text digits, suppress the leading zeros.
#This function is not exported.
#
#  input:	string of packed decimal digits
#  returns:	hexadecimal digits
#
#Similar to unpack("H*", $bcd);
#
#=item * $bcdpacked = NetAddr::IP::Util::simple_pack($bcdtext);
#
#Convert a numeric string into a packed bcd string, left fill with zeros
#
#  input:	string of decimal digits
#  returns:	string of packed decimal digits
#
#Similar to pack("H*", $bcdtext);

=item * $modetext = mode;

Returns the operating mode of this module.

	input:		none
	returns:	"Pure Perl"
		   or	"CC XS"

=item * NetAddr::IP::Util::lower();

Return IPv6 strings in lowercase.

=item * NetAddr::IP::Util::upper();

Return IPv6 strings in uppercase.  This is the default.

=back

=head1 EXAMPLES


  # convert any textual IP address into a 128 bit vector
  #
  sub text2vec {
    my($anyIP,$anyMask) = @_;

  # not IPv4 bit mask
    my $notiv4 = ipv6_aton('FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::');

    my $vecip	= inet_any2n($anyIP);
    my $mask	= inet_any2n($anyMask);

  # extend mask bits for IPv4
    my $bits = 128;	# default
    unless (hasbits($mask & $notiv4)) {
      $mask |= $notiv4;
      $bits = 32;
    }
    return ($vecip, $mask, $bits);
  }

  ... alternate implementation, a little faster

  sub text2vec {
    my($anyIP,$anyMask) = @_;

  # not IPv4 bit mask
    my $notiv4 = ipv6_aton('FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::');

    my $vecip	= inet_any2n($anyIP);
    my $mask	= inet_any2n($anyMask);

  # extend mask bits for IPv4
    my $bits = 128;	# default
    if (isIPv4($mask)) {
      $mask |= $notiv4;
      $bits = 32;
    }
    return ($vecip, $mask, $bits);
  }


  ... elsewhere
    $nip = {
	addr	=> $vecip,
	mask	=> $mask,
	bits	=> $bits,
    };

  # return network and broadcast addresses from IP and Mask
  #
  sub netbroad {
    my($nip) = shift;
    my $notmask	= ~ $nip->{mask};
    my $bcast	= $nip->{addr} | $notmask;
    my $network	= $nip->{addr} & $nip->{mask};
    return ($network, $broadcast);
  }

  # check if address is within a network
  #
  sub within {
    my($nip,$net) = @_;
    my $addr = $nip->{addr}
    my($nw,$bc) = netbroad($net);
  # arg1 >= arg2, sub128 returns true
    return (sub128($addr,$nw) && sub128($bc,$addr))
	? 1 : 0;
  }

  # add a constant, wrapping at netblock boundaries
  # to subtract the constant, negate it before calling
  # 'addwrap' since 'addconst' will extend the sign bits
  #
  sub addwrap {
    my($nip,$const) = @_;
    my $mask	= $nip->{addr};
    my $bits	= $nip->{bits};
    my $notmask	= ~ $mask;
    my $hibits	= $addr & $mask;
    my $addr = addconst($addr,$const);
    my $wraponly = $addr & $notmask;
    my $newip = {
	addr	=> $hibits | $wraponly,
	mask	=> $mask,
	bits	=> $bits,
    };
    # bless $newip as appropriate
    return $newip;
  }

=head1 EXPORT_OK

	inet_aton
	inet_ntoa
	ipv6_aton
	ipv6_n2x
	ipv6_n2d
	inet_any2n
	hasbits
	isIPv4
	inet_n2dx
	inet_n2ad
	ipv4to6
	mask4to6
	ipanyto6
	maskanyto6
	ipv6to4
	shiftleft
	addconst
	add128
	sub128
	notcontiguous
	bin2bcd
	bcd2bin
	mode

=head1 AUTHOR

Michael Robinton <michael@bizsystems.com>

=head1 ACKNOWLEDGMENTS

The following functions are used in whole or in part as include files to
Util.xs. The copyright is include in the file.

  file:		     function:

  miniSocket.inc  inet_aton, inet_ntoa

inet_aton, inet_ntoa are from the perl-5.8.0 release by Larry Wall, copyright
1989-2002. inet_aton, inet_ntoa code is current through perl-5.9.3 release.
Thank you Larry for making PERL possible for all of us.

=head1 COPYRIGHT

Copyright 2003 - 2008, Michael Robinton E<lt>michael@bizsystems.comE<gt>

LICENSE AND WARRANTY

This software is (c) Michael Robinton.  It can be used under the terms of
the perl artistic license provided  that proper credit for the work of
the  author is  preserved in  the form  of this  copyright  notice and
license for this module.

No warranty of any kind is  expressed or implied, by using it
you accept any and all the liability.


=head1 AUTHOR

Michael Robinton <michael@bizsystems.com>

=cut

1;

