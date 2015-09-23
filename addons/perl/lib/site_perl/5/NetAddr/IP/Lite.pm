#!/usr/bin/perl

package NetAddr::IP::Lite;

use Carp;
use strict;
#use diagnostics;
#use warnings;
use NetAddr::IP::Util qw(
	inet_any2n
	addconst
	sub128
	ipv6to4
	notcontiguous
	isIPv4
	shiftleft
	inet_n2dx
	hasbits
	bin2bcd
	bcd2bin
	inet_aton
	inet_any2n
	ipv6_aton
	ipv6_n2x
	mask4to6
	ipv4to6
);
use vars qw(@ISA @EXPORT_OK $VERSION $Accept_Binary_IP $Old_nth $AUTOLOAD *Zero);

$VERSION = do { my @r = (q$Revision: 1.13 $ =~ /\d+/g); sprintf "%d."."%02d" x $#r, @r };

require Exporter;

@ISA = qw(Exporter);

@EXPORT_OK = qw(Zeros Zero Ones V4mask V4net);

# Set to true, to enable recognizing of ipV4 && ipV6 binary notation IP
# addresses. Thanks to Steve Snodgrass for reporting. This can be done
# at the time of use-ing the module. See docs for details.

$Accept_Binary_IP = 0;
$Old_nth = 0;
*Zero = \&Zeros;

=head1 NAME

NetAddr::IP::Lite - Manages IPv4 and IPv6 addresses and subnets

=head1 SYNOPSIS

  use NetAddr::IP::Lite qw(
	Zeros
	Ones
	V4mask
	V4net
	:aton		DEPRECATED !
	:old_nth
  );

  my $ip = new NetAddr::IP::Lite '127.0.0.1';
	or from a packed IPv4 address
  my $ip = new_from_aton NetAddr::IP::Lite (inet_aton('127.0.0.1'));
	or from an octal filtered IPv4 address
  my $ip = new_no NetAddr::IP::Lite '127.012.0.0';

  print "The address is ", $ip->addr, " with mask ", $ip->mask, "\n" ;

  if ($ip->within(new NetAddr::IP::Lite "127.0.0.0", "255.0.0.0")) {
      print "Is a loopback address\n";
  }

				# This prints 127.0.0.1/32
  print "You can also say $ip...\n";

  The following four functions return ipV6 representations of:

  ::					   = Zeros();
  FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF  = Ones();
  FFFF:FFFF:FFFF:FFFF:FFFF:FFFF::	   = V4mask();
  ::FFFF:FFFF				   = V4net();

=head1 INSTALLATION

Un-tar the distribution in an appropriate directory and type:

	perl Makefile.PL
	make
	make test
	make install

B<NetAddr::IP::Lite> depends on B<NetAddr::IP::Util> which installs by default with its primary functions compiled
using Perl's XS extensions to build a 'C' library. If you do not have a 'C'
complier available or would like the slower Pure Perl version for some other
reason, then type:

	perl Makefile.PL -noxs
	make
	make test
	make install

=head1 DESCRIPTION

This module provides an object-oriented abstraction on top of IP
addresses or IP subnets, that allows for easy manipulations. Most of the
operations of NetAddr::IP are supported. This module will work older
versions of Perl and does B<not> use Math::BigInt.

The internal representation of all IP objects is in 128 bit IPv6 notation.
IPv4 and IPv6 objects may be freely mixed.

The supported operations are described below:

=cut

# in the off chance that NetAddr::IP::Lite objects are created
# and the caller later loads NetAddr::IP and expects to use
# those objects, let the AUTOLOAD routine find and redirect
# NetAddr::IP::Lite method and subroutine calls to NetAddr::IP.
#

my $parent = 'NetAddr::IP';

# test function
#
# input:	subroutine name in NetAddr::IP
# output:	t/f	if sub name exists in NetAddr::IP namespace
#
#sub sub_exists {
#  my $other = $parent .'::';
#  return exists ${$other}{$_[0]};
#}

sub DESTROY {};

sub AUTOLOAD {
  no strict;
  my ($pkg,$func) = ($AUTOLOAD =~ /(.*)::([^:]+)$/);
  my $other = $parent .'::';

  if ($pkg =~ /^$other/o && exists ${$other}{$func}) {
    $other .= $func;
    goto &{$other};
  }

  my @stack = caller(0);

  if ( $pkg eq ref $_[0] ) {
    $other = qq|Can't locate object method "$func" via|;
  }
  else {
    $other = qq|Undefined subroutine \&$AUTOLOAD not found in|;
  }
  die $other . qq| package "$parent" or "$pkg" (did you forgot to load a module?) at $stack[1] line $stack[2].\n|;
}

=head2 Overloaded Operators

=cut

# these really should be packed in Network Long order but since they are
# symmetrical, that extra internal processing can be skipped

my $_v4zero = pack('L',0);
my $_zero = pack('L4',0,0,0,0);
my $_ones = ~$_zero;
my $_v4mask = pack('L4',0xffffffff,0xffffffff,0xffffffff,0);
my $_v4net = ~ $_v4mask;

sub Zeros() {
  return $_zero;
}
sub Ones() {
  return $_ones;
}
sub V4mask() {
  return $_v4mask;
}
sub V4net() {
  return $_v4net;
}

				#############################################
				# These are the overload methods, placed here
				# for convenience.
				#############################################

use overload

    '+'		=> \&plus,

    '-'		=> \&minus,

    '++'	=> \&plusplus,

    '--'	=> \&minusminus,

    "="		=> \&copy,

    '""'	=> sub { $_[0]->cidr(); },

    'eq'	=> sub {
	my $a = (UNIVERSAL::isa($_[0],__PACKAGE__)) ? $_[0]->cidr : $_[0];
	my $b = (UNIVERSAL::isa($_[1],__PACKAGE__)) ? $_[1]->cidr : $_[1];
	$a eq $b;
    },

    '=='	=> sub {
	return 0 unless UNIVERSAL::isa($_[0],__PACKAGE__) && UNIVERSAL::isa($_[1],__PACKAGE__);
	$_[0]->cidr eq $_[1]->cidr;
    },

    '>'		=> sub {
	return &comp_addr_mask > 0 ? 1 : 0;
    },

    '<'		=> sub {
	return &comp_addr_mask < 0 ? 1 : 0;
    },

    '>='	=> sub {
	return &comp_addr_mask < 0 ? 0 : 1;
    },

    '<='	=> sub {
	return &comp_addr_mask > 0 ? 0 : 1;
    },

    '<=>'	=> \&comp_addr_mask,

    'cmp'	=> \&comp_addr_mask;

sub comp_addr_mask {
  my($c,$rv) = sub128($_[0]->{addr},$_[1]->{addr});
  return -1 unless $c;
  return 1 if hasbits($rv);
  ($c,$rv) = sub128($_[0]->{mask},$_[1]->{mask});
  return -1 unless $c;
  return hasbits($rv) ? 1 : 0;
}

#sub comp_addr {
#  my($c,$rv) = sub128($_[0]->{addr},$_[1]->{addr});
#  return -1 unless $c;
#  return hasbits($rv) ? 1 : 0;
#}

=pod

=over

=item B<Assignment (C<=>)>

Has been optimized to copy one NetAddr::IP::Lite object to another very quickly.

=item B<C<-E<gt>copy()>>

The B<assignment (C<=>)> operation is only put in to operation when the
copied object is further mutated by another overloaded operation. See
L<overload> B<SPECIAL SYMBOLS FOR "use overload"> for details.

B<C<-E<gt>copy()>> actually creates a new object when called.

=cut

sub copy {
	return _new($_[0],$_[0]->{addr}, $_[0]->{mask});
}

=item B<Stringification>

An object can be used just as a string. For instance, the following code

	my $ip = new NetAddr::IP::Lite '192.168.1.123';
        print "$ip\n";

Will print the string 192.168.1.123/32.

	my $ip = new6 NetAddr::IP::Lite '192.168.1.123';
	print "$ip\n";

Will print the string

=item B<Equality>

You can test for equality with either C<eq> or C<==>. C<eq> allows the
comparison with arbitrary strings as well as NetAddr::IP::Lite objects. The
following example:

    if (NetAddr::IP::Lite->new('127.0.0.1','255.0.0.0') eq '127.0.0.1/8')
       { print "Yes\n"; }

Will print out "Yes".

Comparison with C<==> requires both operands to be NetAddr::IP::Lite objects.

In both cases, a true value is returned if the CIDR representation of
the operands is equal.

=item B<Comparison via E<gt>, E<lt>, E<gt>=, E<lt>=, E<lt>=E<gt> and C<cmp>>

Internally, all network objects are represented in 128 bit format.
The numeric representation of the network is compared through the
corresponding operation. Comparisons are tried first on the address portion
of the object and if that is equal then the NUMERIC cidr portion of the
masks are compared. This leads to the counterintuitive result that

        /24 > /16

Comparison should not be done on netaddr objects with different CIDR as
this may produce indeterminate - unexpected results,
rather the determination of which netblock is larger or smaller should be
done by comparing

        $ip1->masklen <=> $ip2->masklen

=item B<Addition of a constant (C<+>)>

Add a 32 bit signed constant to the address part of a NetAddr object.
This operation changes the address part to point so many hosts above the
current objects start address. For instance, this code:

    print NetAddr::IP::Lite->new('127.0.0.1') + 5;

will output 127.0.0.6/8. The address will wrap around at the broadcast
back to the network address. This code:

    print NetAddr::IP::Lite->new('10.0.0.1/24') + 255;

outputs 10.0.0.0/24.

Returns the the unchanged object when the constant is missing or out of range.

    2147483647 <= constant >= -2147483648

=cut

sub plus {
    my $ip	= shift;
    my $const	= shift;

    return $ip unless $const &&
		$const < 2147483648 &&
		$const > -2147483649;

    my $a = $ip->{addr};
    my $m = $ip->{mask};

    my $lo = $a & ~$m;
    my $hi = $a & $m;

    my $new = ((addconst($lo,$const))[1] & ~$m) | $hi;

    return _new($ip,$new,$m);
}

=item B<Subtraction of a constant (C<->)>

The complement of the addition of a constant.

=item B<Difference (C<->)>

Returns the difference between the address parts of two NetAddr::IP::Lite
objects address parts as a 32 bit signed number.

Returns B<undef> if the difference is out of range.

=cut

my $_smsk = pack('L3N',0xffffffff,0xffffffff,0xffffffff,0x80000000);

sub minus {
    my $ip	= shift;
    my $arg	= shift;
    unless (ref $arg) {
	return plus($ip, -$arg);
    }
    my($carry,$dif) = sub128($ip->{addr},$arg->{addr});
    if ($carry) {					# value is positive
	return undef if hasbits($dif & $_smsk);		# all sign bits should be 0's
	return (unpack('L3N',$dif))[3];
    } else {
	return undef if hasbits(($dif & $_smsk) ^ $_smsk);	# sign is 1's
	return (unpack('L3N',$dif))[3] - 4294967296;
    }
}

				# Auto-increment an object

=item B<Auto-increment>

Auto-incrementing a NetAddr::IP::Lite object causes the address part to be
adjusted to the next host address within the subnet. It will wrap at
the broadcast address and start again from the network address.

=cut

sub plusplus {
    my $ip	= shift;

    my $a = $ip->{addr};
    my $m = $ip->{mask};

    my $lo = $a & ~ $m;
    my $hi = $a & $m;

    $ip->{addr} = ((addconst($lo,1))[1] & ~ $m) | $hi;
    return $ip;
}

=item B<Auto-decrement>

Auto-decrementing a NetAddr::IP::Lite object performs exactly the opposite
of auto-incrementing it, as you would expect.

=cut

sub minusminus {
    my $ip	= shift;

    my $a = $ip->{addr};
    my $m = $ip->{mask};

    my $lo = $a & ~$m;
    my $hi = $a & $m;

    $ip->{addr} = ((addconst($lo,-1))[1] & ~$m) | $hi;
    return $ip;
}

				#############################################
				# End of the overload methods.
				#############################################

# Preloaded methods go here.

				# This is a variant to ->new() that
				# creates and blesses a new object
				# without the fancy parsing of
				# IP formats and shorthands.

# return a blessed IP object without parsing
# input:	prototype, naddr, nmask
# returns:	blessed IP object
#
sub _new ($$$) {
  my $proto = shift;
  my $class = ref($proto) || die "reference required";
  $proto = $proto->{isv6};
  my $self = {
	addr	=> $_[0],
	mask	=> $_[1],
	isv6	=> $proto,
  };
  return bless $self, $class;
}

=pod

=back

=head2 Methods

=over

=item C<-E<gt>new([$addr, [ $mask|IPv6 ]])>

=item C<-E<gt>new6([$addr, [ $mask]])>

=item C<-E<gt>new_no([$addr, [ $mask]])>

=item C<-E<gt>new_from_aton($netaddr)>

The first two methods create a new address with the supplied address in
C<$addr> and an optional netmask C<$mask>, which can be omitted to get
a /32 or /128 netmask for IPv4 / IPv6 addresses respectively.

The third method C<new_no> is exclusively for IPv4 addresses and filters
improperly formatted
dot quad strings for leading 0's that would normally be interpreted as octal
format by NetAddr per the specifications for inet_aton.

B<new_from_aton> takes a packed IPv4 address and assumes a /32 mask. This
function replaces the DEPRECATED :aton functionality which is fundamentally
broken.

C<-E<gt>new6> marks the address as being in ipV6 address space even if the
format would suggest otherwise.

  i.e.	->new6('1.2.3.4') will result in ::102:304

  addresses submitted to ->new in ipV6 notation will
  remain in that notation permanently. i.e.
	->new('::1.2.3.4') will result in ::102:304
  whereas new('1.2.3.4') would print out as 1.2.3.4

  See "STRINGIFICATION" below.

C<$addr> can be almost anything that can be resolved to an IP address
in all the notations I have seen over time. It can optionally contain
the mask in CIDR notation.

B<prefix> notation is understood, with the limitation that the range
specified by the prefix must match with a valid subnet.

Addresses in the same format returned by C<inet_aton> or
C<gethostbyname> can also be understood, although no mask can be
specified for them. The default is to not attempt to recognize this
format, as it seems to be seldom used.

###### DEPRECATED, will be remove in version 5 ############
To accept addresses in that format, invoke the module as in

  use NetAddr::IP::Lite ':aton'

###### USE new_from_aton instead ##########################

If called with no arguments, 'default' is assumed.

C<$addr> can be any of the following and possibly more...

  n.n
  n.n/mm
  n.n.n
  n.n.n/mm
  n.n.n.n
  n.n.n.n/mm		32 bit cidr notation
  n.n.n.n/m.m.m.m
  loopback, localhost, broadcast, any, default
  x.x.x.x/host
  0xABCDEF, 0b111111000101011110, (or a bcd number)
  a netaddr as returned by 'inet_aton'


Any RFC1884 notation

  ::n.n.n.n
  ::n.n.n.n/mmm		128 bit cidr notation
  ::n.n.n.n/::m.m.m.m
  ::x:x
  ::x:x/mmm
  x:x:x:x:x:x:x:x
  x:x:x:x:x:x:x:x/mmm
  x:x:x:x:x:x:x:x/m:m:m:m:m:m:m:m any RFC1884 notation
  loopback, localhost, unspecified, any, default
  ::x:x/host
  0xABCDEF, 0b111111000101011110 within the limits
  of perl's number resolution
  123456789012  a 'big' bcd number i.e. Math::BigInt

If called with no arguments, 'default' is assumed.

=cut

my %fip4 = (
        default         => Zeros,
        any             => Zeros,
        broadcast       => inet_any2n('255.255.255.255'),
        loopback        => inet_any2n('127.0.0.1'),
	unspecified	=> undef,
);
my %fip4m = (
        default         => Zeros,
        any             => Zeros,
        broadcast       => Ones,
        loopback        => mask4to6(inet_aton('255.0.0.0')),
	unspecified	=> undef,	# not applicable for ipV4
	host		=> Ones,
);

my %fip6 = (
	default         => Zeros,
	any             => Zeros,
	broadcast       => undef,	# not applicable for ipV6
	loopback        => inet_any2n('::1'),
	unspecified     => Zeros,
);

my %fip6m = (
	default         => Zeros,
	any             => Zeros,
	broadcast       => undef,	# not applicable for ipV6
	loopback        => Ones,
	unspecified     => Ones,
	host		=> Ones,
);

my $ff000000 = pack('L3N',0xffffffff,0xffffffff,0xffffffff,0xFF000000);
my $ffff0000 = pack('L3N',0xffffffff,0xffffffff,0xffffffff,0xFFFF0000);
my $ffffff00 = pack('L3N',0xffffffff,0xffffffff,0xffffffff,0xFFFFFF00);

sub _obits ($$) {
    my($lo,$hi) = @_;

    return 0xFF if $lo == $hi;
    return (~ ($hi ^ $lo)) & 0xFF;
}

sub new_no($;$$) {
  unshift @_, -1;
  goto &_xnew;
}

sub new($;$$) {
  unshift @_, 0;
  goto &_xnew;
}

sub new_from_aton($$) {
  my $proto     = shift;
  my $class = ref $proto || $proto || __PACKAGE__;
  my $ip = shift;
  return undef unless defined $ip;
  my $addrlen = length($ip);
  return undef unless $addrlen == 4;
  my $self = {
	addr    => ipv4to6($ip),
	mask    => &Ones,
	isv6    => 0,
  };
  return bless $self, $class;
}

sub new6($;$$) {
  unshift @_, 1;
  goto &_xnew;
}

sub _no_octal {
  $_[0] =~ m/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
  return sprintf("%d.%d.%d.%d",$1,$2,$3,$4);
}

sub _xnew($$;$$) {
  my $noctal	= 0;
  my $isV6	= shift;
  if ($isV6 < 0) {		# flag for no octal?
    $isV6	= 0;
    $noctal	= 1;
  }
  my $proto	= shift;
  my $class	= ref $proto || $proto || __PACKAGE__;
  my $ip	= lc shift;
  $ip = 'default' unless defined $ip;
  my $hasmask = 1;
  my($mask,$tmp);

  while (1) {
    unless (@_) {
      if ($ip =~ m!^(.+)/(.+)$!) {
	$ip	= $1;
	$mask	= $2;
      } elsif (grep($ip eq $_,qw(default any broadcast loopback unspecified))) {
	$isV6 = 1 if $ip eq 'unspecified';
	if ($isV6) {
	  $mask = $fip6m{$ip};
	  return undef unless defined ($ip = $fip6{$ip});
	} else {
	  $mask	= $fip4m{$ip};
	  return undef unless defined ($ip = $fip4{$ip});
	}
	last;
      }
    }
    elsif (defined $_[0]) {
      if ($_[0] =~ /ipv6/i || $isV6) {
	if (grep($ip eq $_,qw(default any loopback unspecified))) {
	  $mask	= $fip6m{$ip};
	  $ip	= $fip6{$ip};
	  last;
	} else {
	  return undef;
        }
      } else {
	$mask = lc $_[0];
      }
    }
    unless (defined $mask) {
      $hasmask	= 0;
      $mask	= 'host';
    }

# parse mask
    if ($mask =~ /^(\d+)$/) {
      if (index($ip,':') < 0) {			# is ipV4
	if ($1 == 32) {				# cidr 32
	  $mask = Ones;
	}
	elsif ($mask < 32) {			# small cidr
	  $mask = shiftleft(Ones,32 -$1);
	} else {				# is a binary mask
	  $mask = pack('L3N',0xffffffff,0xffffffff,0xffffffff,$1);
	}
      } else {					# is ipV6
	$isV6	= 1;
	if ($1 == 128) {			# cidr 128
	  $mask = Ones;
	}
	elsif ($mask < 128) {			# small cidr
	  $mask = shiftleft(Ones,128 -$1);
	} else {				# is a binary mask
	  $mask = bcd2bin($1);
	}
      }
    } elsif ($mask =~ m/^\d+\.\d+\.\d+\.\d+$/) { # ipv4 form of mask
      $mask = _no_octal($mask) if $noctal;	# filter for octal
      return undef unless defined ($mask = inet_aton($mask));
      $mask = mask4to6($mask);
    } elsif (grep($mask eq $_,qw(default any broadcast loopback unspecified host))) {
      if (index($ip,':') < 0 && ! $isV6) {
	return undef unless defined ($mask = $fip4m{$mask});
      } else {
	return undef unless defined ($mask = $fip6m{$mask});
      }
    } else {
      return undef unless defined ($mask = ipv6_aton($mask));	# try ipv6 form of mask
    }

# parse IP

    if (index($ip,':') < 0) {				# ipv4 address
      if ($ip =~ m/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
	;	# the common case
      }
      elsif (grep($ip eq $_,qw(default any broadcast loopback))) {
	return undef unless defined ($ip = $fip4{$ip});
	last;
      }
      elsif ($ip =~ m/^(\d+)\.(\d+)$/) {
	$ip = ($hasmask)
		? "${1}.${2}.0.0"
		: "${1}.0.0.${2}";
      }
      elsif ($ip =~ m/^(\d+)\.(\d+)\.(\d+)$/) {
	$ip = ($hasmask)
		? "${1}.${2}.${3}.0"
		: "${1}.${2}.0.${3}";
      }
      elsif ($ip =~ /^(\d+)$/ && $hasmask && $1 >= 0 and $1 < 256) { # pure numeric
	$ip = sprintf("%d.0.0.0",$1);
      }
      elsif ($ip =~ /^\d+$/ && !$hasmask) {	# a big integer
	$ip = bcd2bin($ip);
	last;
      }
      elsif ($ip =~ /^0[xb]\d+$/ && $hasmask &&
		(($tmp = eval "$ip") || 1) &&
		$tmp >= 0 && $tmp < 256) {
        $ip = sprintf("%d.0.0.0",$tmp);
      }
      elsif ($ip =~ /^-?\d+$/) {
	$ip += 2 ** 32 if $ip < 0;
	$ip = pack('L3N',0,0,0,$ip);
	last;
      }
      elsif ($ip =~ /^-?0[xb]\d+$/) {
	$ip = eval "$ip";
	$ip = pack('L3N',0,0,0,$ip);
	last;
      }

#	notations below include an implicit mask specification

      elsif ($ip =~ m/^(\d+)\.$/) {
	$ip = "${1}.0.0.0";
	$mask = $ff000000;
      }
      elsif ($ip =~ m/^(\d+)\.(\d+)-(\d+)\.?$/ && $2 <= $3 && $3 < 256) {
	$ip = "${1}.${2}.0.0";
	$mask = pack('L3C4',0xffffffff,0xffffffff,0xffffffff,255,_obits($2,$3),0,0);
      }
      elsif ($ip =~ m/^(\d+)-(\d+)\.?$/ and $1 <= $2 && $2 < 256) {
	$ip = "${1}.0.0.0";
	$mask = pack('L3C4',0xffffffff,0xffffffff,0xffffffff,_obits($1,$2),0,0,0)
      }
      elsif ($ip =~ m/^(\d+)\.(\d+)\.$/) {
	$ip = "${1}.${2}.0.0";
	$mask = $ffff0000;
      }
      elsif ($ip =~ m/^(\d+)\.(\d+)\.(\d+)-(\d+)\.?$/ && $3 <= $4 && $4 < 256) {
	$ip = "${1}.${2}.${3}.0";
	$mask = pack('L3C4',0xffffffff,0xffffffff,0xffffffff,255,255,_obits($3,$4),0);
      }
      elsif ($ip =~ m/^(\d+)\.(\d+)\.(\d+)\.$/) {
	$ip = "${1}.${2}.${3}.0";
	$mask = $ffffff00;
      }
      elsif ($ip =~ m/^(\d+)\.(\d+)\.(\d+)\.(\d+)-(\d+)$/ && $4 <= $5 && $5 < 256) {
	$ip = "${1}.${2}.${3}.${4}";
	$mask = pack('L3C4',0xffffffff,0xffffffff,0xffffffff,255,255,255,_obits($4,$5));
      }
      elsif ($ip =~ m/^(\d+\.\d+\.\d+\.\d+)
		\s*-\s*(\d+\.\d+\.\d+\.\d+)$/x) {
	if ($noctal) {
	  return undef unless ($ip = inet_aton(_no_octal($1)));
	  return undef unless ($tmp = inet_aton(_no_octal($2)));
	} else {
	  return undef unless ($ip = inet_aton($1));
	  return undef unless ($tmp = inet_aton($2));
	}
# check for left side greater than right side
# save numeric difference in $mask
	return undef if ($tmp = unpack('N',$tmp) - unpack('N',$ip)) < 0;
	$ip = ipv4to6($ip);
	$tmp = pack('L3N',0,0,0,$tmp);
	$mask = ~$tmp;
	return undef if notcontiguous($mask);
# check for non-aligned left side
	return undef if hasbits($ip & $tmp);
	last;
      }
      elsif ($ip !~ /[^a-zA-Z0-9\.-]/ && ($tmp = gethostbyname($ip)) && $tmp ne $_v4zero && $tmp ne $_zero ) {
	$ip = ipv4to6($tmp);
	last;
      }
      elsif ($Accept_Binary_IP && ! $hasmask) {
	if (length($ip) == 4) {
	  $ip = ipv4to6($ip);
	} elsif (length($ip) == 16) {
	  $isV6 = 1;
	} else {
	  return undef;
	}
	last;
      } else {
	return undef;
      }
      return undef unless defined ($ip = inet_aton($ip));
      $ip = ipv4to6($ip);
      last;
    }
########## continuing
    else {						# ipv6 address
      $isV6 = 1;
      if (defined ($tmp = ipv6_aton($ip))) {
	$ip = $tmp;
	last;
      }
      last if grep($ip eq $_,qw(default any loopback unspecified)) &&
		defined ($ip = $fip6{$ip});
      return undef;
    }
  } # end while (1)

  return undef if notcontiguous($mask);			# invalid if not contiguous

  my $self = {
	addr	=> $ip,
	mask	=> $mask,
	isv6	=> $isV6,
  };
  return bless $self, $class;
}

=item C<-E<gt>broadcast()>

Returns a new object referring to the broadcast address of a given
subnet. The broadcast address has all ones in all the bit positions
where the netmask has zero bits. This is normally used to address all
the hosts in a given subnet.

=cut

sub broadcast ($) {
  my $ip = _new($_[0],$_[0]->{addr} | ~$_[0]->{mask},$_[0]->{mask});
  $ip->{addr} &= V4net unless $ip->{isv6};
  return $ip;
}

=item C<-E<gt>network()>

Returns a new object referring to the network address of a given
subnet. A network address has all zero bits where the bits of the
netmask are zero. Normally this is used to refer to a subnet.

=cut

sub network ($) {
  return _new($_[0],$_[0]->{addr} & $_[0]->{mask},$_[0]->{mask});
}

=item C<-E<gt>addr()>

Returns a scalar with the address part of the object as an IPv4 or IPv6 text
string as appropriate. This is useful for printing or for passing the address
part of the NetAddr::IP::Lite object to other components that expect an IP
address. If the object is an ipV6 address or was created using ->new6($ip)
it will be reported in ipV6 hex format otherwise it will be reported in dot
quad format only if it resides in ipV4 address space.

=cut

sub addr ($) {
  return ($_[0]->{isv6})
	? ipv6_n2x($_[0]->{addr})
	: inet_n2dx($_[0]->{addr});
}

=item C<-E<gt>mask()>

Returns a scalar with the mask as an IPv4 or IPv6 text string as
described above.

=cut

sub mask ($) {
  return ipv6_n2x($_[0]->{mask}) if $_[0]->{isv6};
  my $mask = isIPv4($_[0]->{addr})
	? $_[0]->{mask} & V4net
	: $_[0]->{mask};
  return inet_n2dx($mask);
}

=item C<-E<gt>masklen()>

Returns a scalar the number of one bits in the mask.

=cut

sub masklen ($) {
  my $len = (notcontiguous($_[0]->{mask}))[1];
  return 0 unless $len;
  return $len if $_[0]->{isv6};
  return isIPv4($_[0]->{addr})
	? $len -96
	: $len;
}

=item C<-E<gt>bits()>

Returns the width of the address in bits. Normally 32 for v4 and 128 for v6.

=cut

sub bits {
  return $_[0]->{isv6} ? 128 : 32;
}

=item C<-E<gt>version()>

Returns the version of the address or subnet. Currently this can be
either 4 or 6.

=cut

sub version {
  my $self = shift;
  return $self->{isv6} ? 6 : 4;
}

=item C<-E<gt>cidr()>

Returns a scalar with the address and mask in CIDR notation. A
NetAddr::IP::Lite object I<stringifies> to the result of this function.
(see comments about ->new6() and ->addr() for output formats)

=cut

sub cidr ($) {
  return $_[0]->addr . '/' . $_[0]->masklen;
}

=item C<-E<gt>aton()>

Returns the address part of the NetAddr::IP::Lite object in the same format
as the C<inet_aton()> or C<ipv6_aton> function respectively. If the object
was created using ->new6($ip), the address returned will always be in ipV6
format, even for addresses in ipV4 address space.

=cut

sub aton {
  return $_[0]->{addr} if $_[0]->{isv6};
  return isIPv4($_[0]->{addr})
	? ipv6to4($_[0]->{addr})
	: $_[0]->{addr};
}

=item C<-E<gt>range()>

Returns a scalar with the base address and the broadcast address
separated by a dash and spaces. This is called range notation.

=cut

sub range ($) {
  return $_[0]->network->addr . ' - ' . $_[0]->broadcast->addr;
}

=item C<-E<gt>numeric()>

When called in a scalar context, will return a numeric representation
of the address part of the IP address. When called in an array
contest, it returns a list of two elements. The first element is as
described, the second element is the numeric representation of the
netmask.

This method is essential for serializing the representation of a
subnet.

=cut

sub numeric ($) {
  if (wantarray) {
    if (! $_[0]->{isv6} && isIPv4($_[0]->{addr})) {
      return (	sprintf("%u",unpack('N',ipv6to4($_[0]->{addr}))),
		sprintf("%u",unpack('N',ipv6to4($_[0]->{mask}))));
    }
    else {
      return (	bin2bcd($_[0]->{addr}),
		bin2bcd($_[0]->{mask}));
    }
  }
  return (! $_[0]->{isv6} && isIPv4($_[0]->{addr}))
    ? sprintf("%u",unpack('N',ipv6to4($_[0]->{addr})))
    : bin2bcd($_[0]->{addr});
}

=item C<$me-E<gt>contains($other)>

Returns true when C<$me> completely contains C<$other>. False is
returned otherwise and C<undef> is returned if C<$me> and C<$other>
are not both C<NetAddr::IP::Lite> objects.

=cut

sub contains ($$) {
  return within(@_[1,0]);
}

=item C<$me-E<gt>within($other)>

The complement of C<-E<gt>contains()>. Returns true when C<$me> is
completely contained within C<$other>, undef if C<$me> and C<$other>
are not both C<NetAddr::IP::Lite> objects.

=cut

sub within ($$) {
  return 1 unless hasbits($_[1]->{mask});	# 0x0 contains everything
  my $netme	= $_[0]->{addr} & $_[0]->{mask};
  my $brdme	= $_[0]->{addr} | ~ $_[0]->{mask};
  my $neto	= $_[1]->{addr} & $_[1]->{mask};
  my $brdo	= $_[1]->{addr} | ~ $_[1]->{mask};
  return (sub128($netme,$neto) && sub128($brdo,$brdme))
	? 1 : 0;
}

=item C<-E<gt>first()>

Returns a new object representing the first usable IP address within
the subnet (ie, the first host address).

=cut

sub first ($) {
  return $_[0]->network + 1;
}

=item C<-E<gt>last()>

Returns a new object representing the last usable IP address within
the subnet (ie, one less than the broadcast address).

=cut

sub last ($) {
  return $_[0]->broadcast - 1;
}

=item C<-E<gt>nth($index)>

Returns a new object representing the I<n>-th usable IP address within
the subnet (ie, the I<n>-th host address).  If no address is available
(for example, when the network is too small for C<$index> hosts),
C<undef> is returned.

Version 4.00 of NetAddr::IP and version 1.00 of NetAddr::IP::Lite implements
C<-E<gt>nth($index)> and C<-E<gt>num()> exactly as the documentation states.
Previous versions behaved slightly differently and not in a consistent
manner.

To use the old behavior for C<-E<gt>nth($index)> and C<-E<gt>num()>:

  use NetAddr::IP::Lite qw(:old_nth);

  old behavior:
  NetAddr::IP->new('10/32')->nth(0) == undef
  NetAddr::IP->new('10/32')->nth(1) == undef
  NetAddr::IP->new('10/31')->nth(0) == undef
  NetAddr::IP->new('10/31')->nth(1) == 10.0.0.1/31
  NetAddr::IP->new('10/30')->nth(0) == undef
  NetAddr::IP->new('10/30')->nth(1) == 10.0.0.1/30
  NetAddr::IP->new('10/30')->nth(2) == 10.0.0.2/30
  NetAddr::IP->new('10/30')->nth(3) == 10.0.0.3/30

Note that in each case, the broadcast address is represented in the
output set and that the 'zero'th index is alway undef.

  new behavior:
  NetAddr::IP->new('10/32')->nth(0)  == 10.0.0.0/32
  NetAddr::IP->new('10.1/32'->nth(0) == 10.0.0.1/32
  NetAddr::IP->new('10/31')->nth(0)  == undef
  NetAddr::IP->new('10/31')->nth(1)  == undef
  NetAddr::IP->new('10/30')->nth(0) == 10.0.0.1/30
  NetAddr::IP->new('10/30')->nth(1) == 10.0.0.2/30
  NetAddr::IP->new('10/30')->nth(2) == undef

Note that a /32 net always has 1 usable address while a /31 has none since
it has a network and broadcast address, but no host addresses. The first
index (0) returns the address immediately following the network address.

=cut

sub nth ($$) {
  my $self    = shift;
  my $count   = shift;

  ++$count unless ($Old_nth);
  return undef if ($count < 1 or $count > $self->num ());
  return $self->network + $count;
}

=item C<-E<gt>num()>

Version 4.00 of NetAddr::IP and version 1.00 of NetAddr::IP::Lite
Returns the number of usable addresses IP addresses within the
subnet, not counting the broadcast or network address. Previous versions
returned th number of IP addresses not counting the broadcast address.

To use the old behavior for C<-E<gt>nth($index)> and C<-E<gt>num()>:

  use NetAddr::IP::Lite qw(:old_nth);

=cut

sub num ($) {
  my @net = unpack('L3N',$_[0]->{mask} ^ Ones);
  if ($Old_nth) {
# number of ip's less broadcast
    return 0xfffffffe if $net[0] || $net[1] || $net[2]; # 2**32 -1
    return $net[3] if $net[3];
  } else {	# returns 1 for /32 /128, 0 for /31 /127 else n-2 up to 2**32
# number of usable IP's === number of ip's less broadcast & network addys
    return 0xfffffffd if $net[0] || $net[1] || $net[2]; # 2**32 -2
    return 1 unless $net[3];
    $net[3]--;
  }
  return $net[3];
}

=pod

=back

=cut

sub import {
  if (grep { $_ eq ':aton' } @_) {
    $Accept_Binary_IP = 1;
    @_ = grep { $_ ne ':aton' } @_;
  }
  if (grep { $_ eq ':old_nth' } @_) {
    $Old_nth = 1;
    @_ = grep { $_ ne ':old_nth' } @_;
  }
  NetAddr::IP::Lite->export_to_level(1, @_);
}

=head1 EXPORT_OK

	Zeros
	Ones
	V4mask
	V4net
	:aton		DEPRECATED
	:old_nth

=head1 AUTHOR

Luis E. Muñoz E<lt>luismunoz@cpan.orgE<gt>,
Michael Robinton E<lt>michael@bizsystems.comE<gt>

=head1 WARRANTY

This software comes with the  same warranty as perl itself (ie, none),
so by using it you accept any and all the liability.

=head1 LICENSE

 This software is (c) Luis E. Muñoz, 1999 - 2005
 and (c) Michael Robinton, 2006 - 2008.

It can be used under the terms of the perl artistic license provided that
proper credit for the work of the author is preserved in the form of this
copyright notice and license for this module.

=head1 SEE ALSO

perl(1), NetAddr::IP(3), NetAddr::IP::Util(3)

=cut

1;
