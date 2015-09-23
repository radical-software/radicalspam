package Net::DNS::RR::DLV;
#
# $Id: DLV.pm 580 2006-04-20 15:56:57Z olaf $
#
use strict;
BEGIN { 
    eval { require bytes; }
} 
use vars qw(@ISA $VERSION);
use Net::DNS::RR::DS;


@ISA     = qw(Net::DNS::RR::DS);
$VERSION = (qw$LastChangedRevision: 580 $)[1];



=head1 NAME

Net::DNS::RR::DLV - DNS DLV resource record

=head1 SYNOPSIS

C<use Net::DNS::RR>;

=head1 DESCRIPTION

This is a clone of the DS record. This class therfore completely inherits
all properties of the Net::DNS::RR::DS class.

Please see the L<Net::DNS::RR::DS> perldocumentation for details

=head1 COPYRIGHT

Copyright (c) 2005 Olaf Kolkman (NLnet Labs)

All rights reserved.  This program is free software; you may redistribute
it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
RFC4431.


=cut

