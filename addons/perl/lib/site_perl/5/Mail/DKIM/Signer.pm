#!/usr/bin/perl

# Copyright 2005-2007 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::Algorithm::rsa_sha1;
use Mail::DKIM::Signature;
use Mail::Address;

=head1 NAME

Mail::DKIM::Signer - generates a DKIM signature for a message

=head1 SYNOPSIS

  use Mail::DKIM::Signer;

  # create a signer object
  my $dkim = Mail::DKIM::Signer->new(
                  Algorithm => "rsa-sha1",
                  Method => "relaxed",
                  Domain => "example.org",
                  Selector => "selector1",
                  KeyFile => "private.key",
             );

  # read an email from a file handle
  $dkim->load(*STDIN);

  # or read an email and pass it into the signer, one line at a time
  while (<STDIN>)
  {
      # remove local line terminators
      chomp;
      s/\015$//;

      # use SMTP line terminators
      $dkim->PRINT("$_\015\012");
  }
  $dkim->CLOSE;

  # what is the signature result?
  my $signature = $dkim->signature;

=head1 CONSTRUCTOR

=head2 new()

Construct an object-oriented signer.

  # create a signer using the default policy
  my $dkim = Mail::DKIM::Signer->new(
                  Algorithm => "rsa-sha1",
                  Method => "relaxed",
                  Domain => "example.org",
                  Selector => "selector1",
                  KeyFile => "private.key",
             );

  # create a signer using a custom policy
  my $dkim = Mail::DKIM::Signer->new(
                  Policy => $policyfn,
             );

The "default policy" is to create a DKIM signature using the specified
parameters, but only if the message's sender matches the domain.
The following parameters can be passed to this new() method to
influence the resulting signature:
Algorithm, Method, Domain, Selector, KeyFile, Identity, Timestamp.

If you want different behavior, you can provide a "signer policy"
instead. A signer policy is a subroutine or class that determines
signature parameters after the message's headers have been parsed.
See the section L</"SIGNER POLICIES"> below for more information.

See L<Mail::DKIM::SignerPolicy> for more information about policy objects.

In addition to the parameters demonstrated above, the following
are recognized:

=over

=item Key

rather than using C<KeyFile>, use C<Key> to use an already-loaded
L<Mail::DKIM::PrivateKey> object.

=back

=cut

package Mail::DKIM::Signer;
use base "Mail::DKIM::Common";
use Carp;
our $VERSION = 0.37;

# PROPERTIES
#
# public:
#
# $dkim->{Algorithm}
#   identifies what algorithm to use when signing the message
#   default is "rsa-sha1"
#
# $dkim->{Domain}
#   identifies what domain the message is signed for
#
# $dkim->{KeyFile}
#   name of the file containing the private key used to sign
#
# $dkim->{Method}
#   identifies what canonicalization method to use when signing
#   the message. default is "relaxed"
#
# $dkim->{Policy}
#   a signing policy (of type Mail::DKIM::SigningPolicy)
#
# $dkim->{Selector}
#   identifies name of the selector identifying the key
#
# $dkim->{Key}
#   the loaded private key
#
# private:
#
# $dkim->{algorithms} = []
#   an array of algorithm objects... an algorithm object is created for
#   each signature being added to the message
#
# $dkim->{result}
#   result of the signing policy: "signed" or "skipped"
#
# $dkim->{signature}
#   the created signature (of type Mail::DKIM::Signature)


sub init
{
	my $self = shift;
	$self->SUPER::init;

	if (defined $self->{KeyFile})
	{
		$self->{Key} ||= Mail::DKIM::PrivateKey->load(
				File => $self->{KeyFile});
	}
	
	unless ($self->{"Algorithm"})
	{
		# use default algorithm
		$self->{"Algorithm"} = "rsa-sha1";
	}
	unless ($self->{"Method"})
	{
		# use default canonicalization method
		$self->{"Method"} = "relaxed";
	}
	unless ($self->{"Domain"})
	{
		# use default domain
		$self->{"Domain"} = "example.org";
	}
	unless ($self->{"Selector"})
	{
		# use default selector
		$self->{"Selector"} = "unknown";
	}
}

sub finish_header
{
	my $self = shift;

	$self->{algorithms} = [];

	my $policy = $self->{Policy};
	if (UNIVERSAL::isa($policy, "CODE"))
	{
		# policy is a subroutine ref
		my $default_sig = $policy->($self);
		unless (@{$self->{algorithms}} || $default_sig)
		{
			$self->{"result"} = "skipped";
			return;
		}
	}
	elsif ($policy && $policy->can("apply"))
	{
		# policy is a Perl object or class
		my $default_sig = $policy->apply($self);
		unless (@{$self->{algorithms}} || $default_sig)
		{
			$self->{"result"} = "skipped";
			return;
		}
	}

	unless (@{$self->{algorithms}})
	{
		# no algorithms were created yet, so construct a signature
		# using the current signature properties

		# check properties
		unless ($self->{"Algorithm"})
		{
			die "invalid algorithm property";
		}
		unless ($self->{"Method"})
		{
			die "invalid method property";
		}
		unless ($self->{"Domain"})
		{
			die "invalid header property";
		}
		unless ($self->{"Selector"})
		{
			die "invalid selector property";
		}

		$self->add_signature(
			Mail::DKIM::Signature->new(
				Algorithm => $self->{"Algorithm"},
				Method => $self->{"Method"},
				Headers => $self->headers,
				Domain => $self->{"Domain"},
				Selector => $self->{"Selector"},
				Key => $self->{"Key"},
				KeyFile => $self->{"KeyFile"},
				($self->{"Identity"} ?
					(Identity => $self->{"Identity"}) : ()),
				($self->{"Timestamp"} ?
					(Timestamp => $self->{"Timestamp"}) : ()),
			));
	}

	foreach my $algorithm (@{$self->{algorithms}})
	{
		# output header as received so far into canonicalization
		foreach my $header (@{$self->{headers}})
		{
			$algorithm->add_header($header);
		}
		$algorithm->finish_header;
	}
}

sub finish_body
{
	my $self = shift;

	foreach my $algorithm (@{$self->{algorithms}})
	{
		# finished canonicalizing
		$algorithm->finish_body;

		# load the private key file if necessary
		my $signature = $algorithm->signature;
		my $key = $signature->{Key}
			|| $signature->{KeyFile}
			|| $self->{Key}
			|| $self->{KeyFile};
		if (not ref $key)
		{
			$key = Mail::DKIM::PrivateKey->load(
					File => $key);
		}
		$key
			or die "no key available to sign with\n";

		# compute signature value
		my $signb64 = $algorithm->sign($key);
		$signature->data($signb64);

		# insert linebreaks in signature data, if desired
		$signature->prettify_safe();

		$self->{signature} = $signature;
		$self->{result} = "signed";
	}
}

=head1 METHODS

=head2 PRINT()

Feed part of the message to the signer.

  $dkim->PRINT("a line of the message\015\012");

Feeds content of the message being signed into the signer.
The API is designed this way so that the entire message does NOT need
to be read into memory at once.

=head2 CLOSE()

Call this when finished feeding in the message.

  $dkim->CLOSE;

This method finishes the canonicalization process, computes a hash,
and generates a signature.

=head2 add_signature()

Used by signer policy to create a new signature.

  $dkim->add_signature(new Mail::DKIM::Signature(...));

Signer policies can use this method to specify complete parameters for
the signature to add, including what type of signature. For more information,
see L<Mail::DKIM::SignerPolicy>.

=cut

sub add_signature
{
	my $self = shift;
	my $signature = shift;

	# create a canonicalization filter and algorithm
	my $algorithm_class = $signature->get_algorithm_class(
			$signature->algorithm);
	my $algorithm = $algorithm_class->new(
			Signature => $signature,
			Debug_Canonicalization => $self->{Debug_Canonicalization},
		);
	push @{$self->{algorithms}}, $algorithm;
	return;
}

=head2 algorithm()

Get or set the selected algorithm.

  $alg = $dkim->algorithm;

  $dkim->algorithm("rsa-sha1");

=cut

sub algorithm
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Algorithm} = shift;
	}
	return $self->{Algorithm};
}

=head2 domain()

Get or set the selected domain.

  $alg = $dkim->domain;

  $dkim->domain("example.org");

=cut

sub domain
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Domain} = shift;
	}
	return $self->{Domain};
}

=head2 load()

Load the entire message from a file handle.

  $dkim->load($file_handle);

Reads a complete message from the designated file handle,
feeding it into the signer.  The message must use <CRLF> line
terminators (same as the SMTP protocol).

=cut

=head2 headers()

Determine which headers to put in signature.

  my $headers = $dkim->headers;

This is a string containing the names of the header fields that
will be signed, separated by colons.

=cut

# these are headers that "should" be included in the signature,
# according to the DKIM spec.
my @DEFAULT_HEADERS = qw(From Sender Reply-To Subject Date
	Message-ID To Cc MIME-Version
	Content-Type Content-Transfer-Encoding Content-ID Content-Description
	Resent-Date Resent-From Resent-Sender Resent-To Resent-cc
	Resent-Message-ID
	In-Reply-To References
	List-Id List-Help List-Unsubscribe List-Subscribe
	List-Post List-Owner List-Archive);

sub headers
{
	my $self = shift;
	croak "unexpected argument" if @_;

	# these are the header fields we found in the message we're signing
	my @found_headers = @{$self->{header_field_names}};

	# these are the headers we actually want to sign
	my @wanted_headers = @DEFAULT_HEADERS;
	if ($self->{Headers})
	{
		push @wanted_headers, split /:/, $self->{Headers};
	}

	my @headers =
		grep { my $a = $_;
			scalar grep { lc($a) eq lc($_) } @wanted_headers }
		@found_headers;
	return join(":", @headers);
}

# return nonzero if this is header we should sign
sub want_header
{
	my $self = shift;
	my ($header_name) = @_;

	#TODO- provide a way for user to specify which headers to sign
	return scalar grep { lc($_) eq lc($header_name) } @DEFAULT_HEADERS;
}

=head2 key()

Get or set the private key object.

  my $key = $dkim->key;

  $dkim->key(Mail::DKIM::PrivateKey->load(File => "private.key"));

If you use this method to specify a private key,
do not use L</"key_file()">.

=cut

sub key
{
	my $self = shift;
	if (@_)
	{
		$self->{Key} = shift;
		$self->{KeyFile} = undef;
	}
	return $self->{Key};
}

=head2 key_file()

Get or set the filename containing the private key.

  my $filename = $dkim->key_file;

  $dkim->key_file("private.key");

If you use this method to specify a private key file,
do not use L</"key()">.

=cut

sub key_file
{
	my $self = shift;
	if (@_)
	{
		$self->{Key} = undef;
		$self->{KeyFile} = shift;
	}
	return $self->{KeyFile};
}

=head2 method()

Get or set the selected canonicalization method.

  $alg = $dkim->method;

  $dkim->method("relaxed");

=cut

sub method
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Method} = shift;
	}
	return $self->{Method};
}

=head2 message_originator()

Access the "From" header.

  my $address = $dkim->message_originator;

Returns the "originator address" found in the message, as a
L<Mail::Address> object.
This is typically the (first) name and email address found in the
From: header. If there is no From: header,
then an empty L<Mail::Address> object is returned.

To get just the email address part, do:

  my $email = $dkim->message_originator->address;

See also L</"message_sender()">.

=head2 message_sender()

Access the "From" or "Sender" header.

  my $address = $dkim->message_sender;

Returns the "sender" found in the message, as a L<Mail::Address> object.
This is typically the (first) name and email address found in the
Sender: header. If there is no Sender: header, it is the first name and
email address in the From: header. If neither header is present,
then an empty L<Mail::Address> object is returned.

To get just the email address part, do:

  my $email = $dkim->message_sender->address;

The "sender" is the mailbox of the agent responsible for the actual
transmission of the message. For example, if a secretary were to send a
message for another person, the "sender" would be the secretary and
the "originator" would be the actual author.


=cut

=head2 selector()

Get or set the current key selector.

  $alg = $dkim->selector;

  $dkim->selector("alpha");

=cut

sub selector
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Selector} = shift;
	}
	return $self->{Selector};
}

=head2 signature()

Access the generated signature object.

  my $signature = $dkim->signature;

Returns the generated signature. The signature is an object of type
Mail::DKIM::Signature. If multiple signatures were generated, this method
returns the last one.

The signature should be B<prepended> to the message to make the
resulting message. At the very least, it should precede any headers
that were signed.

=head2 signatures()

Access list of generated signature objects.

  my @signatures = $dkim->signatures;

Returns all generated signatures, as a list.

=cut

sub signatures
{
	my $self = shift;
	croak "no arguments allowed" if @_;
	return map { $_->signature } @{$self->{algorithms}};
}

=head1 SIGNER POLICIES

The new() constructor takes an optional Policy argument. This
can be a Perl object or class with an apply() method, or just a simple
subroutine reference. The method/subroutine will be called with the
signer object as an argument. The policy is responsible for checking the
message and specifying signature parameters. The policy must return a
nonzero value to create the signature, otherwise no signature will be
created. E.g.,

  my $policyfn = sub {
      my $dkim = shift;

      # specify signature parameters
      $dkim->algorithm("rsa-sha1");
      $dkim->method("relaxed");
      $dkim->domain("example.org");
      $dkim->selector("mx1");

      # return true value to create the signature
      return 1;
  };

Or the policy object can actually create the signature, using the
add_signature method within the policy object.
If you add a signature, you do not need to return a nonzero value.
This mechanism can be utilized to create multiple signatures,
or to create the older DomainKey-style signatures.

  my $policyfn = sub {
      my $dkim = shift;
      $dkim->add_signature(
              new Mail::DKIM::Signature(
                      Algorithm => "rsa-sha1",
                      Method => "relaxed",
                      Headers => $dkim->headers,
                      Domain => "example.org",
                      Selector => "mx1",
              ));
      $dkim->add_signature(
              new Mail::DKIM::DkSignature(
                      Algorithm => "rsa-sha1",
                      Method => "nofws",
                      Headers => $dkim->headers,
                      Domain => "example.org",
                      Selector => "mx1",
              ));
      return;
  };

If no policy is specified, the default policy is used. The default policy
signs every message using the domain, algorithm, method, and selector
specified in the new() constructor.

=head1 SEE ALSO

L<Mail::DKIM::SignerPolicy>

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2007 by Messiah College

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
