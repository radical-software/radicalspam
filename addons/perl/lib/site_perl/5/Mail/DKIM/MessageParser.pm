#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::MessageParser;
use Carp;

sub new_object
{
	my $class = shift;
	return $class->TIEHANDLE(@_);
}

sub new_handle
{
	my $class = shift;
	local *TMP;
	tie *TMP, $class, @_;
	return *TMP;
}

sub TIEHANDLE
{
	my $class = shift;
	my %args = @_;
	my $self = bless \%args, $class;
	$self->init;
	return $self;
}

sub init
{
	my $self = shift;

	$self->{in_header} = 1;
	$self->{buf} = "";
}

sub PRINT
{
	my $self = shift;
	my $buf = $self->{buf};
	$buf .= @_ == 1 ? $_[0] : join("", @_)  if @_;

	if ($self->{in_header}) {
		while (length $buf)
		{
			if (substr($buf,0,2) eq "\015\012")
			{
				$buf = substr($buf, 2);
				$self->finish_header();
				$self->{in_header} = 0;
				last;
			}
			if ($buf !~ /^(.+?\015\012)[^\ \t]/s)
			{
				last;
			}
			my $header = $1;
			$self->add_header($header);
			$buf = substr($buf, length($header));
		}
	}

	if (!$self->{in_header}) {
		my $j = rindex($buf,"\015\012");
		if ($j >= 0)
		{
			$self->add_body(substr($buf, 0, $j+2));
			substr($buf, 0, $j+2) = '';
		}
	}
	$self->{buf} = $buf;
	return 1;
}

sub CLOSE
{
	my $self = shift;
	my $buf = $self->{buf};

	if ($self->{in_header})
	{
		if (length $buf)
		{
			# A line of header text ending CRLF would not have been
			# processed yet since before we couldn't tell if it was
			# the complete header. Now that we're in CLOSE, we can
			# finish the header...
			$buf =~ s/\015\012$//s;
			$self->add_header("$buf\015\012");
		}
		$self->finish_header;
		$self->{in_header} = 0;
	}
	else
	{
		if (length $buf)
		{
			$self->add_body($buf);
		}
	}
	$self->{buf} = "";
	$self->finish_body;
	return 1;
}

sub add_header
{
	die "add_header not implemented";
}

sub finish_header
{
	die "finish_header not implemented";
}

sub add_body
{
	die "add_body not implemented";
}

sub finish_body
{
	# do nothing by default
}

sub reset
{
	carp "reset not implemented";
}

1;
