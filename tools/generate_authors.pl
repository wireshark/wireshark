#!/usr/bin/perl

#
# Generate the AUTHORS file combining existing AUTHORS file with
# git commit log.
#
# Usage: generate_authors.pl AUTHORS.src

#
# Copyright 2016 Michael Mann (see AUTHORS file)
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

use v5.10;

use warnings;
use strict;
use open ':std', ':encoding(UTF-8)';

my $state = "";
my %contributors = ();

my $acknowledgements_heading = "= Acknowledgements =";

my $git_log_text = "
= From git log =

";

# Perl trim function to remove whitespace from the start and end of the string
sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

sub parse_author_name {
	my $full_name = $_[0];
	my $email_key;

	if ($full_name =~ /^([\w\.\-\'\x80-\xff]+(\s*[\w+\.\-\'\x80-\xff])*)\s+<([^>]*)>/) {
		#Make an exception for Gerald because he's part of the header
		if ($3 ne "gerald[AT]wireshark.org") {
			$email_key = lc($3);
			$contributors{$email_key} = $1;
			say $full_name;
		}
	} elsif ($full_name =~ /^([\w\.\-\'\x80-\xff]+(\s*[\w+\.\-\'\x80-\xff])*)\s+\(/) {
		$contributors{"<no_email>"} = $1;
		say $full_name;
	}
}

sub parse_git_name {
	my $full_name = $_[0];
	my $name;
	my $email;
	my $email_key;
	my $len;
	my $ntab = 3;
	my $line;

	#  4321	Navin R. Johnson <nrjohnson@example.com>
	if ($full_name =~ /^\s*\d+\s+([^<]*)\s*<([^>]*)>/) {
		$name = trim($1);
		#Convert real email address to "spam proof" one
		$email = trim($2);
		$email =~ s/@/[AT]/g;
		$email_key = lc($email);

		if (!exists($contributors{ $email_key })) {
			#Make an exception for Gerald because he's part of the header
			if ($email ne "gerald[AT]wireshark.org") {
				$len = length $name;
				if ($len >= 8 * $ntab) {
					$line = "$name <$email>";
				} else {
					$ntab -= $len / 8;
					$ntab +=1 if ($len % 8);
					$line = $name . "\t" x $ntab . "<$email>";
				}
				$contributors{$email_key} = $1;
				say $line;
			}
		}
	}
}

# ---------------------------------------------------------------------
#
# MAIN
#

open( my $author_fh, '<', $ARGV[0] ) or die "Can't open $ARGV[0]: $!";

while ( my $line = <$author_fh> ) {
	chomp $line;

	say $line;

	last if $line eq "= Contributors =";
}

while ( my $line = <$author_fh> ) {
	chomp $line;

	last if ($line eq $acknowledgements_heading);

	if ($line =~ /([^\{]*)\{/) {
		parse_author_name($line);
		$state = "s_in_bracket";
	} elsif ($state eq "s_in_bracket") {
		if ($line =~ /([^\}]*)\}/) {
			say $line;
			$state = "";
		} else {
			say $line;
		}
	} elsif ($line =~ /</) {
		parse_author_name($line);
	} elsif ($line =~ "(e-mail address removed at contributor's request)") {
		parse_author_name($line);
	} else {
		say $line;
	}
}

print $git_log_text;

open( my $git_author_fh, 'git --no-pager shortlog -se HEAD|')
        or die "Can't execute git shortlog: $!";

while ( my $git_line = <$git_author_fh> ) {
	chomp $git_line;

	parse_git_name($git_line);
}
close $git_author_fh;

print "\n\n";

say $acknowledgements_heading;

while ( my $line = <$author_fh> ) {
	chomp $line;
	say $line;
}

close $author_fh;

__END__
