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

use warnings;
use strict;
use Getopt::Long;
use Encode qw(encode decode);

my $state = "";
my %contributors = ();
my $is_contributing = 0;

my $header = "

= Original Author =

Gerald Combs            <gerald[AT]wireshark.org>


";

my $trailer = "

= Acknowledgements =

Dan Lasley <dlasley[AT]promus.com> gave permission for his dumpit() hex-dump routine to be used.

Mattia Cazzola <mattiac[AT]alinet.it> provided a patch to the hex dump display routine.

We use the exception module from Kazlib, a C library written by Kaz Kylheku <kaz[AT]kylheku.com>. Thanks go to him for his well-written library. The Kazlib home page can be found at http://www.kylheku.com/~kaz/kazlib.html

We use Lua BitOp, written by Mike Pall, for bitwise operations on numbers in Lua. The Lua BitOp home page can be found at https://bitop.luajit.org

snax <snax[AT]shmoo.com> gave permission to use his(?) weak key detection code from Airsnort.

IANA gave permission for their port-numbers file to be used.

We use the natural order string comparison algorithm, written by Martin Pool <mbp[AT]sourcefrog.net>.

Emanuel Eichhammer <support[AT]qcustomplot.com> granted permission to use QCustomPlot.

Insecure.Com LLC (\"The Nmap Project\") has granted the Wireshark Foundation permission to distribute Npcap with our Windows installers.
";

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
			print encode('UTF-8', "$full_name\n");
		}
	} elsif ($full_name =~ /^([\w\.\-\'\x80-\xff]+(\s*[\w+\.\-\'\x80-\xff])*)\s+\(/) {
		$contributors{"<no_email>"} = $1;
		print encode('UTF-8', "$full_name\n");
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
				print encode('UTF-8', "$line\n");
			}
		}
	}
}

# ---------------------------------------------------------------------
#
# MAIN
#

print $header;

open( my $author_fh, '<', $ARGV[0] ) or die "Can't open $ARGV[0]: $!";
while ( my $line = decode('UTF-8', <$author_fh>) ) {
	chomp $line;

	last if ($line =~ "Acknowledgements");

	if ($line =~ "Contributors") {
		$is_contributing = 1;
	} elsif ($is_contributing == 0) {
		next;
	}

	if ($line =~ /([^\{]*)\{/) {
		parse_author_name($line);
		$state = "s_in_bracket";
	} elsif ($state eq "s_in_bracket") {
		if ($line =~ /([^\}]*)\}/) {
			print encode('UTF-8', "$line\n");
			$state = "";
		} else {
			print encode('UTF-8', "$line\n");
		}
	} elsif ($line =~ /</) {
		parse_author_name($line);
	} elsif ($line =~ "(e-mail address removed at contributor's request)") {
		parse_author_name($line);
	} else {
		print encode('UTF-8', "$line\n");
	}
}
close $author_fh;

print $git_log_text;

open( my $git_author_fh, 'git --no-pager shortlog -se HEAD|')
        or die "Can't execute git shortlog: $!";

while ( my $git_line = decode('UTF-8', <$git_author_fh>) ) {
	chomp $git_line;

	parse_git_name($git_line);
}
close $git_author_fh;

print $trailer;

__END__
