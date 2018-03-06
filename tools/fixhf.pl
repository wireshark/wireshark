#!/usr/bin/env perl

# Copyright 2010, Jeff Morriss <jeff.morriss.ws[AT]gmail.com>
#
# A simple tool to remove bogus blurbs from hf entries.
# This has already been run so it may not be necessary any more, but
# may as well check it in in case it can serve as a base for other, future,
# global hf changes.
#
# Usage:
# fixhf.pl file1 [file2 file3 ...]
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

use strict;

# Read through the files
while ($_ = $ARGV[0])
{
        shift;
        my $filename = $_;
        my $fileContents = '';
        my @foundAPIs = ();

        die "No such file: \"$filename\"" if (! -e $filename);

        # delete leading './'
        $filename =~ s{ ^ \. / } {}xo;

        # Read in the file (ouch, but it's easier that way)
        open(FC, $filename) || die("Couldn't open $filename");
        while (<FC>) { $fileContents .= $_; }
        close(FC);

	if ($fileContents =~ s{   
				  (\{
				  \s*
				  &\s*[A-Z0-9_\[\]-]+		# &hf
				  \s*,\s*
				  \{\s*
				  ("[A-Z0-9 '\./\(\)_:-]+")	# name
				  \s*,\s*
				  "[A-Z0-9_\.-]+"		# abbrev
				  \s*,\s*
				  FT_[A-Z0-9_]+			# field type
				  \s*,\s*
				  [A-Z0-9x|_]+			# display
				  \s*,\s*
				  [A-Z0-9&_\(\)' -]+		# convert
				  \s*,\s*
				  [A-Z0-9x_]+			# bitmask
				  \s*,\s*)
				  \2				# blurb
				} [$1NULL]xgios)
				 # \s*HFILL)
	{
		print STDERR "Warning: field with name==blurb found in " .$filename. " FIXING IT!\n";

		# Trim trailing white space while we're here
		$fileContents =~ s{[ \t]+$} []gom;

		open(FC, ">".$filename) || die("Couldn't open $filename");
		print FC $fileContents;
		close(FC);
	}

}
