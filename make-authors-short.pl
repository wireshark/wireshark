#!/usr/bin/perl -w

# $Id$

use strict;

# Unset environment variables so perl doesn't
# interpret bytes as UTF-8 characters

delete $ENV{LANG};
delete $ENV{LANGUAGE};
delete $ENV{LC_ALL};
delete $ENV{LC_CTYPE};

# Call make-authors-short2.pl in same directory, using same interpreter

(my $prog2 = $0) =~ s/\.pl$/2.pl/;
system($^X, "$prog2", @ARGV);
