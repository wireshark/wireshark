#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 6;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util qw(test_warnings test_errors);
use Parse::Pidl qw(warning error);

test_warnings("", sub {});

test_warnings("x:1: msg\n", sub { warning({FILE => "x", LINE => 1}, "msg"); });
test_warnings("", sub {});

test_errors("", sub {});

test_errors("x:1: msg\n", sub { error({FILE => "x", LINE => 1}, "msg"); });
test_errors("", sub {});

