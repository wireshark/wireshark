#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 7;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::CUtil qw(get_pointer_to get_value_of);

is("&foo", get_pointer_to("foo"));
is("&(&foo)", get_pointer_to(get_pointer_to("foo")));
is("*foo", get_pointer_to("**foo"));
is("foo", get_pointer_to("*foo"));

is("foo", get_value_of("&foo"));
is("*foo", get_value_of("foo"));
is("**foo", get_value_of("*foo"));
