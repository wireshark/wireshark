#!/usr/bin/perl
# (C) 2007 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 10;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util;
use Parse::Pidl::Util qw(MyDumper);
use Parse::Pidl::NDR qw(GetElementLevelTable ParseElement);

# Case 1

my $e = {
	'FILE' => 'foo.idl',
	'NAME' => 'v',
	'PROPERTIES' => {},
	'POINTERS' => 0,
	'TYPE' => 'uint8',
	'PARENT' => { TYPE => 'STRUCT' },
	'LINE' => 42 };

is_deeply(GetElementLevelTable($e), [
	{
		'IS_DEFERRED' => 0,
		'LEVEL_INDEX' => 0,
		'DATA_TYPE' => 'uint8',
		'CONVERT_FROM' => undef,
		'CONTAINS_DEFERRED' => 0,
		'TYPE' => 'DATA',
		'IS_SURROUNDING' => 0,
		'CONVERT_TO' => undef
	}
]);

my $ne = ParseElement($e);
is($ne->{ORIGINAL}, $e);
is($ne->{NAME}, "v");
is($ne->{ALIGN}, 1);
is($ne->{TYPE}, "uint8");
is_deeply($ne->{LEVELS},  [
	{
		'IS_DEFERRED' => 0,
		'LEVEL_INDEX' => 0,
		'DATA_TYPE' => 'uint8',
		'CONVERT_FROM' => undef,
		'CONTAINS_DEFERRED' => 0,
		'TYPE' => 'DATA',
		'IS_SURROUNDING' => 0,
		'CONVERT_TO' => undef
	}
]);

# Case 2 : pointers
#
$e = {
	'FILE' => 'foo.idl',
	'NAME' => 'v',
	'PROPERTIES' => {"unique" => 1},
	'POINTERS' => 1,
	'PARENT' => { TYPE => 'STRUCT' },
	'TYPE' => 'uint8',
	'LINE' => 42 };

is_deeply(GetElementLevelTable($e), [
	{
		LEVEL_INDEX => 0,
		IS_DEFERRED => 0,
		TYPE => 'POINTER',
		POINTER_TYPE => "unique",
		POINTER_INDEX => 0,
		LEVEL => 'EMBEDDED'
	},
	{
		'IS_DEFERRED' => 1,
		'LEVEL_INDEX' => 1,
		'DATA_TYPE' => 'uint8',
		'CONVERT_FROM' => undef,
		'CONTAINS_DEFERRED' => 0,
		'TYPE' => 'DATA',
		'IS_SURROUNDING' => 0,
		'CONVERT_TO' => undef
	}
]);

# Case 3 : double pointers
#
$e = {
	'FILE' => 'foo.idl',
	'NAME' => 'v',
	'PROPERTIES' => {"unique" => 1},
	'POINTERS' => 2,
	'TYPE' => 'uint8',
	'PARENT' => { TYPE => 'STRUCT' },
	'LINE' => 42 };

is_deeply(GetElementLevelTable($e), [
	{
		LEVEL_INDEX => 0,
		IS_DEFERRED => 0,
		TYPE => 'POINTER',
		POINTER_TYPE => "unique",
		POINTER_INDEX => 0,
		LEVEL => 'EMBEDDED'
	},
	{
		LEVEL_INDEX => 1,
		IS_DEFERRED => 1,
		TYPE => 'POINTER',
		POINTER_TYPE => "unique",
		POINTER_INDEX => 1,
		LEVEL => 'EMBEDDED'
	},
	{
		'IS_DEFERRED' => 1,
		'LEVEL_INDEX' => 2,
		'DATA_TYPE' => 'uint8',
		'CONVERT_FROM' => undef,
		'CONTAINS_DEFERRED' => 0,
		'TYPE' => 'DATA',
		'IS_SURROUNDING' => 0,
		'CONVERT_TO' => undef
	}
]);

# Case 3 : ref pointers
#
$e = {
	'FILE' => 'foo.idl',
	'NAME' => 'v',
	'PROPERTIES' => {"ref" => 1},
	'POINTERS' => 1,
	'TYPE' => 'uint8',
	'PARENT' => { TYPE => 'STRUCT' },
	'LINE' => 42 };

is_deeply(GetElementLevelTable($e), [
	{
		LEVEL_INDEX => 0,
		IS_DEFERRED => 0,
		TYPE => 'POINTER',
		POINTER_TYPE => "ref",
		POINTER_INDEX => 0,
		LEVEL => 'EMBEDDED'
	},
	{
		'IS_DEFERRED' => 1,
		'LEVEL_INDEX' => 1,
		'DATA_TYPE' => 'uint8',
		'CONVERT_FROM' => undef,
		'CONTAINS_DEFERRED' => 0,
		'TYPE' => 'DATA',
		'IS_SURROUNDING' => 0,
		'CONVERT_TO' => undef
	}
]);


# Case 4 : top-level ref pointers
#
$e = {
	'FILE' => 'foo.idl',
	'NAME' => 'v',
	'PROPERTIES' => {"ref" => 1},
	'POINTERS' => 1,
	'TYPE' => 'uint8',
	'PARENT' => { TYPE => 'FUNCTION' },
	'LINE' => 42 };

is_deeply(GetElementLevelTable($e), [
	{
		LEVEL_INDEX => 0,
		IS_DEFERRED => 0,
		TYPE => 'POINTER',
		POINTER_TYPE => "ref",
		POINTER_INDEX => 0,
		LEVEL => 'TOP'
	},
	{
		'IS_DEFERRED' => 0,
		'LEVEL_INDEX' => 1,
		'DATA_TYPE' => 'uint8',
		'CONVERT_FROM' => undef,
		'CONTAINS_DEFERRED' => 0,
		'TYPE' => 'DATA',
		'IS_SURROUNDING' => 0,
		'CONVERT_TO' => undef
	}
]);
