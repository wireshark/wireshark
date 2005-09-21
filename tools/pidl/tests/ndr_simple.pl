#!/usr/bin/perl
# Some simple tests for pidl
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;

use Parse::Pidl::Test;

my %settings = Parse::Pidl::Test::GetSettings(@ARGV);
$settings{'IDL-Arguments'} = ['--quiet', '--parse', '--parser=ndr_test.c', '--header=ndr_test.h'];
$settings{'IncludeFiles'} = ['ndr_test.h'];
$settings{'ExtraFiles'} = ['ndr_test.c'];

Parse::Pidl::Test::test_idl(
	# Name
	'UInt8',
	
	# Settings
	\%settings,
	
	# IDL 
	'void Test();',
	
	# C Test
	'
	uint8_t data[] = { 0x02 };
	uint8_t result;
	DATA_BLOB b;
	struct ndr_pull *ndr;

	b.data = data;
	b.length = 1;
	ndr = ndr_pull_init_blob(&b, mem_ctx);

	if (NT_STATUS_IS_ERR(ndr_pull_uint8(ndr, NDR_SCALARS, &result)))
		return 1;

	if (result != 0x02) 
		return 2;
');
