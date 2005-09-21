#!/usr/bin/perl
# Array testing
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
	'Fixed-Array',
	
	# Settings
	\%settings,
	
	# IDL 
	'[public] void Test([in] uint8 x[10]);',
	
	# C Test
	'
	uint8_t data[] = {1,2,3,4,5,6,7,8,9,10};
	int i;
	DATA_BLOB b;
	struct ndr_pull *ndr;
	struct Test r;

	b.data = data;
	b.length = 10;
	ndr = ndr_pull_init_blob(&b, mem_ctx);

	if (NT_STATUS_IS_ERR(ndr_pull_Test(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 10)
		return 2;
	
	for (i = 0; i < 10; i++) {
		if (r.in.x[i] != i+1) return 3;
	}
');
