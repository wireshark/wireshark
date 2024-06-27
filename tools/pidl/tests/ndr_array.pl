#!/usr/bin/perl
# Array testing
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 8;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util qw(test_samba4_ndr);

test_samba4_ndr(
	'Fixed-Array',
	
	'[public] void Test([in] uint8 x[10]);',
	
	'
	uint8_t data[] = {1,2,3,4,5,6,7,8,9,10};
	int i;
	DATA_BLOB b;
	struct ndr_pull *ndr;
	struct Test r;

	b.data = data;
	b.length = 10;
	ndr = ndr_pull_init_blob(&b, mem_ctx, NULL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_Test(ndr, NDR_IN, &r)))
		return 1;

	if (ndr->offset != 10)
		return 2;
	
	for (i = 0; i < 10; i++) {
		if (r.in.x[i] != i+1) return 3;
	}
');
