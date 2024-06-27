#!/usr/bin/perl
# Some simple tests for pidl
# (C) 2005 Jelmer Vernooij <jelmer@samba.org>
# Published under the GNU General Public License
use strict;
use warnings;

use Test::More tests => 8;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util qw(test_samba4_ndr);

test_samba4_ndr("simple", "void Test(); ",
"
	uint8_t data[] = { 0x02 };
	uint8_t result;
	DATA_BLOB b;
	struct ndr_pull *ndr;

	b.data = data;
	b.length = 1;
	ndr = ndr_pull_init_blob(&b, mem_ctx, NULL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_uint8(ndr, NDR_SCALARS, &result)))
		return 1;

	if (result != 0x02)
		return 2;
");
