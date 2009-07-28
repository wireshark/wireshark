#!/usr/bin/perl
# Simple tests for unique pointers
# (C) 2006 Jelmer Vernooij <jelmer@samba.org>.
# Published under the GNU General Public License.
use strict;

use Test::More tests => 1 * 8;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util qw(test_samba4_ndr);

SKIP: {
	skip "full pointers not supported yet", 8;

test_samba4_ndr("fullptr-push-dup", 
'	
	[public] uint16 echo_TestFull([in,ptr] uint32 *x, [in,ptr] uint32 *y);
',
'
	struct ndr_push *ndr = ndr_push_init_ctx(NULL, NULL);
	uint32_t v = 13;
	struct echo_TestFull r;
	r.in.x = &v; 
	r.in.y = &v; 

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_echo_TestFull(ndr, NDR_IN, &r))) {
		fprintf(stderr, "push failed\n");
		return 1;
	}

	if (ndr->offset != 12) {
		fprintf(stderr, "Offset(%d) != 12\n", ndr->offset);
		return 2;
	}

	if (ndr->data[0] != ndr->data[8] || 
	    ndr->data[1] != ndr->data[9] ||
		ndr->data[2] != ndr->data[10] ||
		ndr->data[3] != ndr->data[11]) {
		fprintf(stderr, "Data incorrect\n");
		return 3;
	}
');
}
