#!/usr/bin/perl
# Support for tagged types
# (C) 2005 Jelmer Vernooij. Published under the GNU GPL
use strict;

use Test::More tests => 3 * 8;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util qw(test_samba4_ndr);

test_samba4_ndr('struct-notypedef', '[public] struct bla { uint8 x; }; ',
'
	struct ndr_push *ndr = ndr_push_init_ctx(NULL, NULL);
	struct bla r;
	uint8_t expected[] = { 0x0D };
	DATA_BLOB expected_blob = { expected, 1 };
	DATA_BLOB result_blob;
	r.x = 13;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_STRUCT_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (data_blob_cmp(&result_blob, &expected_blob) != 0) 
		return 2;
');

test_samba4_ndr('struct-notypedef-used', '[public] struct bla { uint8 x; };
	[public] void myfn([in] struct bla r); ',
'
	struct ndr_push *ndr = ndr_push_init_ctx(NULL, NULL);
	struct myfn fn;
	uint8_t expected[] = { 0x0D };
	DATA_BLOB expected_blob = { expected, 1 };
	DATA_BLOB result_blob;
	fn.in.r.x = 13;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_myfn(ndr, NDR_IN, &fn)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (data_blob_cmp(&result_blob, &expected_blob) != 0) 
		return 2;
');


test_samba4_ndr('struct-notypedef-embedded', 'struct bla { uint8 x; };
	[public] struct myst { struct bla r; }; ',
'
	struct ndr_push *ndr = ndr_push_init_ctx(NULL, NULL);
	struct myst st;
	uint8_t expected[] = { 0x0D };
	DATA_BLOB expected_blob = { expected, 1 };
	DATA_BLOB result_blob;
	st.r.x = 13;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_STRUCT_myst(ndr, NDR_IN, &st)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (data_blob_cmp(&result_blob, &expected_blob) != 0) 
		return 2;
');
