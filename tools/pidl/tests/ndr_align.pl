#!/usr/bin/perl
# NDR alignment tests
# (C) 2005 Jelmer Vernooij. Published under the GNU GPL
use strict;
use warnings;

use Test::More tests => 5 * 8;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util qw(test_samba4_ndr);

test_samba4_ndr('align-uint8-uint16', 
'
	typedef [public] struct { 
		uint8 x;
		uint16 y;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init_ctx(NULL);
	struct bla r;
	uint8_t expected[] = { 0x0D, 0x00, 0xef, 0xbe };
	DATA_BLOB expected_blob = { expected, 4 };
	DATA_BLOB result_blob;
	r.x = 13;
	r.y = 0xbeef;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (data_blob_cmp(&result_blob, &expected_blob) != 0) 
		return 2;
');

test_samba4_ndr('align-uint8-uint32', 
'
	typedef [public] struct { 
		uint8 x;
		uint32 y;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init_ctx(NULL);
	struct bla r;
	uint8_t expected[] = { 0x0D, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xef, 0xbe };
	DATA_BLOB expected_blob = { expected, 8 };
	DATA_BLOB result_blob;
	r.x = 13;
	r.y = 0xbeefbeef;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (data_blob_cmp(&result_blob, &expected_blob) != 0) 
		return 2;
');


test_samba4_ndr('align-uint8-hyper', 
'
	typedef [public] struct { 
		uint8 x;
		hyper y;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init_ctx(NULL);
	struct bla r;
	uint8_t expected[] = { 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
			       0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe };
	DATA_BLOB expected_blob = { expected, 16 };
	DATA_BLOB result_blob;
	r.x = 13;
	r.y = 0xbeefbeefbeefbeefLLU;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (data_blob_cmp(&result_blob, &expected_blob) != 0) 
		return 2;
');

test_samba4_ndr('noalignflag-uint8-uint16', 
'
	typedef [public] struct { 
		uint8 x;
		uint16 y;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init_ctx(NULL);
	struct bla r;
	uint8_t expected[] = { 0x0D, 0xef, 0xbe };
	DATA_BLOB expected_blob = { expected, 3 };
	DATA_BLOB result_blob;
	ndr->flags |= LIBNDR_FLAG_NOALIGN;

	r.x = 13;
	r.y = 0xbeef;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (data_blob_cmp(&result_blob, &expected_blob) != 0) 
		return 2;
');

test_samba4_ndr('align-blob-align2', 
'
	typedef [public] struct { 
		uint8 x;
		[flag(LIBNDR_FLAG_ALIGN2)] DATA_BLOB data;
		uint8 y;
	} blie;
',
'
	struct ndr_push *ndr = ndr_push_init_ctx(NULL);
	struct blie r;
	uint8_t data[] = { 0x01, 0x02 };
	uint8_t expected[] = { 0x0D, 0x00, 0x0E };
	DATA_BLOB expected_blob = { expected, 3 };
	DATA_BLOB result_blob;

	r.x = 13;
	r.y = 14;
	r.data.data = data;
	r.data.length = 2;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_blie(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);

	if (data_blob_cmp(&result_blob, &expected_blob) != 0) 
		return 2;
');
