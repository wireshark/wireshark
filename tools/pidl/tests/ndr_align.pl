#!/usr/bin/perl
# NDR alignment tests
# (C) 2005 Jelmer Vernooij. Published under the GNU GPL
use strict;

use Parse::Pidl::Test;

my %settings = Parse::Pidl::Test::GetSettings(@ARGV);

$settings{'IDL-Arguments'} = ['--quiet', '--parse', '--parser=ndr_test.c', '--header=ndr_test.h'];
$settings{'IncludeFiles'} = ['ndr_test.h'];
$settings{'ExtraFiles'} = ['ndr_test.c'];

Parse::Pidl::Test::test_idl('align-uint8-uint16', \%settings,
'
	typedef [public] struct { 
		uint8 x;
		uint16 y;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct bla r;
	uint8_t expected[] = { 0x0D, 0x00, 0xef, 0xbe };
	DATA_BLOB expected_blob = { expected, 4 };
	DATA_BLOB result_blob;
	r.x = 13;
	r.y = 0xbeef;

	if (NT_STATUS_IS_ERR(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (!data_blob_equal(&result_blob, &expected_blob)) 
		return 2;
');

Parse::Pidl::Test::test_idl('align-uint8-uint32', \%settings,
'
	typedef [public] struct { 
		uint8 x;
		uint32 y;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct bla r;
	uint8_t expected[] = { 0x0D, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xef, 0xbe };
	DATA_BLOB expected_blob = { expected, 8 };
	DATA_BLOB result_blob;
	r.x = 13;
	r.y = 0xbeefbeef;

	if (NT_STATUS_IS_ERR(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (!data_blob_equal(&result_blob, &expected_blob)) 
		return 2;
');


Parse::Pidl::Test::test_idl('align-uint8-hyper', \%settings,
'
	typedef [public] struct { 
		uint8 x;
		hyper y;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct bla r;
	uint8_t expected[] = { 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
						   0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe };
	DATA_BLOB expected_blob = { expected, 16 };
	DATA_BLOB result_blob;
	r.x = 13;
	r.y = 0xbeefbeefbeefbeef;

	if (NT_STATUS_IS_ERR(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (!data_blob_equal(&result_blob, &expected_blob)) 
		return 2;
');

Parse::Pidl::Test::test_idl('noalignflag-uint8-uint16', \%settings,
'
	typedef [public] struct { 
		uint8 x;
		uint16 y;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct bla r;
	uint8_t expected[] = { 0x0D, 0xef, 0xbe };
	DATA_BLOB expected_blob = { expected, 3 };
	DATA_BLOB result_blob;
	ndr->flags |= LIBNDR_FLAG_NOALIGN;

	r.x = 13;
	r.y = 0xbeef;

	if (NT_STATUS_IS_ERR(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);
	
	if (!data_blob_equal(&result_blob, &expected_blob)) 
		return 2;
');

Parse::Pidl::Test::test_idl('align-blob-align2', \%settings,
'
	typedef [public] struct { 
		uint8 x;
		[flag(LIBNDR_FLAG_ALIGN2)] DATA_BLOB data;
	} bla;
',
'
	struct ndr_push *ndr = ndr_push_init();
	struct bla r;
	uint8_t data[] = { 0x01, 0x02 };
	uint8_t expected[] = { 0x0D, 0x00, 0x01, 0x02 };
	DATA_BLOB expected_blob = { expected, 4 };
	DATA_BLOB result_blob;

	r.x = 13;
	r.data.data = data;
	r.data.length = 2;

	if (NT_STATUS_IS_ERR(ndr_push_bla(ndr, NDR_SCALARS|NDR_BUFFERS, &r)))
		return 1;

	result_blob = ndr_push_blob(ndr);

	if (!data_blob_equal(&result_blob, &expected_blob)) 
		return 2;
');
