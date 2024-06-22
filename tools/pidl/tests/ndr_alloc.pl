#!/usr/bin/perl
# NDR allocation tests
# (C) 2005 Jelmer Vernooij. Published under the GNU GPL
use strict;
use warnings;

use Test::More tests => 5 * 8;
use FindBin qw($RealBin);
use lib "$RealBin";
use Util qw(test_samba4_ndr);

# Check that an outgoing scalar pointer is allocated correctly

test_samba4_ndr("alloc-scalar", 
'	
	typedef struct {
		uint8 *x;
	} bla;
	
	[public] void TestAlloc([in] bla foo);
','
	uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef, 0x03 };
	DATA_BLOB b = { data, 5 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL, NULL);
	struct TestAlloc r;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestAlloc(ndr, NDR_IN, &r)))
		return 1;

	if (r.in.foo.x == NULL)
		return 2;
	
	if (*r.in.foo.x != 0x03)
		return 3;
'
);

# Check that an outgoing buffer pointer is allocated correctly
test_samba4_ndr("alloc-buffer", 
'	
	typedef struct { uint8 data; } blie;
	typedef struct { blie *x; } bla; 

	[public] void TestAlloc([in] bla foo);
','
	uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef, 0x03 };
	DATA_BLOB b = { data, 5 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL, NULL);
	struct TestAlloc r;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestAlloc(ndr, NDR_IN, &r)))
		return 1;

	if (r.in.foo.x == NULL)
		return 2;
	
	if (r.in.foo.x->data != 0x03)
		return 3;
'
);

# Check that ref pointers aren't allocated by default
test_samba4_ndr("ref-noalloc-null", 
'	
	[public] void TestAlloc([in,ref] uint8 *t);
','
	uint8_t data[] = { 0x03 };
	DATA_BLOB b = { data, 1 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL, NULL);
	struct TestAlloc r;
	r.in.t = NULL;

	if (NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestAlloc(ndr, NDR_IN, &r)))
		return 1;
'
);

# Check that ref pointers aren't allocated by default
test_samba4_ndr("ref-noalloc", 
'	
	[public] void TestAlloc([in,ref] uint8 *t);
','
	uint8_t data[] = { 0x03 };
	DATA_BLOB b = { data, 1 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL, NULL);
	struct TestAlloc r;
	uint8_t x;
	r.in.t = &x;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestAlloc(ndr, NDR_IN, &r)))
		return 1;

	if (*r.in.t != 0x03)
		return 2;
'
);

# Check that an outgoing ref pointer is allocated correctly
test_samba4_ndr("ref-alloc", 
'	
	[public] void TestAlloc([in,ref] uint8 *t);
','
	uint8_t data[] = { 0x03 };
	DATA_BLOB b = { data, 1 };
	struct ndr_pull *ndr = ndr_pull_init_blob(&b, NULL, NULL);
	struct TestAlloc r;
	ndr->flags |= LIBNDR_FLAG_REF_ALLOC;
	r.in.t = NULL;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_pull_TestAlloc(ndr, NDR_IN, &r)))
		return 1;

	if (r.in.t == NULL)
		return 2;

	if (*r.in.t != 0x03)
		return 3;
'
);
